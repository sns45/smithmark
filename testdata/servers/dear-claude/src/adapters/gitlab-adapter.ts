/**
 * GitLab Adapter
 * Handles GitLab webhooks and API interactions for issues and merge requests
 */

import { createHmac, timingSafeEqual } from "crypto";
import type { Context } from "hono";
import type { PlatformAdapter, PlatformEvent, AdapterConfig } from "./platform-adapter.js";

interface GitLabMergeRequest {
  iid: number;
  title: string;
  description?: string;
  author?: { username: string };
  source_branch?: string;
  target_branch?: string;
}

interface GitLabIssue {
  iid: number;
  title: string;
  description?: string;
  author?: { username: string };
}

interface GitLabNote {
  id: number;
  body: string;
  author?: { username: string };
  noteable_type: string;
}

interface GitLabWebhookPayload {
  object_kind: string;
  user?: { username: string };
  project: { id: number; path_with_namespace: string };
  object_attributes: Record<string, unknown>;
  merge_request?: GitLabMergeRequest;
  issue?: GitLabIssue;
}

export class GitLabAdapter implements PlatformAdapter {
  readonly platform = "gitlab" as const;
  private config: AdapterConfig;
  private apiUrl: string;

  constructor(config: AdapterConfig) {
    this.config = config;
    this.apiUrl = (process.env.GITLAB_URL || "https://gitlab.com").replace(/\/$/, "") + "/api/v4";
  }

  isConfigured(): boolean {
    return !!this.config.accessToken;
  }

  setAccessToken(token: string): void {
    this.config.accessToken = token;
  }

  async verifySignature(ctx: Context, body: string): Promise<boolean> {
    const token = ctx.req.header("x-gitlab-token");
    if (!this.config.webhookSecret) {
      console.warn("[GitLabAdapter] No webhook secret configured, skipping verification");
      return true;
    }
    if (!token) {
      console.warn("[GitLabAdapter] Missing X-Gitlab-Token header");
      return false;
    }
    // GitLab webhook secret is a simple string comparison
    return token === this.config.webhookSecret;
  }

  async parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null> {
    const payload = body as GitLabWebhookPayload;
    const project = payload.project.path_with_namespace;

    // Issue opened
    if (payload.object_kind === "issue") {
      const attrs = payload.object_attributes as any;
      if (attrs.action !== "open") return null;
      return {
        platform: "gitlab",
        threadId: `${project}#${attrs.iid}`,
        content: `${attrs.title || ""}\n${attrs.description || ""}`,
        isDescription: true,
        authorId: payload.user?.username,
        raw: payload
      };
    }

    // Note (comment) on issue or MR
    if (payload.object_kind === "note") {
      const attrs = payload.object_attributes as any;
      const isMR = attrs.noteable_type === "MergeRequest";
      const isIssue = attrs.noteable_type === "Issue";
      const iid = isMR ? payload.merge_request?.iid : payload.issue?.iid;
      if (!iid) return null;

      const separator = isMR ? "!" : "#";
      return {
        platform: "gitlab",
        threadId: `${project}${separator}${iid}`,
        content: attrs.note || "",
        isDescription: false,
        messageId: String(attrs.id),
        authorId: payload.user?.username,
        isPullRequest: isMR,
        raw: payload
      };
    }

    // Merge request opened
    if (payload.object_kind === "merge_request") {
      const attrs = payload.object_attributes as any;
      if (attrs.action !== "open") return null;

      // Fetch diff
      let diffContent: string | undefined;
      try {
        diffContent = await this.fetchMRDiff(payload.project.id, attrs.iid);
      } catch (e) {
        console.error("[GitLabAdapter] Failed to fetch MR diff:", e);
      }

      const gitlabHost = (process.env.GITLAB_URL || "https://gitlab.com").replace(/\/$/, "");
      return {
        platform: "gitlab",
        threadId: `${project}!${attrs.iid}`,
        content: `${attrs.title || ""}\n${attrs.description || ""}`,
        isDescription: true,
        authorId: payload.user?.username,
        isPullRequest: true,
        diffContent,
        repoCloneUrl: `${gitlabHost}/${project}.git`,
        prBranch: attrs.source_branch,
        prBaseBranch: attrs.target_branch,
        prNumber: attrs.iid,
        raw: payload
      };
    }

    return null;
  }

  private async fetchMRDiff(projectId: number, mrIid: number): Promise<string> {
    const token = this.config.accessToken;
    if (!token) throw new Error("No access token");

    const response = await fetch(`${this.apiUrl}/projects/${projectId}/merge_requests/${mrIid}/changes`, {
      headers: { "PRIVATE-TOKEN": token }
    });
    if (!response.ok) throw new Error(`Failed to fetch MR diff: ${response.status}`);

    const data = await response.json() as { changes: Array<{ diff: string; old_path: string; new_path: string }> };
    return data.changes.map(c => `--- ${c.old_path}\n+++ ${c.new_path}\n${c.diff}`).join("\n\n");
  }

  async postResponse(threadId: string, message: string): Promise<void> {
    if (!this.config.accessToken) throw new Error("GitLab access token not configured");

    const { projectPath, iid, isMR } = this.parseThreadId(threadId);
    const encodedProject = encodeURIComponent(projectPath);
    const resource = isMR ? "merge_requests" : "issues";

    const response = await fetch(`${this.apiUrl}/projects/${encodedProject}/${resource}/${iid}/notes`, {
      method: "POST",
      headers: {
        "PRIVATE-TOKEN": this.config.accessToken,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ body: message })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post GitLab comment: ${error}`);
    }

    console.log(`[GitLabAdapter] Posted comment to ${threadId}`);
  }

  async setStatus(threadId: string, status: "processing" | "done" | "error"): Promise<void> {
    if (!this.config.accessToken) return;

    const { projectPath, iid, isMR } = this.parseThreadId(threadId);
    const encodedProject = encodeURIComponent(projectPath);
    const resource = isMR ? "merge_requests" : "issues";

    const labelName = `claude-${status}`;
    const labelsToRemove = ["claude-processing", "claude-done", "claude-error"].filter(l => l !== labelName);

    try {
      // Ensure the label exists
      await this.ensureLabel(encodedProject, labelName, status);

      // Get current labels
      const getResponse = await fetch(`${this.apiUrl}/projects/${encodedProject}/${resource}/${iid}`, {
        headers: { "PRIVATE-TOKEN": this.config.accessToken }
      });
      if (!getResponse.ok) return;

      const item = await getResponse.json() as { labels: string[] };
      const currentLabels = item.labels || [];
      const newLabels = currentLabels
        .filter((l: string) => !labelsToRemove.includes(l) && l !== labelName)
        .concat(labelName);

      // Update labels
      await fetch(`${this.apiUrl}/projects/${encodedProject}/${resource}/${iid}`, {
        method: "PUT",
        headers: {
          "PRIVATE-TOKEN": this.config.accessToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ labels: newLabels.join(",") })
      });

      console.log(`[GitLabAdapter] Set label "${labelName}" on ${threadId}`);
    } catch (error) {
      console.error("[GitLabAdapter] Failed to set status label:", error);
    }
  }

  private async ensureLabel(encodedProject: string, name: string, status: string): Promise<void> {
    const colors: Record<string, string> = {
      processing: "#f0ad4e",
      done: "#5cb85c",
      error: "#d9534f"
    };

    // Check if label exists
    const response = await fetch(`${this.apiUrl}/projects/${encodedProject}/labels?search=${encodeURIComponent(name)}`, {
      headers: { "PRIVATE-TOKEN": this.config.accessToken! }
    });
    if (!response.ok) return;

    const labels = await response.json() as Array<{ name: string }>;
    if (labels.some(l => l.name === name)) return;

    // Create label
    await fetch(`${this.apiUrl}/projects/${encodedProject}/labels`, {
      method: "POST",
      headers: {
        "PRIVATE-TOKEN": this.config.accessToken!,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name, color: colors[status] || "#428bca" })
    });
  }

  async addReaction(threadId: string, emoji: string, targetId?: string): Promise<void> {
    if (!this.config.accessToken) return;

    const { projectPath, iid, isMR } = this.parseThreadId(threadId);
    const encodedProject = encodeURIComponent(projectPath);
    const resource = isMR ? "merge_requests" : "issues";

    // GitLab uses emoji names like "eyes", "white_check_mark", "x"
    const gitlabEmoji = this.mapEmojiToGitLab(emoji);

    try {
      let url: string;
      if (targetId) {
        // React to a specific note
        url = `${this.apiUrl}/projects/${encodedProject}/${resource}/${iid}/notes/${targetId}/award_emoji`;
      } else {
        // React to the issue/MR itself
        url = `${this.apiUrl}/projects/${encodedProject}/${resource}/${iid}/award_emoji`;
      }

      await fetch(url, {
        method: "POST",
        headers: {
          "PRIVATE-TOKEN": this.config.accessToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ name: gitlabEmoji })
      });

      console.log(`[GitLabAdapter] Added reaction ${gitlabEmoji} to ${threadId}`);
    } catch (error) {
      console.error("[GitLabAdapter] Failed to add reaction:", error);
    }
  }

  private mapEmojiToGitLab(emoji: string): string {
    const map: Record<string, string> = {
      "eyes": "eyes",
      "white_check_mark": "white_check_mark",
      "x": "x",
      "+1": "thumbsup",
      "-1": "thumbsdown",
      "rocket": "rocket",
      "heart": "heart",
    };
    return map[emoji] || emoji;
  }

  async getAuthCloneUrl(cloneUrl: string): Promise<string> {
    if (!this.config.accessToken) throw new Error("GitLab access token not configured");
    return cloneUrl.replace("https://", `https://oauth2:${this.config.accessToken}@`);
  }

  async postPRReview(
    threadId: string,
    body: string,
    comments?: Array<{ path: string; line: number; body: string }>,
    event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES" = "COMMENT"
  ): Promise<void> {
    if (!this.config.accessToken) throw new Error("GitLab access token not configured");

    const { projectPath, iid } = this.parseThreadId(threadId);
    const encodedProject = encodeURIComponent(projectPath);

    // Post summary as a note
    await this.postResponse(threadId, body);

    // Post inline comments as discussions
    if (comments && comments.length > 0) {
      // Fetch diff_refs for positioning
      const mrResponse = await fetch(`${this.apiUrl}/projects/${encodedProject}/merge_requests/${iid}`, {
        headers: { "PRIVATE-TOKEN": this.config.accessToken }
      });
      if (!mrResponse.ok) {
        console.error("[GitLabAdapter] Failed to fetch MR for diff_refs");
        return;
      }
      const mrData = await mrResponse.json() as { diff_refs: { base_sha: string; head_sha: string; start_sha: string } };
      const { base_sha, head_sha, start_sha } = mrData.diff_refs;

      for (const comment of comments) {
        try {
          await fetch(`${this.apiUrl}/projects/${encodedProject}/merge_requests/${iid}/discussions`, {
            method: "POST",
            headers: {
              "PRIVATE-TOKEN": this.config.accessToken,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              body: comment.body,
              position: {
                position_type: "text",
                base_sha,
                head_sha,
                start_sha,
                new_path: comment.path,
                new_line: comment.line
              }
            })
          });
        } catch (err) {
          console.error(`[GitLabAdapter] Failed to post inline comment on ${comment.path}:${comment.line}:`, err);
        }
      }
    }

    console.log(`[GitLabAdapter] Posted PR review to ${threadId}`);
  }

  private parseThreadId(threadId: string): { projectPath: string; iid: number; isMR: boolean } {
    // Format: "group/project#123" for issues, "group/project!123" for MRs
    const mrMatch = threadId.match(/^(.+?)!(\d+)$/);
    if (mrMatch) {
      return { projectPath: mrMatch[1], iid: parseInt(mrMatch[2]), isMR: true };
    }
    const issueMatch = threadId.match(/^(.+?)#(\d+)$/);
    if (issueMatch) {
      return { projectPath: issueMatch[1], iid: parseInt(issueMatch[2]), isMR: false };
    }
    throw new Error(`Invalid GitLab thread ID format: ${threadId}`);
  }
}
