/**
 * Jira Cloud Adapter
 * Handles Jira webhooks and API interactions
 * Uses REST API v2 for plain text comments (avoids Atlassian Document Format)
 */

import type { Context } from "hono";
import type { PlatformAdapter, PlatformEvent, AdapterConfig } from "./platform-adapter.js";

interface JiraIssue {
  id: string;
  key: string;
  self: string;
  fields: {
    summary: string;
    description?: string;
    issuetype: { name: string };
    project: { key: string };
    parent?: { key: string; id: string };
    creator?: { accountId: string };
    labels?: string[];
  };
}

interface JiraComment {
  id: string;
  body: string;
  author?: { accountId: string };
}

interface JiraWebhookPayload {
  webhookEvent: string;
  issue?: JiraIssue;
  comment?: JiraComment;
  changelog?: { items: Array<{ field: string; fromString?: string; toString?: string }> };
  user?: { accountId: string };
}

export interface JiraAdapterConfig extends AdapterConfig {
  domain?: string;       // e.g. "mycompany" -> mycompany.atlassian.net
  userEmail?: string;    // For Basic auth
  apiToken?: string;     // Jira API token
}

export class JiraAdapter implements PlatformAdapter {
  readonly platform = "jira" as const;
  private config: JiraAdapterConfig;
  private baseUrl: string;

  constructor(config: JiraAdapterConfig) {
    this.config = config;
    this.baseUrl = config.domain
      ? `https://${config.domain}.atlassian.net`
      : "";
  }

  isConfigured(): boolean {
    return !!(this.config.domain && this.config.userEmail && this.config.apiToken);
  }

  setAccessToken(token: string): void {
    this.config.apiToken = token;
  }

  private getBasicAuth(): string {
    if (!this.config.userEmail || !this.config.apiToken) {
      throw new Error("Jira credentials not configured");
    }
    return Buffer.from(`${this.config.userEmail}:${this.config.apiToken}`).toString("base64");
  }

  async verifySignature(ctx: Context, body: string): Promise<boolean> {
    // Jira Cloud system webhooks don't support HMAC signatures.
    // Optionally validate a shared secret query param if configured.
    if (this.config.webhookSecret) {
      const secret = ctx.req.query("secret");
      if (secret !== this.config.webhookSecret) {
        console.warn("[JiraAdapter] Webhook secret mismatch");
        return false;
      }
      return true;
    }

    console.warn("[JiraAdapter] No webhook secret configured, accepting all requests");
    return true;
  }

  async parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null> {
    const payload = body as JiraWebhookPayload;

    // Issue created
    if (payload.webhookEvent === "jira:issue_created" && payload.issue) {
      const issue = payload.issue;
      const description = await this.fetchPlainDescription(issue.key);
      return {
        platform: "jira",
        threadId: issue.key,
        content: `${issue.fields.summary || ""}\n${description || issue.fields.description || ""}`,
        isDescription: true,
        authorId: issue.fields.creator?.accountId || payload.user?.accountId,
        issueTitle: issue.fields.summary,
        issueDescription: description || issue.fields.description,
        issueUrl: `${this.baseUrl}/browse/${issue.key}`,
        projectKey: issue.fields.project.key,
        parentIssueId: issue.fields.parent?.key,
        raw: payload
      };
    }

    // Issue updated — only trigger on description changes
    if (payload.webhookEvent === "jira:issue_updated" && payload.issue && payload.changelog) {
      const descriptionChanged = payload.changelog.items.some(
        item => item.field === "description"
      );
      if (!descriptionChanged) return null;

      const issue = payload.issue;
      const description = await this.fetchPlainDescription(issue.key);
      return {
        platform: "jira",
        threadId: issue.key,
        content: `${issue.fields.summary || ""}\n${description || issue.fields.description || ""}`,
        isDescription: true,
        authorId: payload.user?.accountId,
        issueTitle: issue.fields.summary,
        issueDescription: description || issue.fields.description,
        issueUrl: `${this.baseUrl}/browse/${issue.key}`,
        projectKey: issue.fields.project.key,
        parentIssueId: issue.fields.parent?.key,
        raw: payload
      };
    }

    // Comment created
    if (payload.webhookEvent === "comment_created" && payload.issue && payload.comment) {
      const issue = payload.issue;
      return {
        platform: "jira",
        threadId: issue.key,
        content: payload.comment.body || "",
        isDescription: false,
        messageId: payload.comment.id,
        authorId: payload.comment.author?.accountId || payload.user?.accountId,
        issueTitle: issue.fields.summary,
        issueUrl: `${this.baseUrl}/browse/${issue.key}`,
        projectKey: issue.fields.project.key,
        parentIssueId: issue.fields.parent?.key,
        raw: payload
      };
    }

    return null;
  }

  /**
   * Fetch issue description as plain text via REST API v2 (avoids ADF)
   */
  private async fetchPlainDescription(issueKey: string): Promise<string | undefined> {
    if (!this.isConfigured()) return undefined;
    try {
      const response = await fetch(
        `${this.baseUrl}/rest/api/2/issue/${issueKey}?fields=description`,
        {
          headers: {
            Authorization: `Basic ${this.getBasicAuth()}`,
            Accept: "application/json"
          }
        }
      );
      if (!response.ok) return undefined;
      const data = await response.json() as { fields?: { description?: string } };
      return data.fields?.description || undefined;
    } catch {
      return undefined;
    }
  }

  async postResponse(threadId: string, message: string): Promise<void> {
    const auth = this.getBasicAuth();

    // Use v2 API for plain text comments
    const response = await fetch(
      `${this.baseUrl}/rest/api/2/issue/${threadId}/comment`,
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${auth}`,
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({ body: message })
      }
    );

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post Jira comment: ${error}`);
    }

    console.log(`[JiraAdapter] Posted comment to ${threadId}`);
  }

  async setStatus(threadId: string, status: "processing" | "done" | "error"): Promise<void> {
    if (!this.isConfigured()) return;

    const auth = this.getBasicAuth();
    const labelToAdd = `claude-${status}`;
    const labelsToRemove = ["claude-processing", "claude-done", "claude-error"].filter(l => l !== labelToAdd);

    try {
      // Get current labels
      const getResponse = await fetch(
        `${this.baseUrl}/rest/api/2/issue/${threadId}?fields=labels`,
        {
          headers: {
            Authorization: `Basic ${auth}`,
            Accept: "application/json"
          }
        }
      );
      if (!getResponse.ok) return;

      const data = await getResponse.json() as { fields?: { labels?: string[] } };
      const currentLabels = data.fields?.labels || [];
      const newLabels = currentLabels
        .filter((l: string) => !labelsToRemove.includes(l) && l !== labelToAdd)
        .concat(labelToAdd);

      // Update labels
      await fetch(
        `${this.baseUrl}/rest/api/2/issue/${threadId}`,
        {
          method: "PUT",
          headers: {
            Authorization: `Basic ${auth}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ fields: { labels: newLabels } })
        }
      );

      console.log(`[JiraAdapter] Set label "${labelToAdd}" on ${threadId}`);
    } catch (error) {
      console.error("[JiraAdapter] Failed to set status label:", error);
    }
  }

  async addReaction(threadId: string, emoji: string, targetId?: string): Promise<void> {
    // Jira has no native comment reactions — log and skip
    console.log(`[JiraAdapter] Reactions not supported on Jira, skipping ${emoji} on ${threadId}`);
  }
}
