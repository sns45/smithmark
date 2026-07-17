/**
 * Linear Adapter
 * Handles Linear webhooks and API interactions
 */

import { createHmac, timingSafeEqual } from "crypto";
import type { Context } from "hono";
import type { PlatformAdapter, PlatformEvent, AdapterConfig } from "./platform-adapter.js";

interface LinearIssue {
  id: string;
  title: string;
  description?: string;
  number: number;
  identifier: string;
  url: string;
  creatorId?: string;
}

interface LinearComment {
  id: string;
  body: string;
  issueId: string;
  userId?: string;
  issue?: { id: string };
}

interface LinearWebhookPayload {
  type: string;
  action: string;
  data: LinearIssue | LinearComment;
  updatedFrom?: Record<string, unknown>;
  organizationId: string;
  createdAt: string;
}

export class LinearAdapter implements PlatformAdapter {
  readonly platform = "linear" as const;
  private config: AdapterConfig;
  private apiUrl = "https://api.linear.app/graphql";
  private authUrl = "https://linear.app/oauth/authorize";
  private tokenUrl = "https://api.linear.app/oauth/token";

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  isConfigured(): boolean {
    return !!(this.config.accessToken || (this.config.clientId && this.config.clientSecret));
  }

  async verifySignature(ctx: Context, body: string): Promise<boolean> {
    if (!this.config.webhookSecret) {
      console.warn("[LinearAdapter] No webhook secret configured, skipping verification");
      return true;
    }

    const signature = ctx.req.header("linear-signature");
    if (!signature) {
      console.warn("[LinearAdapter] Missing Linear signature header");
      return false;
    }

    try {
      const hmac = createHmac("sha256", this.config.webhookSecret);
      hmac.update(body);
      const expectedSignature = hmac.digest("hex");

      const sigBuffer = Buffer.from(signature);
      const expectedBuffer = Buffer.from(expectedSignature);

      if (sigBuffer.length !== expectedBuffer.length) {
        console.warn("[LinearAdapter] Signature length mismatch");
        return false;
      }

      return timingSafeEqual(sigBuffer, expectedBuffer);
    } catch (error) {
      console.error("[LinearAdapter] Signature verification error:", error);
      return false;
    }
  }

  async parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null> {
    const payload = body as LinearWebhookPayload;

    if (payload.type === "Issue" && payload.action === "create") {
      const issue = payload.data as LinearIssue;
      const issueContext = await this.fetchIssueContext(issue.id);
      return {
        platform: "linear",
        threadId: issue.id,
        content: `${issue.title || ""}\n${issue.description || ""}`,
        isDescription: true,
        authorId: issue.creatorId,
        issueTitle: issueContext?.title || issue.title,
        issueDescription: issueContext?.description || issue.description,
        issueUrl: issueContext?.url || issue.url,
        projectKey: issueContext?.teamKey,
        parentIssueId: issueContext?.parentId,
        raw: payload
      };
    }

    // Handle issue description updates (e.g. user edits description to add "Dear Claude")
    if (payload.type === "Issue" && payload.action === "update") {
      if (!payload.updatedFrom || !("description" in payload.updatedFrom)) return null;
      const issue = payload.data as LinearIssue;
      const issueContext = await this.fetchIssueContext(issue.id);
      return {
        platform: "linear",
        threadId: issue.id,
        content: `${issue.title || ""}\n${issue.description || ""}`,
        isDescription: true,
        authorId: issue.creatorId,
        issueTitle: issueContext?.title || issue.title,
        issueDescription: issueContext?.description || issue.description,
        issueUrl: issueContext?.url || issue.url,
        projectKey: issueContext?.teamKey,
        parentIssueId: issueContext?.parentId,
        raw: payload
      };
    }

    if (payload.type === "Comment" && payload.action === "create") {
      const comment = payload.data as LinearComment;
      const threadId = comment.issueId || comment.issue?.id || "";
      const issueContext = threadId ? await this.fetchIssueContext(threadId) : null;
      return {
        platform: "linear",
        threadId,
        content: comment.body || "",
        isDescription: false,
        messageId: comment.id,
        authorId: comment.userId,
        issueTitle: issueContext?.title,
        issueDescription: issueContext?.description,
        issueUrl: issueContext?.url,
        projectKey: issueContext?.teamKey,
        parentIssueId: issueContext?.parentId,
        raw: payload
      };
    }

    return null;
  }

  async postResponse(threadId: string, message: string): Promise<void> {
    if (!this.config.accessToken) {
      throw new Error("Linear access token not configured");
    }

    const mutation = `
      mutation CreateComment($issueId: String!, $body: String!) {
        commentCreate(input: { issueId: $issueId, body: $body }) {
          success
          comment {
            id
          }
        }
      }
    `;

    const response = await fetch(this.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": this.config.accessToken
      },
      body: JSON.stringify({
        query: mutation,
        variables: { issueId: threadId, body: message }
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post Linear comment: ${error}`);
    }

    const result = await response.json() as { data?: { commentCreate?: { success: boolean } }; errors?: Array<{ message: string }> };
    if (result.errors) {
      throw new Error(`Linear API error: ${result.errors.map((e: { message: string }) => e.message).join(", ")}`);
    }

    console.log(`[LinearAdapter] Posted comment to issue ${threadId}`);
  }

  async setStatus(threadId: string, status: "processing" | "done" | "error"): Promise<void> {
    if (!this.config.accessToken) return;

    const labelName = `claude-${status}`;
    const labelsToRemove = ["claude-processing", "claude-done", "claude-error"].filter(l => l !== labelName);
    const colors: Record<string, string> = {
      "claude-processing": "#f0ad4e",
      "claude-done": "#5cb85c",
      "claude-error": "#d9534f"
    };

    try {
      // Get the issue's team to scope label search
      const issueQuery = `query { issue(id: "${threadId}") { team { id } labelIds } }`;
      const issueResult = await this.graphql(issueQuery) as {
        data?: { issue?: { team: { id: string }; labelIds: string[] } }
      };
      const issue = issueResult.data?.issue;
      if (!issue) return;

      // Find or create the target label
      const searchQuery = `query { issueLabels(filter: { name: { eq: "${labelName}" } }) { nodes { id name } } }`;
      const searchResult = await this.graphql(searchQuery) as {
        data?: { issueLabels?: { nodes: Array<{ id: string; name: string }> } }
      };

      let labelId: string;
      const existing = searchResult.data?.issueLabels?.nodes?.[0];
      if (existing) {
        labelId = existing.id;
      } else {
        // Create the label
        const createMutation = `mutation { issueLabelCreate(input: { name: "${labelName}", color: "${colors[labelName] || "#428bca"}", teamId: "${issue.team.id}" }) { success issueLabel { id } } }`;
        const createResult = await this.graphql(createMutation) as {
          data?: { issueLabelCreate?: { issueLabel?: { id: string } } }
        };
        labelId = createResult.data?.issueLabelCreate?.issueLabel?.id || "";
        if (!labelId) return;
      }

      // Get IDs of labels to remove
      const removeIds: string[] = [];
      for (const removeName of labelsToRemove) {
        const q = `query { issueLabels(filter: { name: { eq: "${removeName}" } }) { nodes { id } } }`;
        const r = await this.graphql(q) as { data?: { issueLabels?: { nodes: Array<{ id: string }> } } };
        const found = r.data?.issueLabels?.nodes?.[0];
        if (found) removeIds.push(found.id);
      }

      // Update issue labels: keep existing, remove old status, add new
      const newLabelIds = (issue.labelIds || [])
        .filter((id: string) => !removeIds.includes(id) && id !== labelId)
        .concat(labelId);

      const updateMutation = `mutation { issueUpdate(id: "${threadId}", input: { labelIds: ${JSON.stringify(newLabelIds)} }) { success } }`;
      await this.graphql(updateMutation);

      console.log(`[LinearAdapter] Set label "${labelName}" on issue ${threadId}`);
    } catch (error) {
      console.error("[LinearAdapter] Failed to set status label:", error);
    }
  }

  async addReaction(threadId: string, emoji: string, targetId?: string): Promise<void> {
    if (!this.config.accessToken) return;

    // Linear reactions are on comments only (targetId = commentId)
    if (!targetId) {
      console.log(`[LinearAdapter] Reactions only supported on comments, skipping reaction on issue ${threadId}`);
      return;
    }

    try {
      const mutation = `mutation { reactionCreate(input: { commentId: "${targetId}", emoji: "${emoji}" }) { success } }`;
      await this.graphql(mutation);
      console.log(`[LinearAdapter] Added reaction ${emoji} to comment ${targetId}`);
    } catch (error) {
      console.error("[LinearAdapter] Failed to add reaction:", error);
    }
  }

  private async fetchIssueContext(issueId: string): Promise<{
    title: string; description?: string; identifier: string; url: string;
    teamKey: string; parentId?: string;
  } | null> {
    if (!this.config.accessToken) return null;
    try {
      const query = `query { issue(id: "${issueId}") { title description identifier url team { key } parent { id } } }`;
      const result = await this.graphql(query) as {
        data?: { issue?: { title: string; description?: string; identifier: string; url: string; team: { key: string }; parent?: { id: string } } }
      };
      const issue = result.data?.issue;
      if (!issue) return null;
      return {
        title: issue.title,
        description: issue.description,
        identifier: issue.identifier,
        url: issue.url,
        teamKey: issue.team.key,
        parentId: issue.parent?.id
      };
    } catch (err) {
      console.error("[LinearAdapter] Failed to fetch issue context:", err);
      return null;
    }
  }

  private async graphql(query: string): Promise<unknown> {
    const response = await fetch(this.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": this.config.accessToken!
      },
      body: JSON.stringify({ query })
    });

    if (!response.ok) {
      throw new Error(`Linear API error: ${response.status}`);
    }

    return response.json();
  }

  getAuthUrl(redirectUri: string, state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId!,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "read,write,issues:create,comments:create",
      state,
      prompt: "consent"
    });

    return `${this.authUrl}?${params.toString()}`;
  }

  setAccessToken(token: string): void {
    this.config.accessToken = token;
  }

  async handleCallback(code: string, redirectUri: string): Promise<{ accessToken: string; refreshToken?: string; username?: string }> {
    // Linear uses PKCE, but for server-side flow we can use standard OAuth
    const response = await fetch(this.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.config.clientId!,
        client_secret: this.config.clientSecret!,
        redirect_uri: redirectUri,
        code
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to exchange code: ${error}`);
    }

    const data = await response.json() as { access_token: string; refresh_token?: string };

    // Fetch the authenticated user's Linear ID
    let username: string | undefined;
    try {
      const viewerResult = await fetch(this.apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": data.access_token },
        body: JSON.stringify({ query: "{ viewer { id name } }" })
      });
      if (viewerResult.ok) {
        const viewerData = await viewerResult.json() as { data?: { viewer?: { id: string; name: string } } };
        username = viewerData.data?.viewer?.id;
        console.log(`[LinearAdapter] Authenticated as: ${viewerData.data?.viewer?.name} (${username})`);
      }
    } catch (err) {
      console.error("[LinearAdapter] Failed to fetch viewer:", err);
    }

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      username
    };
  }

  /**
   * Register a webhook with Linear
   */
  async registerWebhook(url: string, teamId?: string): Promise<{ id: string; secret: string }> {
    if (!this.config.accessToken) {
      throw new Error("Linear access token not configured");
    }

    const mutation = `
      mutation CreateWebhook($input: WebhookCreateInput!) {
        webhookCreate(input: $input) {
          success
          webhook {
            id
            secret
          }
        }
      }
    `;

    const input: Record<string, unknown> = {
      url,
      resourceTypes: ["Issue", "Comment"],
      enabled: true
    };

    if (teamId) {
      input.teamId = teamId;
    }

    const response = await fetch(this.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": this.config.accessToken
      },
      body: JSON.stringify({
        query: mutation,
        variables: { input }
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to register webhook: ${await response.text()}`);
    }

    const result = await response.json() as {
      data?: { webhookCreate?: { success: boolean; webhook?: { id: string; secret: string } } };
      errors?: Array<{ message: string }>;
    };

    if (result.errors || !result.data?.webhookCreate?.success) {
      throw new Error(`Failed to create webhook: ${JSON.stringify(result.errors)}`);
    }

    const webhook = result.data.webhookCreate.webhook!;
    console.log(`[LinearAdapter] Registered webhook: ${webhook.id}`);

    return { id: webhook.id, secret: webhook.secret };
  }
}
