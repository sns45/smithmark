/**
 * Notion Adapter
 * Handles Notion webhooks and API interactions
 * Comments appear as the integration bot (not the user)
 */

import { createHmac, timingSafeEqual } from "crypto";
import type { Context } from "hono";
import type { PlatformAdapter, PlatformEvent, AdapterConfig } from "./platform-adapter.js";

interface NotionRichText {
  type: "text";
  text: { content: string; link?: { url: string } | null };
  plain_text: string;
}

interface NotionBlock {
  id: string;
  type: string;
  has_children: boolean;
  [key: string]: unknown;
}

interface NotionPage {
  id: string;
  url: string;
  properties: Record<string, NotionProperty>;
}

interface NotionProperty {
  type: string;
  title?: Array<{ plain_text: string }>;
  rich_text?: Array<{ plain_text: string }>;
  select?: { name: string } | null;
  [key: string]: unknown;
}

interface NotionCommentWebhook {
  type: "comment.created";
  data: {
    id: string;
    parent: { type: "page_id"; page_id: string } | { type: "block_id"; block_id: string };
    rich_text: NotionRichText[];
    created_by: { id: string };
  };
}

interface NotionPageWebhook {
  type: "page.content_updated";
  data: {
    id: string; // page ID
    updated_by: { id: string };
  };
}

type NotionWebhookPayload = NotionCommentWebhook | NotionPageWebhook;

export interface NotionAdapterConfig extends AdapterConfig {
  // accessToken can be from OAuth or NOTION_ACCESS_TOKEN (internal integration)
}

export class NotionAdapter implements PlatformAdapter {
  readonly platform = "notion" as const;
  private config: NotionAdapterConfig;
  private apiUrl = "https://api.notion.com/v1";
  private authUrl = "https://api.notion.com/v1/oauth/authorize";
  private tokenUrl = "https://api.notion.com/v1/oauth/token";
  private notionVersion = "2022-06-28";

  constructor(config: NotionAdapterConfig) {
    this.config = config;
  }

  isConfigured(): boolean {
    return !!(this.config.accessToken || (this.config.clientId && this.config.clientSecret));
  }

  setAccessToken(token: string): void {
    this.config.accessToken = token;
  }

  async verifySignature(ctx: Context, body: string): Promise<boolean> {
    if (!this.config.webhookSecret) {
      console.warn("[NotionAdapter] No webhook secret configured, skipping verification");
      return true;
    }

    const signature = ctx.req.header("x-notion-signature");
    if (!signature) {
      console.warn("[NotionAdapter] Missing X-Notion-Signature header");
      return false;
    }

    try {
      const hmac = createHmac("sha256", this.config.webhookSecret);
      hmac.update(body);
      const expectedSignature = hmac.digest("hex");

      const sigBuffer = Buffer.from(signature);
      const expectedBuffer = Buffer.from(expectedSignature);

      if (sigBuffer.length !== expectedBuffer.length) {
        return false;
      }

      return timingSafeEqual(sigBuffer, expectedBuffer);
    } catch (error) {
      console.error("[NotionAdapter] Signature verification error:", error);
      return false;
    }
  }

  async parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null> {
    const payload = body as NotionWebhookPayload;

    if (payload.type === "comment.created") {
      const data = (payload as NotionCommentWebhook).data;
      const pageId = data.parent.type === "page_id"
        ? data.parent.page_id
        : undefined;

      if (!pageId) {
        console.log("[NotionAdapter] Comment on non-page parent, skipping");
        return null;
      }

      const commentText = data.rich_text.map(rt => rt.plain_text).join("");

      // Fetch page context for enrichment
      const pageContext = await this.fetchPageContext(pageId);

      return {
        platform: "notion",
        threadId: `notion:${pageId}`,
        content: commentText,
        isDescription: false,
        messageId: data.id,
        authorId: data.created_by.id,
        issueTitle: pageContext?.title,
        issueDescription: pageContext?.content?.slice(0, 2000),
        issueUrl: pageContext?.url,
        raw: payload
      };
    }

    if (payload.type === "page.content_updated") {
      const data = (payload as NotionPageWebhook).data;
      const pageId = data.id;

      // Fetch the page blocks to check for trigger
      const pageContext = await this.fetchPageContext(pageId);
      if (!pageContext) return null;

      const fullContent = `${pageContext.title || ""}\n${pageContext.content || ""}`;

      return {
        platform: "notion",
        threadId: `notion:${pageId}`,
        content: fullContent,
        isDescription: true,
        authorId: data.updated_by.id,
        issueTitle: pageContext.title,
        issueDescription: pageContext.content?.slice(0, 2000),
        issueUrl: pageContext.url,
        raw: payload
      };
    }

    return null;
  }

  async postResponse(threadId: string, message: string): Promise<void> {
    if (!this.config.accessToken) {
      throw new Error("Notion access token not configured");
    }

    // threadId format: "notion:<page-uuid>"
    const pageId = threadId.replace("notion:", "");

    // Notion rich_text blocks have a 2000 char limit per block
    const chunks = this.chunkText(message, 2000);

    const richText: NotionRichText[] = chunks.map(chunk => ({
      type: "text",
      text: { content: chunk },
      plain_text: chunk
    }));

    const response = await this.notionFetch(`/comments`, {
      method: "POST",
      body: JSON.stringify({
        parent: { page_id: pageId },
        rich_text: richText
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post Notion comment: ${error}`);
    }

    console.log(`[NotionAdapter] Posted comment to page ${pageId}`);
  }

  async setStatus(threadId: string, status: "processing" | "done" | "error"): Promise<void> {
    if (!this.config.accessToken) return;

    const pageId = threadId.replace("notion:", "");
    const statusValue = `claude-${status}`;

    try {
      // Try to update a "Claude Status" select property if it exists
      const response = await this.notionFetch(`/pages/${pageId}`, {
        method: "PATCH",
        body: JSON.stringify({
          properties: {
            "Claude Status": {
              select: { name: statusValue }
            }
          }
        })
      });

      if (response.ok) {
        console.log(`[NotionAdapter] Set status "${statusValue}" on page ${pageId}`);
      } else {
        // Property might not exist — that's fine, silently skip
        console.log(`[NotionAdapter] Could not set status property (may not exist): ${response.status}`);
      }
    } catch (error) {
      console.error("[NotionAdapter] Failed to set status:", error);
    }
  }

  async addReaction(_threadId: string, _emoji: string, _targetId?: string): Promise<void> {
    // Notion has no comment reaction API
    console.log("[NotionAdapter] Reactions not supported on Notion, skipping");
  }

  // --- OAuth ---

  getAuthUrl(redirectUri: string, state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId!,
      redirect_uri: redirectUri,
      response_type: "code",
      owner: "user",
      state
    });

    return `${this.authUrl}?${params.toString()}`;
  }

  async handleCallback(code: string, redirectUri: string): Promise<{ accessToken: string; refreshToken?: string; username?: string }> {
    const basicAuth = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64");

    const response = await fetch(this.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Basic ${basicAuth}`,
        "Notion-Version": this.notionVersion
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to exchange code: ${error}`);
    }

    const data = await response.json() as {
      access_token: string;
      bot_id: string;
      workspace_name?: string;
      owner?: { user?: { id: string; name?: string } };
    };

    const username = data.owner?.user?.id;
    console.log(`[NotionAdapter] Authenticated for workspace: ${data.workspace_name} (bot: ${data.bot_id})`);

    return {
      accessToken: data.access_token,
      username
    };
  }

  // --- Context Enrichment ---

  private async fetchPageContext(pageId: string): Promise<{
    title: string;
    content: string;
    url: string;
    databaseProperties?: Record<string, string>;
  } | null> {
    if (!this.config.accessToken) return null;

    try {
      // Fetch page metadata
      const pageResp = await this.notionFetch(`/pages/${pageId}`);
      if (!pageResp.ok) return null;
      const page = await pageResp.json() as NotionPage;

      // Extract title from properties
      let title = "";
      for (const [, prop] of Object.entries(page.properties)) {
        if (prop.type === "title" && prop.title) {
          title = prop.title.map(t => t.plain_text).join("");
          break;
        }
      }

      // Extract DB properties
      const dbProps: Record<string, string> = {};
      for (const [key, prop] of Object.entries(page.properties)) {
        if (prop.type === "rich_text" && prop.rich_text) {
          dbProps[key] = prop.rich_text.map(t => t.plain_text).join("");
        } else if (prop.type === "select" && prop.select) {
          dbProps[key] = prop.select.name;
        }
      }

      // Fetch all blocks (paginated)
      const content = await this.fetchAllBlocks(pageId);

      return {
        title,
        content,
        url: page.url,
        databaseProperties: Object.keys(dbProps).length > 0 ? dbProps : undefined
      };
    } catch (err) {
      console.error("[NotionAdapter] Failed to fetch page context:", err);
      return null;
    }
  }

  private async fetchAllBlocks(blockId: string, depth: number = 0): Promise<string> {
    if (depth > 3) return ""; // Limit recursion depth
    if (!this.config.accessToken) return "";

    const parts: string[] = [];
    let cursor: string | undefined;

    do {
      const url = cursor
        ? `/blocks/${blockId}/children?start_cursor=${cursor}&page_size=100`
        : `/blocks/${blockId}/children?page_size=100`;

      // Simple rate limit delay
      if (cursor) await this.delay(350);

      const resp = await this.notionFetch(url);
      if (!resp.ok) break;

      const data = await resp.json() as {
        results: NotionBlock[];
        has_more: boolean;
        next_cursor: string | null;
      };

      for (const block of data.results) {
        const text = this.extractBlockText(block);
        if (text) parts.push(text);

        // Recurse into children
        if (block.has_children) {
          const childContent = await this.fetchAllBlocks(block.id, depth + 1);
          if (childContent) parts.push(childContent);
        }
      }

      cursor = data.has_more && data.next_cursor ? data.next_cursor : undefined;
    } while (cursor);

    return parts.join("\n");
  }

  private extractBlockText(block: NotionBlock): string {
    const typeData = block[block.type] as { rich_text?: NotionRichText[] } | undefined;
    if (!typeData?.rich_text) return "";
    return typeData.rich_text.map(rt => rt.plain_text).join("");
  }

  // --- Helpers ---

  private async notionFetch(path: string, init?: RequestInit): Promise<Response> {
    return fetch(`${this.apiUrl}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.config.accessToken}`,
        "Notion-Version": this.notionVersion,
        ...init?.headers
      }
    });
  }

  private chunkText(text: string, maxLen: number): string[] {
    const chunks: string[] = [];
    let remaining = text;
    while (remaining.length > 0) {
      if (remaining.length <= maxLen) {
        chunks.push(remaining);
        break;
      }
      // Try to break at a newline
      let breakIdx = remaining.lastIndexOf("\n", maxLen);
      if (breakIdx < maxLen / 2) breakIdx = maxLen;
      chunks.push(remaining.slice(0, breakIdx));
      remaining = remaining.slice(breakIdx);
    }
    return chunks;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
