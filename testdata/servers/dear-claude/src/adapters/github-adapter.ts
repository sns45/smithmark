/**
 * GitHub Adapter
 * Handles GitHub webhooks and API interactions
 * Supports both OAuth and GitHub App authentication
 */

import { createHmac, createSign, timingSafeEqual } from "crypto";
import { readFileSync, appendFileSync } from "fs";
import type { Context } from "hono";

const debugLog = (msg: string) => {
  appendFileSync("/tmp/dear-claude-debug.log", `${new Date().toISOString()} [GitHubAdapter] ${msg}\n`);
};
import type { PlatformAdapter, PlatformEvent, AdapterConfig } from "./platform-adapter.js";

interface GitHubIssue {
  number: number;
  title: string;
  body?: string;
  user?: { login: string };
  labels?: Array<{ name: string }>;
}

interface GitHubComment {
  id: number;
  body: string;
  user?: { login: string };
}

interface GitHubRepository {
  full_name: string;
  owner: { login: string };
  name: string;
  clone_url: string;
}

interface GitHubPullRequest {
  number: number;
  title: string;
  body?: string;
  user?: { login: string };
  diff_url?: string;
  head: { ref: string };
  base: { ref: string };
}

interface GitHubPRReviewComment {
  id: number;
  body: string;
  path: string;
  line?: number;
  diff_hunk: string;
  user?: { login: string };
}

interface GitHubWebhookPayload {
  action: string;
  issue?: GitHubIssue;
  comment?: GitHubComment;
  pull_request?: GitHubPullRequest;
  review?: { id: number; body?: string; state: string; user?: { login: string } };
  repository: GitHubRepository;
  sender: { login: string };
  installation?: { id: number };
}

interface InstallationToken {
  token: string;
  expiresAt: Date;
}

export class GitHubAdapter implements PlatformAdapter {
  readonly platform = "github" as const;
  private config: AdapterConfig;
  private apiUrl = "https://api.github.com";
  private authUrl = "https://github.com/login/oauth/authorize";
  private tokenUrl = "https://github.com/login/oauth/access_token";

  // GitHub App specific
  private appId?: string;
  private privateKey?: string;
  private installationTokens: Map<number, InstallationToken> = new Map();

  constructor(config: AdapterConfig) {
    this.config = config;

    // Load GitHub App credentials if available
    this.appId = process.env.GITHUB_APP_ID;
    const privateKeyPath = process.env.GITHUB_APP_PRIVATE_KEY_PATH;
    const privateKeyEnv = process.env.GITHUB_APP_PRIVATE_KEY;

    if (privateKeyPath) {
      try {
        this.privateKey = readFileSync(privateKeyPath, "utf-8");
        debugLog(` Loaded GitHub App private key from ${privateKeyPath}`);
      } catch (e) {
        console.error(`[GitHubAdapter] Failed to load private key from ${privateKeyPath}:`, e);
      }
    } else if (privateKeyEnv) {
      // Support inline private key (with escaped newlines)
      this.privateKey = privateKeyEnv.replace(/\\n/g, "\n");
      console.log("[GitHubAdapter] Using GitHub App private key from environment");
    }

    if (this.appId && this.privateKey) {
      debugLog(` GitHub App mode enabled (App ID: ${this.appId}, key length: ${this.privateKey.length})`);
    } else {
      debugLog(` GitHub App mode NOT enabled - appId: ${this.appId ? "set" : "missing"}, privateKey: ${this.privateKey ? "set" : "missing"}`);
      debugLog(` Env vars: GITHUB_APP_ID=${process.env.GITHUB_APP_ID}, GITHUB_APP_PRIVATE_KEY_PATH=${process.env.GITHUB_APP_PRIVATE_KEY_PATH}`);
    }
  }

  isConfigured(): boolean {
    // GitHub App mode OR OAuth mode
    return !!(
      (this.appId && this.privateKey) ||
      this.config.accessToken ||
      (this.config.clientId && this.config.clientSecret)
    );
  }

  isAppMode(): boolean {
    return !!(this.appId && this.privateKey);
  }

  /**
   * Generate a JWT for GitHub App authentication
   */
  private generateAppJwt(): string {
    if (!this.appId || !this.privateKey) {
      throw new Error("GitHub App credentials not configured");
    }

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iat: now - 60, // Issued 60 seconds ago to account for clock drift
      exp: now + 600, // Expires in 10 minutes
      iss: this.appId
    };

    // Create JWT manually (header.payload.signature)
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const unsigned = `${header}.${body}`;

    const sign = createSign("RSA-SHA256");
    sign.update(unsigned);
    const signature = sign.sign(this.privateKey, "base64url");

    return `${unsigned}.${signature}`;
  }

  /**
   * Get an installation access token for a specific installation
   */
  private async getInstallationToken(installationId: number): Promise<string> {
    // Check cache
    const cached = this.installationTokens.get(installationId);
    if (cached && cached.expiresAt > new Date(Date.now() + 60000)) {
      debugLog(` Using cached installation token`);
      return cached.token;
    }

    debugLog(` Generating JWT for app ID: ${this.appId}`);
    const jwt = this.generateAppJwt();
    debugLog(` JWT generated, length: ${jwt.length}`);

    const response = await fetch(`${this.apiUrl}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });

    debugLog(` Installation token response: ${response.status}`);

    if (!response.ok) {
      const error = await response.text();
      debugLog(` Installation token error: ${error}`);
      throw new Error(`Failed to get installation token: ${error}`);
    }

    const data = await response.json() as { token: string; expires_at: string };

    // Cache the token
    this.installationTokens.set(installationId, {
      token: data.token,
      expiresAt: new Date(data.expires_at)
    });

    debugLog(` Got installation token for installation ${installationId}`);
    return data.token;
  }

  /**
   * Get access token - either from OAuth or GitHub App installation
   */
  private async getAccessToken(installationId?: number): Promise<string> {
    // Use installation ID from parameter, env var, or fallback
    const effectiveInstallationId = installationId ||
      (process.env.GITHUB_INSTALLATION_ID ? parseInt(process.env.GITHUB_INSTALLATION_ID) : undefined);

    debugLog(` getAccessToken: isAppMode=${this.isAppMode()}, effectiveInstallationId=${effectiveInstallationId}`);

    if (this.isAppMode() && effectiveInstallationId) {
      return this.getInstallationToken(effectiveInstallationId);
    }

    if (this.config.accessToken) {
      debugLog(` Using OAuth token`);
      return this.config.accessToken;
    }

    throw new Error("No access token available");
  }

  setAccessToken(token: string): void {
    this.config.accessToken = token;
  }

  async verifySignature(ctx: Context, body: string): Promise<boolean> {
    if (!this.config.webhookSecret) {
      console.warn("[GitHubAdapter] No webhook secret configured, skipping verification");
      return true;
    }

    const signature = ctx.req.header("x-hub-signature-256");
    if (!signature) {
      console.warn("[GitHubAdapter] Missing GitHub signature header");
      return false;
    }

    try {
      const hmac = createHmac("sha256", this.config.webhookSecret);
      hmac.update(body);
      const expectedSignature = `sha256=${hmac.digest("hex")}`;

      const sigBuffer = Buffer.from(signature);
      const expectedBuffer = Buffer.from(expectedSignature);

      if (sigBuffer.length !== expectedBuffer.length) {
        console.warn("[GitHubAdapter] Signature length mismatch");
        return false;
      }

      return timingSafeEqual(sigBuffer, expectedBuffer);
    } catch (error) {
      console.error("[GitHubAdapter] Signature verification error:", error);
      return false;
    }
  }

  async parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null> {
    const event = ctx.req.header("x-github-event");
    const payload = body as GitHubWebhookPayload;

    // Extract installation ID for GitHub App mode
    const installationId = payload.installation?.id;

    // Handle issue events
    if (event === "issues" && payload.action === "opened" && payload.issue) {
      return {
        platform: "github",
        threadId: `${payload.repository.full_name}#${payload.issue.number}`,
        content: `${payload.issue.title || ""}\n${payload.issue.body || ""}`,
        isDescription: true,
        authorId: payload.issue.user?.login,
        installationId, // Pass installation ID for GitHub App mode
        raw: payload
      };
    }

    // Handle issue comment events (also fires for PR comments)
    if (event === "issue_comment" && payload.action === "created" && payload.comment && payload.issue) {
      // Check if this is a PR comment (GitHub includes pull_request key on PR issues)
      const isPR = !!(payload.issue as any).pull_request;
      let diffContent: string | undefined;
      let repoCloneUrl: string | undefined;
      let prBranch: string | undefined;
      let prBaseBranch: string | undefined;

      if (isPR) {
        try {
          // Fetch PR details to get branch info and diff
          const prData = await this.fetchPRDetails(
            payload.repository.owner.login,
            payload.repository.name,
            payload.issue.number,
            installationId
          );
          repoCloneUrl = payload.repository.clone_url;
          prBranch = prData.head.ref;
          prBaseBranch = prData.base.ref;
          diffContent = await this.fetchPRDiff(
            payload.repository.owner.login,
            payload.repository.name,
            payload.issue.number,
            installationId
          );
        } catch (e) {
          console.error("[GitHubAdapter] Failed to fetch PR details for issue_comment:", e);
        }
      }

      return {
        platform: "github",
        threadId: `${payload.repository.full_name}#${payload.issue.number}`,
        content: payload.comment.body || "",
        isDescription: false,
        messageId: String(payload.comment.id),
        authorId: payload.comment.user?.login,
        installationId,
        isPullRequest: isPR,
        diffContent,
        repoCloneUrl,
        prBranch,
        prBaseBranch,
        prNumber: isPR ? payload.issue.number : undefined,
        raw: payload
      };
    }

    // Handle pull request opened
    if (event === "pull_request" && payload.action === "opened" && payload.pull_request) {
      const pr = payload.pull_request;
      let diffContent: string | undefined;
      try {
        diffContent = await this.fetchPRDiff(
          payload.repository.owner.login,
          payload.repository.name,
          pr.number,
          installationId
        );
      } catch (e) {
        console.error("[GitHubAdapter] Failed to fetch PR diff:", e);
      }

      return {
        platform: "github",
        threadId: `${payload.repository.full_name}#${pr.number}`,
        content: `${pr.title || ""}\n${pr.body || ""}`,
        isDescription: true,
        authorId: pr.user?.login,
        installationId,
        isPullRequest: true,
        diffContent,
        repoCloneUrl: payload.repository.clone_url,
        prBranch: pr.head.ref,
        prBaseBranch: pr.base.ref,
        prNumber: pr.number,
        raw: payload
      };
    }

    // Handle PR review comment
    if (event === "pull_request_review_comment" && payload.action === "created" && payload.comment) {
      const prNumber = (payload as any).pull_request?.number;
      if (!prNumber) return null;

      return {
        platform: "github",
        threadId: `${payload.repository.full_name}#${prNumber}`,
        content: payload.comment.body || "",
        isDescription: false,
        messageId: String(payload.comment.id),
        authorId: payload.comment.user?.login,
        installationId,
        isPullRequest: true,
        raw: payload
      };
    }

    return null;
  }

  async postResponse(threadId: string, message: string, installationId?: number): Promise<void> {
    debugLog(` postResponse called - threadId: ${threadId}, installationId: ${installationId}, isAppMode: ${this.isAppMode()}`);
    const token = await this.getAccessToken(installationId);
    debugLog(` Got token: ${token ? "yes (length: " + token.length + ")" : "no"}`);

    // Parse threadId: "owner/repo#number"
    const match = threadId.match(/^(.+?)#(\d+)$/);
    if (!match) {
      throw new Error(`Invalid thread ID format: ${threadId}`);
    }

    const [, repo, issueNumber] = match;

    const response = await fetch(`${this.apiUrl}/repos/${repo}/issues/${issueNumber}/comments`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      },
      body: JSON.stringify({ body: message })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post GitHub comment: ${error}`);
    }

    const mode = this.isAppMode() ? "[bot]" : "[oauth]";
    debugLog(` Posted comment to ${threadId} ${mode}`);
  }

  async setStatus(threadId: string, status: "processing" | "done" | "error", installationId?: number): Promise<void> {
    let token: string;
    try {
      token = await this.getAccessToken(installationId);
    } catch {
      return; // No token available
    }

    // Parse threadId
    const match = threadId.match(/^(.+?)#(\d+)$/);
    if (!match) return;

    const [, repo, issueNumber] = match;

    // Map status to label names
    const labelToAdd = `claude-${status}`;
    const labelsToRemove = ["claude-processing", "claude-done", "claude-error"].filter(l => l !== labelToAdd);

    // Remove old status labels and add new one
    try {
      // Get current labels
      const issueResponse = await fetch(`${this.apiUrl}/repos/${repo}/issues/${issueNumber}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json"
        }
      });

      if (!issueResponse.ok) return;

      const issue = await issueResponse.json() as GitHubIssue;
      const currentLabels = (issue.labels || []).map(l => l.name);

      // Filter out claude status labels and add new one
      const newLabels = currentLabels
        .filter(l => !labelsToRemove.includes(l) && l !== labelToAdd)
        .concat(labelToAdd);

      // Update labels
      await fetch(`${this.apiUrl}/repos/${repo}/issues/${issueNumber}/labels`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/vnd.github+json"
        },
        body: JSON.stringify({ labels: newLabels })
      });

      debugLog(` Set label "${labelToAdd}" on ${threadId}`);
    } catch (error) {
      console.error(`[GitHubAdapter] Failed to set status label:`, error);
    }
  }

  async addReaction(threadId: string, emoji: string, targetId?: string, installationId?: number): Promise<void> {
    let token: string;
    try {
      token = await this.getAccessToken(installationId);
    } catch {
      return;
    }

    const match = threadId.match(/^(.+?)#(\d+)$/);
    if (!match) return;
    const [, repo, issueNumber] = match;

    // GitHub reaction content values
    const githubEmoji = this.mapEmojiToGitHub(emoji);

    try {
      let url: string;
      if (targetId) {
        // React to a specific comment
        url = `${this.apiUrl}/repos/${repo}/issues/comments/${targetId}/reactions`;
      } else {
        // React to the issue/PR itself
        url = `${this.apiUrl}/repos/${repo}/issues/${issueNumber}/reactions`;
      }

      await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28"
        },
        body: JSON.stringify({ content: githubEmoji })
      });

      debugLog(` Added reaction ${githubEmoji} to ${threadId}`);
    } catch (error) {
      console.error("[GitHubAdapter] Failed to add reaction:", error);
    }
  }

  private mapEmojiToGitHub(emoji: string): string {
    const map: Record<string, string> = {
      "eyes": "eyes",
      "white_check_mark": "+1",
      "x": "confused",
      "+1": "+1",
      "-1": "-1",
      "rocket": "rocket",
      "heart": "heart",
      "hooray": "hooray",
      "laugh": "laugh",
    };
    return map[emoji] || emoji;
  }

  private async fetchPRDetails(owner: string, repo: string, prNumber: number, installationId?: number): Promise<GitHubPullRequest> {
    const token = await this.getAccessToken(installationId);

    const response = await fetch(`${this.apiUrl}/repos/${owner}/${repo}/pulls/${prNumber}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });

    if (!response.ok) throw new Error(`Failed to fetch PR details: ${response.status}`);
    return response.json() as Promise<GitHubPullRequest>;
  }

  private async fetchPRDiff(owner: string, repo: string, prNumber: number, installationId?: number): Promise<string> {
    const token = await this.getAccessToken(installationId);

    const response = await fetch(`${this.apiUrl}/repos/${owner}/${repo}/pulls/${prNumber}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github.diff",
        "X-GitHub-Api-Version": "2022-11-28"
      }
    });

    if (!response.ok) throw new Error(`Failed to fetch PR diff: ${response.status}`);
    return response.text();
  }

  async getAuthCloneUrl(cloneUrl: string, installationId?: number): Promise<string> {
    const token = await this.getAccessToken(installationId);
    // Replace https://github.com/... with https://x-access-token:<token>@github.com/...
    return cloneUrl.replace("https://", `https://x-access-token:${token}@`);
  }

  async postPRReview(
    threadId: string,
    body: string,
    comments?: Array<{ path: string; line: number; body: string }>,
    event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES" = "COMMENT",
    installationId?: number
  ): Promise<void> {
    const token = await this.getAccessToken(installationId);

    const match = threadId.match(/^(.+?)#(\d+)$/);
    if (!match) throw new Error(`Invalid thread ID format: ${threadId}`);
    const [, repo, prNumber] = match;

    const payload: Record<string, unknown> = { body, event };
    if (comments && comments.length > 0) {
      payload.comments = comments;
    }

    const response = await fetch(`${this.apiUrl}/repos/${repo}/pulls/${prNumber}/reviews`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to post PR review: ${error}`);
    }

    debugLog(` Posted PR review to ${threadId}`);
  }

  getAuthUrl(redirectUri: string, state: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId!,
      redirect_uri: redirectUri,
      scope: "repo read:user",
      state
    });

    return `${this.authUrl}?${params.toString()}`;
  }

  async handleCallback(code: string, redirectUri: string): Promise<{ accessToken: string; refreshToken?: string; username?: string }> {
    const response = await fetch(this.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        code,
        redirect_uri: redirectUri
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to exchange code: ${error}`);
    }

    const data = await response.json() as { access_token: string; refresh_token?: string; error?: string };

    if (data.error) {
      throw new Error(`OAuth error: ${data.error}`);
    }

    // Fetch the authenticated user's profile to get their username
    let username: string | undefined;
    try {
      const userResponse = await fetch(`${this.apiUrl}/user`, {
        headers: {
          Authorization: `Bearer ${data.access_token}`,
          Accept: "application/vnd.github+json"
        }
      });
      if (userResponse.ok) {
        const userData = await userResponse.json() as { login: string };
        username = userData.login;
        debugLog(` Authenticated as: ${username}`);
      }
    } catch (err) {
      console.error("[GitHubAdapter] Failed to fetch user profile:", err);
    }

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      username
    };
  }

  /**
   * Create a webhook for a repository
   */
  async createWebhook(owner: string, repo: string, url: string, secret: string): Promise<{ id: number }> {
    if (!this.config.accessToken) {
      throw new Error("GitHub access token not configured");
    }

    const response = await fetch(`${this.apiUrl}/repos/${owner}/${repo}/hooks`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.config.accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/vnd.github+json"
      },
      body: JSON.stringify({
        name: "web",
        active: true,
        events: ["issues", "issue_comment", "pull_request", "pull_request_review_comment"],
        config: {
          url,
          content_type: "json",
          secret,
          insecure_ssl: "0"
        }
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to create webhook: ${error}`);
    }

    const webhook = await response.json() as { id: number };
    debugLog(` Created webhook ${webhook.id} for ${owner}/${repo}`);

    return webhook;
  }
}
