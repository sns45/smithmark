/**
 * Platform Adapter Interface
 * Common interface for all platform integrations
 */

import type { Context } from "hono";

export type PlatformType = "linear" | "github" | "gitlab" | "jira" | "notion" | "obsidian";

export interface PlatformEvent {
  platform: PlatformType;
  threadId: string;
  content: string;
  isDescription: boolean;
  messageId?: string;
  authorId?: string;
  installationId?: number; // GitHub App installation ID
  isPullRequest?: boolean; // GitHub PR or GitLab MR
  diffContent?: string; // PR/MR diff content
  repoCloneUrl?: string; // HTTPS clone URL (no auth)
  prBranch?: string; // Source branch name
  prBaseBranch?: string; // Target branch name
  prNumber?: number; // PR/MR number
  issueTitle?: string;
  issueDescription?: string;
  parentIssueId?: string;
  projectKey?: string;
  issueUrl?: string;
  raw: unknown;
}

export interface PlatformAdapter {
  /** Platform identifier */
  readonly platform: PlatformType;

  /** Verify webhook signature */
  verifySignature(ctx: Context, body: string): Promise<boolean>;

  /** Parse webhook payload into PlatformEvent */
  parseWebhook(ctx: Context, body: unknown): Promise<PlatformEvent | null>;

  /** Post a response/comment back to the platform */
  postResponse(threadId: string, message: string, installationId?: number): Promise<void>;

  /** Add a label or status indicator (platform-specific) */
  setStatus?(threadId: string, status: "processing" | "done" | "error", installationId?: number): Promise<void>;

  /** Add an emoji reaction to a thread or comment */
  addReaction?(threadId: string, emoji: string, targetId?: string, installationId?: number): Promise<void>;

  /** Post a PR/MR review with inline comments */
  postPRReview?(threadId: string, body: string, comments?: Array<{ path: string; line: number; body: string }>, event?: "COMMENT" | "APPROVE" | "REQUEST_CHANGES", installationId?: number): Promise<void>;

  /** Get an authenticated clone URL for pushing commits */
  getAuthCloneUrl?(cloneUrl: string, installationId?: number): Promise<string>;

  /** Initialize OAuth flow */
  getAuthUrl?(redirectUri: string, state: string): string;

  /** Exchange code for tokens */
  handleCallback?(code: string, redirectUri: string): Promise<{ accessToken: string; refreshToken?: string; username?: string }>;

  /** Set access token (for injecting DB-stored OAuth tokens) */
  setAccessToken?(token: string): void;

  /** Check if adapter is configured */
  isConfigured(): boolean;
}

export interface AdapterConfig {
  clientId?: string;
  clientSecret?: string;
  webhookSecret?: string;
  accessToken?: string;
  refreshToken?: string;
}
