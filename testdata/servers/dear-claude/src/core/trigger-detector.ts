/**
 * Trigger Detector
 * Detects "dear-claude" mentions in platform events
 */

export interface TriggerContext {
  threadId: string;
  platform: "linear" | "github" | "gitlab" | "jira" | "notion" | "obsidian";
  content: string;
  isDescription: boolean;  // True if this is the issue description/email body, false if comment/reply
  messageId?: string;
  authorId?: string;
  timestamp: number;
}

export type TriggerAction = "NEW" | "RESUME" | "IGNORE";

export interface TriggerResult {
  action: TriggerAction;
  context?: TriggerContext;
  reason: string;
}

// Pattern to match "dear claude", "Dear Claude", etc. (space only, not hyphenated)
const DEAR_CLAUDE_PATTERN = /\bdear claude\b/i;

export class TriggerDetector {
  /**
   * Check if content contains "dear-claude" trigger
   */
  static containsTrigger(content: string): boolean {
    return DEAR_CLAUDE_PATTERN.test(content);
  }

  /**
   * Extract the request content after the "dear-claude" trigger
   * Returns the full content after the trigger phrase
   */
  static extractRequest(content: string): string {
    const match = content.match(DEAR_CLAUDE_PATTERN);
    if (!match) return content;

    // Get everything after "dear-claude"
    const afterTrigger = content.slice(match.index! + match[0].length).trim();

    // Remove common punctuation that might follow the trigger
    const cleaned = afterTrigger.replace(/^[,:\-]+\s*/, "");

    return cleaned || content;
  }

  /**
   * Determine the action based on event context
   *
   * Rules:
   * - "dear-claude" in new issue description → NEW instance
   * - "dear-claude" first time in comments → NEW instance
   * - "dear-claude" again in same issue comments → RESUME instance
   * - New email with "dear-claude" → NEW instance
   * - Reply in thread with prior "dear-claude" → RESUME instance
   * - No "dear-claude" keyword → IGNORE
   */
  static determineTriggerAction(
    context: TriggerContext,
    existingInstanceId?: string,
    existingInstanceStatus?: string
  ): TriggerResult {
    const hasTrigger = this.containsTrigger(context.content);

    // No trigger phrase → IGNORE
    if (!hasTrigger) {
      return {
        action: "IGNORE",
        reason: "No 'dear-claude' trigger found in content"
      };
    }

    // Instance already running → IGNORE (debounce)
    if (existingInstanceId && existingInstanceStatus === "running") {
      return {
        action: "IGNORE",
        context,
        reason: `Instance ${existingInstanceId} is already running`
      };
    }

    // Has trigger phrase in description/body of new item
    if (context.isDescription) {
      // If an instance already exists for this thread (e.g. from a prior create/update event), deduplicate
      if (existingInstanceId && existingInstanceStatus && !["expired", "failed"].includes(existingInstanceStatus)) {
        if (existingInstanceStatus === "pending") {
          return {
            action: "IGNORE",
            context,
            reason: `Duplicate description event — instance ${existingInstanceId} already pending`
          };
        }
        return {
          action: "RESUME",
          context,
          reason: `Resuming existing instance ${existingInstanceId} from description update`
        };
      }
      return {
        action: "NEW",
        context,
        reason: "Trigger found in new item description/body"
      };
    }

    // Has trigger in comment/reply...
    // If we have an existing instance (not expired) → RESUME
    if (existingInstanceId && existingInstanceStatus && !["expired", "failed"].includes(existingInstanceStatus)) {
      return {
        action: "RESUME",
        context,
        reason: `Resuming existing instance ${existingInstanceId}`
      };
    }

    // First time trigger in comments (no existing instance or expired) → NEW
    return {
      action: "NEW",
      context,
      reason: "First trigger in thread, creating new instance"
    };
  }

  /**
   * Parse platform-specific events into TriggerContext
   */
  static parseLinearEvent(event: LinearWebhookEvent): TriggerContext | null {
    if (event.type === "Issue" && event.action === "create") {
      return {
        threadId: event.data.id,
        platform: "linear",
        content: `${event.data.title || ""}\n${event.data.description || ""}`,
        isDescription: true,
        authorId: event.data.creatorId,
        timestamp: Date.now()
      };
    }

    if (event.type === "Comment" && event.action === "create") {
      return {
        threadId: event.data.issueId || event.data.issue?.id || "",
        platform: "linear",
        content: event.data.body || "",
        isDescription: false,
        messageId: event.data.id,
        authorId: event.data.userId,
        timestamp: Date.now()
      };
    }

    return null;
  }

  static parseGitHubEvent(event: GitHubWebhookEvent): TriggerContext | null {
    if (event.action === "opened" && event.issue) {
      return {
        threadId: `${event.repository.full_name}#${event.issue.number}`,
        platform: "github",
        content: `${event.issue.title || ""}\n${event.issue.body || ""}`,
        isDescription: true,
        authorId: event.issue.user?.login,
        timestamp: Date.now()
      };
    }

    if (event.action === "created" && event.comment && event.issue) {
      return {
        threadId: `${event.repository.full_name}#${event.issue.number}`,
        platform: "github",
        content: event.comment.body || "",
        isDescription: false,
        messageId: String(event.comment.id),
        authorId: event.comment.user?.login,
        timestamp: Date.now()
      };
    }

    return null;
  }

  static parseGitLabEvent(event: GitLabWebhookEvent): TriggerContext | null {
    if (event.object_kind === "issue" && event.object_attributes?.action === "open") {
      const attrs = event.object_attributes;
      return {
        threadId: `${event.project.path_with_namespace}#${attrs.iid}`,
        platform: "gitlab",
        content: `${attrs.title || ""}\n${attrs.description || ""}`,
        isDescription: true,
        authorId: event.user?.username,
        timestamp: Date.now()
      };
    }

    if (event.object_kind === "note") {
      const attrs = event.object_attributes;
      const iid = event.merge_request?.iid || event.issue?.iid;
      if (!iid) return null;

      return {
        threadId: `${event.project.path_with_namespace}#${iid}`,
        platform: "gitlab",
        content: attrs.note || "",
        isDescription: false,
        messageId: String(attrs.id),
        authorId: event.user?.username,
        timestamp: Date.now()
      };
    }

    if (event.object_kind === "merge_request" && event.object_attributes?.action === "open") {
      const attrs = event.object_attributes;
      return {
        threadId: `${event.project.path_with_namespace}!${attrs.iid}`,
        platform: "gitlab",
        content: `${attrs.title || ""}\n${attrs.description || ""}`,
        isDescription: true,
        authorId: event.user?.username,
        timestamp: Date.now()
      };
    }

    return null;
  }
}

// Type definitions for platform events
export interface LinearWebhookEvent {
  type: "Issue" | "Comment" | string;
  action: "create" | "update" | "remove" | string;
  data: {
    id: string;
    title?: string;
    description?: string;
    body?: string;
    creatorId?: string;
    userId?: string;
    issueId?: string;
    issue?: { id: string };
  };
  organizationId: string;
}

export interface GitHubWebhookEvent {
  action: string;
  repository: {
    full_name: string;
  };
  issue?: {
    number: number;
    title?: string;
    body?: string;
    user?: { login: string };
  };
  comment?: {
    id: number;
    body?: string;
    user?: { login: string };
  };
}

export interface GitLabWebhookEvent {
  object_kind: "issue" | "note" | "merge_request" | string;
  user?: { username: string };
  project: { path_with_namespace: string; id: number };
  object_attributes: {
    id: number;
    iid?: number;
    title?: string;
    description?: string;
    note?: string;
    action?: string;
    noteable_type?: string;
  };
  issue?: { iid: number };
  merge_request?: { iid: number };
}
