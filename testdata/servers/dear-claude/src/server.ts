/**
 * Hono HTTP Server
 * Handles webhooks and OAuth callbacks
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { appendFileSync } from "fs";
const debugLog = (msg: string) => {
  appendFileSync("/tmp/dear-claude-debug.log", `${new Date().toISOString()} ${msg}\n`);
};
import type { DatabaseManager, Instance } from "./db/schema.js";
import type { InstanceManager } from "./core/instance-manager.js";
import { parseReviewOutput } from "./core/claude-executor.js";
import type { ClaudeExecutor, PlatformCallbacks } from "./core/claude-executor.js";
import type { RepoMeta } from "./core/instance-manager.js";
import { TriggerDetector } from "./core/trigger-detector.js";
import { LinearAdapter } from "./adapters/linear-adapter.js";

import { GitHubAdapter } from "./adapters/github-adapter.js";
import { GitLabAdapter } from "./adapters/gitlab-adapter.js";
import { JiraAdapter } from "./adapters/jira-adapter.js";
import { NotionAdapter } from "./adapters/notion-adapter.js";
import { ObsidianAdapter } from "./adapters/obsidian-adapter.js";
import type { ObsidianVaultWatcher } from "./adapters/obsidian-watcher.js";
import type { PlatformAdapter } from "./adapters/platform-adapter.js";
import type { PlatformCredentials, IssueContext, AllPlatformCredentials } from "./core/claude-executor.js";
import { sanitize } from "./utils/sanitize.js";

/**
 * Build credentials for ALL configured platforms (not just the triggering one).
 * This lets instances from any platform call APIs on any other platform.
 */
export function buildAllCredentials(config: ServerConfig, db: DatabaseManager): AllPlatformCredentials {
  const creds: AllPlatformCredentials = {};

  // Linear
  const linearToken = db.getOAuthTokenByProvider("linear")?.access_token || config.linear?.accessToken;
  if (linearToken) {
    creds.linear = { token: linearToken };
  }

  // Jira
  if (config.jira?.domain && config.jira?.userEmail && config.jira?.apiToken) {
    creds.jira = {
      basicAuth: Buffer.from(`${config.jira.userEmail}:${config.jira.apiToken}`).toString("base64"),
      baseUrl: `https://${config.jira.domain}.atlassian.net`
    };
  }

  // Notion
  const notionToken = db.getOAuthTokenByProvider("notion")?.access_token || config.notion?.accessToken;
  if (notionToken) {
    creds.notion = { token: notionToken };
  }

  // GitHub
  const githubToken = db.getOAuthTokenByProvider("github")?.access_token || config.github?.accessToken;
  if (githubToken) {
    creds.github = { token: githubToken };
  }

  // GitLab
  const gitlabToken = db.getOAuthTokenByProvider("gitlab")?.access_token || config.gitlab?.accessToken;
  if (gitlabToken) {
    creds.gitlab = { token: gitlabToken };
  }

  return creds;
}

export interface ServerConfig {
  port: number;
  publicUrl?: string;
  linear?: {
    clientId?: string;
    clientSecret?: string;
    webhookSecret?: string;
    accessToken?: string;
  };
  github?: {
    clientId?: string;
    clientSecret?: string;
    webhookSecret?: string;
    accessToken?: string;
  };
  gitlab?: {
    accessToken?: string;
    webhookSecret?: string;
  };
  jira?: {
    domain?: string;
    userEmail?: string;
    apiToken?: string;
    webhookSecret?: string;
  };
  notion?: {
    clientId?: string;
    clientSecret?: string;
    webhookSecret?: string;
    accessToken?: string;
  };
  obsidian?: {
    vaultPath?: string;
  };
}

export function createServer(
  config: ServerConfig,
  db: DatabaseManager,
  instanceManager: InstanceManager,
  executor: ClaudeExecutor,
  obsidianWatcher?: ObsidianVaultWatcher
): Hono {
  const app = new Hono();

  // Middleware
  app.use("*", logger());
  app.use("*", cors());

  // Initialize adapters
  const adapters: Map<string, PlatformAdapter> = new Map();

  if (config.linear) {
    adapters.set("linear", new LinearAdapter(config.linear));
  }
  if (config.github) {
    adapters.set("github", new GitHubAdapter(config.github));
  }
  if (config.gitlab) {
    adapters.set("gitlab", new GitLabAdapter(config.gitlab));
  }
  if (config.jira) {
    adapters.set("jira", new JiraAdapter(config.jira));
  }
  if (config.notion) {
    adapters.set("notion", new NotionAdapter(config.notion));
  }
  if (config.obsidian?.vaultPath) {
    adapters.set("obsidian", new ObsidianAdapter(config.obsidian.vaultPath, obsidianWatcher));
  }

  // Health check
  app.get("/health", async (c) => {
    const publicUrl = config.publicUrl;

    return c.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      transport: "tailscale",
      publicUrl: publicUrl || null,
      webhooks: publicUrl ? {
        github: `${publicUrl}/webhook/github`,
        linear: `${publicUrl}/webhook/linear`,
        gitlab: `${publicUrl}/webhook/gitlab`,
        jira: `${publicUrl}/webhook/jira`,
        notion: `${publicUrl}/webhook/notion`
      } : null,
      oauth: publicUrl ? {
        github: `${publicUrl}/setup/github`,
        linear: `${publicUrl}/setup/linear`,
        notion: `${publicUrl}/setup/notion`
      } : null,
      platforms: {
        linear: adapters.has("linear"),
        github: adapters.has("github"),
        gitlab: adapters.has("gitlab"),
        jira: adapters.has("jira"),
        notion: adapters.has("notion"),
        obsidian: adapters.has("obsidian")
      },
      authenticatedUsers: {
        github: db.getPlatformUsername("github") || null,
        linear: db.getPlatformUsername("linear") || null
      }
    });
  });

  // Webhook endpoints
  app.post("/webhook/:platform", async (c) => {
    const platform = c.req.param("platform") as "linear" | "github" | "gitlab" | "jira" | "notion";
    const adapter = adapters.get(platform);

    if (!adapter) {
      return c.json({ error: `Platform ${platform} not configured` }, 400);
    }

    // Get raw body for signature verification
    const rawBody = await c.req.text();

    // Verify signature
    const isValid = await adapter.verifySignature(c, rawBody);
    if (!isValid) {
      console.warn(`[Server] Invalid ${platform} webhook signature`);
      return c.json({ error: "Invalid signature" }, 401);
    }

    // Inject DB token before parsing (parseWebhook may need to call APIs)
    const dbToken = db.getOAuthTokenByProvider(platform);
    if (dbToken?.access_token && adapter.setAccessToken) {
      adapter.setAccessToken(dbToken.access_token);
    }

    // Parse webhook
    const body = JSON.parse(rawBody);
    const event = await adapter.parseWebhook(c, body);

    if (!event) {
      // Not a relevant event
      return c.json({ status: "ignored" });
    }

    // Check if the event is from the authenticated user (user filtering)
    const authenticatedUsername = db.getPlatformUsername(platform);
    if (authenticatedUsername && event.authorId) {
      if (event.authorId.toLowerCase() !== authenticatedUsername.toLowerCase()) {
        console.log(`[Server] Ignoring event from ${event.authorId} (authenticated user: ${authenticatedUsername})`);
        return c.json({ status: "ignored", reason: "Event not from authenticated user" });
      }
    }

    // Check for trigger
    if (!TriggerDetector.containsTrigger(event.content)) {
      console.log(`[Server] No trigger found in ${platform} event for thread ${event.threadId}`);
      return c.json({ status: "no_trigger" });
    }

    // Process the event
    const triggerContext = {
      threadId: event.threadId,
      platform: event.platform,
      content: event.content,
      isDescription: event.isDescription,
      messageId: event.messageId,
      authorId: event.authorId,
      timestamp: Date.now()
    };

    const result = await instanceManager.processEvent(triggerContext);
    console.log(`[Server] Trigger result for ${platform}:${event.threadId}: ${result.action} - ${result.reason}`);

    if (result.action === "IGNORE") {
      return c.json({ status: "ignored", reason: result.reason });
    }

    // Set up platform callbacks
    // Pass installationId for GitHub App mode
    const installationId = event.installationId;

    const callbacks: PlatformCallbacks = {
      onStart: async (instanceId, message) => {
        debugLog(`onStart called for ${instanceId}, installationId: ${installationId}`);
        try {
          // React with eyes emoji to indicate processing started
          if (adapter.addReaction) {
            await adapter.addReaction(event.threadId, "eyes", event.messageId, installationId);
          }
          const safeMessage = sanitize(message);
          await adapter.postResponse(event.threadId, safeMessage, installationId);
          debugLog(`onStart postResponse succeeded`);
          if (adapter.setStatus) {
            await adapter.setStatus(event.threadId, "processing", installationId);
          }
        } catch (err) {
          debugLog(`onStart failed: ${err}`);
          console.error(`[Server] Failed to send start message:`, err);
        }
      },
      onComplete: async (instanceId, summary) => {
        try {
          // React with checkmark on completion
          if (adapter.addReaction) {
            await adapter.addReaction(event.threadId, "white_check_mark", event.messageId, installationId);
          }
          const safeSummary = sanitize(summary);
          // For PR/MR events, parse review output and post inline comments
          if (event.isPullRequest && adapter.postPRReview) {
            const parsed = parseReviewOutput(safeSummary);
            const comments = parsed.inlineComments.map(c => ({
              path: c.path,
              line: c.endLine || c.startLine,
              body: c.body
            }));
            await adapter.postPRReview(
              event.threadId,
              parsed.summary,
              comments.length > 0 ? comments : undefined,
              "COMMENT",
              installationId
            );
          } else {
            await adapter.postResponse(event.threadId, safeSummary, installationId);
          }
          if (adapter.setStatus) {
            await adapter.setStatus(event.threadId, "done", installationId);
          }
        } catch (err) {
          console.error(`[Server] Failed to send completion message:`, err);
        }
      },
      onError: async (instanceId, error) => {
        try {
          // React with X on error
          if (adapter.addReaction) {
            await adapter.addReaction(event.threadId, "x", event.messageId, installationId);
          }
          const safeError = sanitize(error);
          await adapter.postResponse(event.threadId, `**Error**\n${safeError}`, installationId);
          if (adapter.setStatus) {
            await adapter.setStatus(event.threadId, "error", installationId);
          }
        } catch (err) {
          console.error(`[Server] Failed to send error message:`, err);
        }
      }
    };

    // Execute Claude
    const isResume = result.action === "RESUME";

    // Build repo metadata for PR/MR events (or refresh token for resumes)
    let repoMeta: RepoMeta | undefined;
    if (event.repoCloneUrl && event.prBranch && adapter.getAuthCloneUrl) {
      try {
        const authCloneUrl = await adapter.getAuthCloneUrl(event.repoCloneUrl, installationId);
        const repoName = event.repoCloneUrl.replace(/\.git$/, "").split("/").slice(-2).join("/");
        repoMeta = {
          authCloneUrl,
          branch: event.prBranch,
          baseBranch: event.prBaseBranch || "main",
          prNumber: event.prNumber || 0,
          repoName
        };

        // Store/update repoMeta in instance context (refreshes auth token on resume)
        const ctx = await instanceManager.loadContext(result.instanceId!);
        if (ctx) {
          ctx.repoMeta = repoMeta;
          await instanceManager.saveContext(result.instanceId!, ctx);
        }
      } catch (err) {
        console.error("[Server] Failed to build auth clone URL:", err);
      }
    }

    // Build platform credentials for the executor prompt
    let platformCredentials: PlatformCredentials | undefined;
    let issueCtx: IssueContext | undefined;

    if (platform === "linear") {
      const linearToken = dbToken?.access_token || config.linear?.accessToken;
      if (linearToken) {
        platformCredentials = {
          type: "linear",
          token: linearToken,
          projectKey: event.projectKey
        };
      }
    } else if (platform === "jira" && config.jira) {
      if (config.jira.domain && config.jira.userEmail && config.jira.apiToken) {
        platformCredentials = {
          type: "jira",
          basicAuth: Buffer.from(`${config.jira.userEmail}:${config.jira.apiToken}`).toString("base64"),
          baseUrl: `https://${config.jira.domain}.atlassian.net`,
          projectKey: event.projectKey
        };
      }
    } else if (platform === "notion") {
      const notionToken = dbToken?.access_token || config.notion?.accessToken;
      if (notionToken) {
        platformCredentials = {
          type: "notion",
          token: notionToken
        };
      }
    }

    if (event.issueTitle || event.issueUrl || event.parentIssueId || event.projectKey) {
      issueCtx = {
        title: event.issueTitle,
        issueUrl: event.issueUrl,
        parentIssueId: event.parentIssueId,
        projectKey: event.projectKey
      };
    }

    // Store platformCredentials and issueContext in instance context for resume
    if (platformCredentials || issueCtx) {
      try {
        const ctx = await instanceManager.loadContext(result.instanceId!);
        if (ctx) {
          if (platformCredentials) ctx.platformCredentials = platformCredentials;
          if (issueCtx) ctx.issueContext = issueCtx;
          await instanceManager.saveContext(result.instanceId!, ctx);
        }
      } catch (err) {
        console.error("[Server] Failed to save platform context:", err);
      }
    }

    const allCredentials = buildAllCredentials(config, db);
    const eventMeta = { isPullRequest: event.isPullRequest, diffContent: event.diffContent, repoMeta, platformCredentials, issueContext: issueCtx, allCredentials, spawnPort: config.port };
    executor.execute(result.instanceId!, isResume, callbacks, eventMeta).catch((err) => {
      console.error(`[Server] Execution error:`, err);
    });

    return c.json({
      status: result.action.toLowerCase(),
      instanceId: result.instanceId,
      reason: result.reason
    });
  });

  // OAuth callback endpoints
  app.get("/oauth/callback/:platform", async (c) => {
    const platform = c.req.param("platform") as "linear" | "github" | "notion";
    const adapter = adapters.get(platform);

    if (!adapter || !adapter.handleCallback) {
      return c.json({ error: `Platform ${platform} not configured for OAuth` }, 400);
    }

    const code = c.req.query("code");
    const state = c.req.query("state");
    const error = c.req.query("error");

    if (error) {
      return c.html(`
        <html>
          <body>
            <h1>OAuth Error</h1>
            <p>${error}</p>
            <p>You can close this window.</p>
          </body>
        </html>
      `);
    }

    if (!code) {
      return c.json({ error: "Missing code parameter" }, 400);
    }

    try {
      const redirectUri = `${config.publicUrl}/oauth/callback/${platform}`;
      const tokens = await adapter.handleCallback(code, redirectUri);

      // Save tokens to database
      db.saveOAuthToken({
        id: crypto.randomUUID(),
        provider: platform,
        user_id: "default",  // Single-user for now
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        platform_username: tokens.username,  // Store the authenticated user's username
        scope: ""
      });

      const usernameInfo = tokens.username ? ` as <strong>${tokens.username}</strong>` : "";
      return c.html(`
        <html>
          <body>
            <h1>Success!</h1>
            <p>${platform} has been connected${usernameInfo}.</p>
            <p>Only your issues/comments will trigger Claude instances.</p>
            <p>You can close this window and return to the terminal.</p>
          </body>
        </html>
      `);
    } catch (err) {
      console.error(`[Server] OAuth callback error:`, err);
      return c.html(`
        <html>
          <body>
            <h1>OAuth Error</h1>
            <p>${err instanceof Error ? err.message : "Unknown error"}</p>
            <p>Please try again.</p>
          </body>
        </html>
      `);
    }
  });

  // Setup initiation endpoints (for CLI to open in browser)
  app.get("/setup/:platform", (c) => {
    const platform = c.req.param("platform") as "linear" | "github" | "notion";
    const adapter = adapters.get(platform);

    if (!adapter || !adapter.getAuthUrl) {
      return c.json({ error: `Platform ${platform} not configured for OAuth` }, 400);
    }

    const state = crypto.randomUUID();
    const redirectUri = `${config.publicUrl}/oauth/callback/${platform}`;
    const authUrl = adapter.getAuthUrl(redirectUri, state);

    return c.redirect(authUrl);
  });

  // API endpoints for MCP tools
  app.get("/api/instances", (c) => {
    const projectId = c.req.query("project_id");
    if (projectId) {
      const instances = db.getProjectInstances(projectId);
      return c.json({ instances });
    }
    const instances = instanceManager.getAllInstances(50);
    return c.json({ instances });
  });

  app.get("/api/instances/:id", (c) => {
    const id = c.req.param("id");
    const instance = instanceManager.getInstance(id);

    if (!instance) {
      return c.json({ error: "Instance not found" }, 404);
    }

    const messages = instanceManager.getMessages(id);
    const children = db.getChildInstances(id);
    return c.json({ instance, messages, children });
  });

  app.post("/api/instances/:id/kill", (c) => {
    const id = c.req.param("id");
    const killed = executor.kill(id);
    return c.json({ success: killed });
  });

  // Spawn API — create and execute a new instance programmatically
  app.post("/api/spawn", async (c) => {
    try {
      const body = await c.req.json();
      const {
        prompt,
        platform,
        repo_url,
        branch,
        base_branch,
        parent_instance_id,
        project_id,
        working_dir
      } = body as {
        prompt: string;
        platform?: string;
        repo_url?: string;
        branch?: string;
        base_branch?: string;
        parent_instance_id?: string;
        project_id?: string;
        working_dir?: string;
      };

      if (!prompt) {
        return c.json({ error: "prompt is required" }, 400);
      }

      // Determine platform — inherit from parent if not specified
      let instancePlatform: Instance["platform"] = "github";
      if (platform) {
        instancePlatform = platform as Instance["platform"];
      } else if (parent_instance_id) {
        const parent = instanceManager.getInstance(parent_instance_id);
        if (parent) instancePlatform = parent.platform;
      }

      // Create a synthetic trigger context
      const threadId = `spawn-${crypto.randomUUID().slice(0, 8)}`;
      const triggerContext: import("./core/trigger-detector.js").TriggerContext = {
        threadId,
        platform: instancePlatform,
        content: `Dear Claude, ${prompt}`,
        isDescription: true,
        timestamp: Date.now()
      };

      const createResult = await instanceManager.processEvent(triggerContext);
      if (!createResult.instanceId) {
        return c.json({ error: "Failed to create instance" }, 500);
      }

      const instanceId = createResult.instanceId;

      // Set parent/project on the instance
      if (parent_instance_id || project_id) {
        const updates: string[] = [];
        const values: any[] = [];
        if (parent_instance_id) { updates.push("parent_instance_id = ?"); values.push(parent_instance_id); }
        if (project_id) { updates.push("project_id = ?"); values.push(project_id); }
        values.push(instanceId);
        db.getDatabase().prepare(`UPDATE instances SET ${updates.join(", ")} WHERE id = ?`).run(...values);
      }

      // Override working dir if specified
      if (working_dir) {
        db.getDatabase().prepare("UPDATE instances SET working_dir = ? WHERE id = ?").run(working_dir, instanceId);
      }

      // Build repo metadata if repo_url + branch provided
      let repoMeta: RepoMeta | undefined;
      if (repo_url && branch) {
        const repoName = repo_url.replace(/\.git$/, "").replace(/^https?:\/\/[^/]+\//, "");
        // Try to build auth clone URL using GitHub or GitLab adapter
        let authCloneUrl = repo_url;
        const githubAdapter = adapters.get("github");
        const gitlabAdapter = adapters.get("gitlab");
        if (repo_url.includes("github.com") && githubAdapter?.getAuthCloneUrl) {
          try { authCloneUrl = await githubAdapter.getAuthCloneUrl(repo_url); } catch {}
        } else if (repo_url.includes("gitlab.com") && gitlabAdapter?.getAuthCloneUrl) {
          try { authCloneUrl = await gitlabAdapter.getAuthCloneUrl(repo_url); } catch {}
        }
        repoMeta = {
          authCloneUrl,
          branch,
          baseBranch: base_branch || "main",
          prNumber: 0,
          repoName
        };
      }

      // Build all credentials and execute
      const allCredentials = buildAllCredentials(config, db);
      const eventMeta = { repoMeta, allCredentials, spawnPort: config.port };
      executor.execute(instanceId, false, undefined, eventMeta).catch((err) => {
        console.error(`[Server] Spawn execution error:`, err);
      });

      return c.json({ instance_id: instanceId, status: "pending" });
    } catch (err: any) {
      console.error("[Server] Spawn error:", err);
      return c.json({ error: err.message || "Spawn failed" }, 500);
    }
  });

  app.get("/api/platforms", (c) => {
    const platforms: Record<string, boolean> = {};
    for (const [name, adapter] of adapters) {
      platforms[name] = adapter.isConfigured();
    }
    return c.json({ platforms });
  });

  return app;
}
