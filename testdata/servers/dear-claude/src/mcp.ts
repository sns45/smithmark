/**
 * MCP Server
 * Exposes dear-claude functionality via Model Context Protocol
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool
} from "@modelcontextprotocol/sdk/types.js";
import type { InstanceManager } from "./core/instance-manager.js";
import type { ClaudeExecutor, AllPlatformCredentials } from "./core/claude-executor.js";

export interface MCPServerOptions {
  instanceManager: InstanceManager;
  executor: ClaudeExecutor;
  httpPort?: number;
  enableHttp?: boolean;
  enableTunnel?: boolean;
  db?: import("./db/schema.js").DatabaseManager;
  config?: import("./server.js").ServerConfig;
}

export function createMCPServer(
  instanceManager: InstanceManager,
  executor: ClaudeExecutor,
  config?: import("./server.js").ServerConfig,
  options?: Partial<MCPServerOptions>
): Server {
  const server = new Server(
    {
      name: "dear-claude",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Define tools
  const tools: Tool[] = [
    {
      name: "list_platforms",
      description: "List configured platforms and their status",
      inputSchema: {
        type: "object",
        properties: {},
        required: []
      }
    },
    {
      name: "list_instances",
      description: "List all Claude instances (active and recent)",
      inputSchema: {
        type: "object",
        properties: {
          status: {
            type: "string",
            enum: ["all", "active", "completed", "failed"],
            description: "Filter by status",
            default: "all"
          },
          limit: {
            type: "number",
            description: "Maximum number of instances to return",
            default: 20
          }
        },
        required: []
      }
    },
    {
      name: "get_instance_status",
      description: "Get detailed status of a specific instance",
      inputSchema: {
        type: "object",
        properties: {
          instance_id: {
            type: "string",
            description: "The instance ID"
          }
        },
        required: ["instance_id"]
      }
    },
    {
      name: "get_instance_messages",
      description: "Get conversation history for an instance",
      inputSchema: {
        type: "object",
        properties: {
          instance_id: {
            type: "string",
            description: "The instance ID"
          }
        },
        required: ["instance_id"]
      }
    },
    {
      name: "kill_instance",
      description: "Terminate a running instance",
      inputSchema: {
        type: "object",
        properties: {
          instance_id: {
            type: "string",
            description: "The instance ID to kill"
          }
        },
        required: ["instance_id"]
      }
    },
    {
      name: "get_running_instances",
      description: "Get list of currently running instance IDs",
      inputSchema: {
        type: "object",
        properties: {},
        required: []
      }
    },
    {
      name: "spawn_instance",
      description: "Spawn a new Claude instance to handle a task. Use for parallel coding, cross-platform orchestration, etc.",
      inputSchema: {
        type: "object",
        properties: {
          prompt: {
            type: "string",
            description: "What Claude should do"
          },
          platform: {
            type: "string",
            description: "Target platform (default: github)",
            enum: ["linear", "github", "gitlab", "jira", "notion", "obsidian"]
          },
          repo_url: {
            type: "string",
            description: "Git repo URL to work on (e.g. https://github.com/owner/repo)"
          },
          branch: {
            type: "string",
            description: "Branch name for this task"
          },
          base_branch: {
            type: "string",
            description: "Base branch (default: main)"
          },
          parent_instance_id: {
            type: "string",
            description: "Parent instance that spawned this one"
          },
          project_id: {
            type: "string",
            description: "Group related instances together"
          },
          working_dir: {
            type: "string",
            description: "Override working directory"
          }
        },
        required: ["prompt"]
      }
    },
    {
      name: "get_project_instances",
      description: "List all instances belonging to a project",
      inputSchema: {
        type: "object",
        properties: {
          project_id: {
            type: "string",
            description: "The project ID to query"
          }
        },
        required: ["project_id"]
      }
    }
  ];

  // Handle list tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "list_platforms": {
        const platforms: Record<string, boolean> = {
          linear: !!(config?.linear?.clientId || config?.linear?.accessToken),
          github: !!(config?.github?.clientId || config?.github?.accessToken),
          gitlab: !!(config?.gitlab?.accessToken),
          jira: !!(config?.jira?.domain && config?.jira?.apiToken),
          notion: !!(config?.notion?.clientId || config?.notion?.accessToken),
          obsidian: !!(config?.obsidian?.vaultPath)
        };
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                platforms,
                note: "Run 'dear-claude status' for detailed platform status"
              }, null, 2)
            }
          ]
        };
      }

      case "list_instances": {
        const status = (args?.status as string) || "all";
        const limit = (args?.limit as number) || 20;

        let instances = instanceManager.getAllInstances(limit);

        if (status === "active") {
          instances = instances.filter(i => ["pending", "running", "idle"].includes(i.status));
        } else if (status !== "all") {
          instances = instances.filter(i => i.status === status);
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                count: instances.length,
                instances: instances.map(i => ({
                  id: i.id,
                  platform: i.platform,
                  thread_id: i.thread_id,
                  status: i.status,
                  claude_session_id: i.claude_session_id || null,
                  original_prompt: i.original_prompt.slice(0, 100) + (i.original_prompt.length > 100 ? "..." : ""),
                  created_at: new Date(i.created_at).toISOString(),
                  updated_at: new Date(i.updated_at).toISOString()
                }))
              }, null, 2)
            }
          ]
        };
      }

      case "get_instance_status": {
        const instanceId = args?.instance_id as string;
        if (!instanceId) {
          return {
            content: [{ type: "text", text: "Error: instance_id is required" }],
            isError: true
          };
        }

        const instance = instanceManager.getInstance(instanceId);
        if (!instance) {
          return {
            content: [{ type: "text", text: `Error: Instance ${instanceId} not found` }],
            isError: true
          };
        }

        const isRunning = executor.isRunning(instanceId);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id: instance.id,
                platform: instance.platform,
                thread_id: instance.thread_id,
                status: instance.status,
                is_currently_running: isRunning,
                working_dir: instance.working_dir,
                original_prompt: instance.original_prompt,
                completion_summary: instance.completion_summary,
                claude_session_id: instance.claude_session_id || null,
                resume_command: instance.claude_session_id ? `claude --resume ${instance.claude_session_id}` : null,
                created_at: new Date(instance.created_at).toISOString(),
                updated_at: new Date(instance.updated_at).toISOString(),
                expires_at: new Date(instance.expires_at).toISOString()
              }, null, 2)
            }
          ]
        };
      }

      case "get_instance_messages": {
        const instanceId = args?.instance_id as string;
        if (!instanceId) {
          return {
            content: [{ type: "text", text: "Error: instance_id is required" }],
            isError: true
          };
        }

        const messages = instanceManager.getMessages(instanceId);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                instance_id: instanceId,
                message_count: messages.length,
                messages: messages.map(m => ({
                  role: m.role,
                  content: m.content.slice(0, 500) + (m.content.length > 500 ? "..." : ""),
                  created_at: new Date(m.created_at).toISOString()
                }))
              }, null, 2)
            }
          ]
        };
      }

      case "kill_instance": {
        const instanceId = args?.instance_id as string;
        if (!instanceId) {
          return {
            content: [{ type: "text", text: "Error: instance_id is required" }],
            isError: true
          };
        }

        const killed = executor.kill(instanceId);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                instance_id: instanceId,
                killed,
                message: killed ? "Instance terminated" : "Instance was not running"
              }, null, 2)
            }
          ]
        };
      }

      case "get_running_instances": {
        const running = executor.getRunningInstances();

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                count: running.length,
                instance_ids: running
              }, null, 2)
            }
          ]
        };
      }

      case "spawn_instance": {
        const prompt = args?.prompt as string;
        if (!prompt) {
          return {
            content: [{ type: "text", text: "Error: prompt is required" }],
            isError: true
          };
        }

        try {
          const platform = (args?.platform as string) || "github";
          const threadId = `spawn-${crypto.randomUUID().slice(0, 8)}`;
          const { TriggerDetector } = await import("./core/trigger-detector.js");

          const triggerContext = {
            threadId,
            platform: platform as any,
            content: `Dear Claude, ${prompt}`,
            isDescription: true,
            timestamp: Date.now()
          };

          const createResult = await instanceManager.processEvent(triggerContext);
          if (!createResult.instanceId) {
            return {
              content: [{ type: "text", text: "Error: Failed to create instance" }],
              isError: true
            };
          }

          const instanceId = createResult.instanceId;

          // Set parent/project fields
          if (options?.db) {
            const db = options.db;
            const updates: string[] = [];
            const values: any[] = [];
            if (args?.parent_instance_id) { updates.push("parent_instance_id = ?"); values.push(args.parent_instance_id); }
            if (args?.project_id) { updates.push("project_id = ?"); values.push(args.project_id); }
            if (args?.working_dir) { updates.push("working_dir = ?"); values.push(args.working_dir); }
            if (updates.length > 0) {
              values.push(instanceId);
              db.getDatabase().prepare(`UPDATE instances SET ${updates.join(", ")} WHERE id = ?`).run(...values);
            }
          }

          // Build credentials and execute
          let allCredentials: AllPlatformCredentials | undefined;
          if (options?.db && options?.config) {
            const { buildAllCredentials } = await import("./server.js");
            allCredentials = buildAllCredentials(options.config, options.db);
          }

          const repoUrl = args?.repo_url as string | undefined;
          const branch = args?.branch as string | undefined;
          let repoMeta: import("./core/instance-manager.js").RepoMeta | undefined;
          if (repoUrl && branch) {
            const repoName = repoUrl.replace(/\.git$/, "").replace(/^https?:\/\/[^/]+\//, "");
            repoMeta = {
              authCloneUrl: repoUrl,
              branch,
              baseBranch: (args?.base_branch as string) || "main",
              prNumber: 0,
              repoName
            };
          }

          const httpPort = options?.httpPort || 3334;
          const eventMeta = { repoMeta, allCredentials, spawnPort: httpPort };
          executor.execute(instanceId, false, undefined, eventMeta).catch((err) => {
            console.error("[MCP] Spawn execution error:", err);
          });

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  instance_id: instanceId,
                  status: "pending",
                  message: "Instance spawned and executing"
                }, null, 2)
              }
            ]
          };
        } catch (err: any) {
          return {
            content: [{ type: "text", text: `Error: ${err.message}` }],
            isError: true
          };
        }
      }

      case "get_project_instances": {
        const projectId = args?.project_id as string;
        if (!projectId) {
          return {
            content: [{ type: "text", text: "Error: project_id is required" }],
            isError: true
          };
        }

        if (!options?.db) {
          return {
            content: [{ type: "text", text: "Error: Database not available" }],
            isError: true
          };
        }

        const instances = options.db.getProjectInstances(projectId);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                project_id: projectId,
                count: instances.length,
                instances: instances.map(i => ({
                  id: i.id,
                  platform: i.platform,
                  status: i.status,
                  parent_instance_id: i.parent_instance_id || null,
                  original_prompt: i.original_prompt.slice(0, 100) + (i.original_prompt.length > 100 ? "..." : ""),
                  created_at: new Date(i.created_at).toISOString(),
                  updated_at: new Date(i.updated_at).toISOString()
                }))
              }, null, 2)
            }
          ]
        };
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true
        };
    }
  });

  return server;
}

export async function startMCPServer(
  instanceManager: InstanceManager,
  executor: ClaudeExecutor,
  options?: Partial<MCPServerOptions>
): Promise<void> {
  const server = createMCPServer(instanceManager, executor, options?.config, options);
  const transport = new StdioServerTransport();

  // Start HTTP server for webhooks if enabled
  if (options?.enableHttp && options.db && options.config) {
    const { serve } = await import("bun");
    const { createServer } = await import("./server.js");

    const httpPort = options.httpPort || 3334;
    let publicUrl: string | undefined;

    // Start Tailscale Funnel if enabled
    if (options.enableTunnel !== false) {
      const { TransportManager } = await import("./transport/transport.js");
      const transportManager = new TransportManager({
        port: httpPort
      });

      try {
        publicUrl = await transportManager.start();
        // Update config with public URL for OAuth callbacks
        if (options.config) {
          options.config.publicUrl = publicUrl;
        }
        console.error(`[MCP] Tailscale Funnel: ${publicUrl}`);
      } catch (err) {
        console.error(`[MCP] Tailscale Funnel failed: ${err instanceof Error ? err.message : err}`);
        console.error(`[MCP] Continuing without public URL (webhooks won't work externally)`);
      }
    }

    const app = createServer(options.config, options.db, instanceManager, executor);

    serve({
      fetch: app.fetch,
      port: httpPort
    });

    console.error(`[MCP] HTTP webhook server started on port ${httpPort}`);
    if (publicUrl) {
      console.error(`[MCP] Webhook URLs (public):`);
      console.error(`   GitHub:  ${publicUrl}/webhook/github`);
      console.error(`   Linear:  ${publicUrl}/webhook/linear`);
      console.error(`[MCP] OAuth Setup:`);
      console.error(`   GitHub:  ${publicUrl}/setup/github`);
    } else {
      console.error(`[MCP] Webhook URLs (local only):`);
      console.error(`   GitHub:  http://localhost:${httpPort}/webhook/github`);
      console.error(`   Linear:  http://localhost:${httpPort}/webhook/linear`);
    }
  }

  // Start Obsidian vault watcher if configured
  if (options?.config?.obsidian?.vaultPath && options.db) {
    const { ObsidianVaultWatcher } = await import("./adapters/obsidian-watcher.js");
    const { TriggerDetector } = await import("./core/trigger-detector.js");
    const { ObsidianAdapter } = await import("./adapters/obsidian-adapter.js");
    const { sanitize } = await import("./utils/sanitize.js");
    const vaultPath = options.config.obsidian.vaultPath;
    const db = options.db;

    const obsidianWatcher = new ObsidianVaultWatcher({
      vaultPath,
      debounceMs: parseInt(process.env.OBSIDIAN_WATCH_DEBOUNCE_MS || "2000", 10)
    });

    obsidianWatcher.start(instanceManager, async (event) => {
      if (!TriggerDetector.containsTrigger(event.content)) return;

      const triggerContext = {
        threadId: event.threadId,
        platform: event.platform as "obsidian",
        content: event.content,
        isDescription: event.isDescription,
        messageId: event.messageId,
        authorId: event.authorId,
        timestamp: Date.now()
      };

      const result = await instanceManager.processEvent(triggerContext);
      console.error(`[Obsidian] Trigger result for ${event.threadId}: ${result.action} - ${result.reason}`);

      if (result.action === "IGNORE") return;

      const instance = instanceManager.getInstance(result.instanceId!);
      if (!instance) return;

      // Override working dir to vault path
      db.getDatabase().prepare("UPDATE instances SET working_dir = ? WHERE id = ?")
        .run(vaultPath, result.instanceId!);

      const adapter = new ObsidianAdapter(vaultPath, obsidianWatcher);
      adapter.setInstanceId(result.instanceId!);

      const callbacks = {
        onStart: async (_id: string, _msg: string) => {
          try {
            await adapter.setStatus(event.threadId, "processing");
          } catch (err) {
            console.error("[Obsidian] Failed to set processing status:", err);
          }
        },
        onComplete: async (id: string, summary: string) => {
          try {
            // Fetch latest instance to get claude_session_id
            const latest = instanceManager.getInstance(id);
            if (latest?.claude_session_id) adapter.setSessionId(latest.claude_session_id);
            const safeSummary = sanitize(summary);
            await adapter.postResponse(event.threadId, safeSummary);
            await adapter.setStatus(event.threadId, "done");
          } catch (err) {
            console.error("[Obsidian] Failed to post response:", err);
          }
        },
        onError: async (id: string, error: string) => {
          try {
            const latest = instanceManager.getInstance(id);
            if (latest?.claude_session_id) adapter.setSessionId(latest.claude_session_id);
            const safeError = sanitize(error);
            await adapter.postResponse(event.threadId, `**Error**\n${safeError}`);
            await adapter.setStatus(event.threadId, "error");
          } catch (err) {
            console.error("[Obsidian] Failed to post error:", err);
          }
        }
      };

      const isResume = result.action === "RESUME";

      // Build allCredentials so Obsidian instances can access all platform APIs
      let allCredentials: AllPlatformCredentials | undefined;
      if (options?.config) {
        const { buildAllCredentials } = await import("./server.js");
        allCredentials = buildAllCredentials(options.config, db);
      }
      const httpPort = options?.httpPort || 3334;
      const eventMeta = { allCredentials, spawnPort: httpPort };

      executor.execute(result.instanceId!, isResume, callbacks, eventMeta).catch((err) => {
        console.error("[Obsidian] Execution error:", err);
      });
    });

    console.error(`[MCP] Obsidian watcher started: ${vaultPath}`);
  }

  await server.connect(transport);
  console.error("[MCP] Server started on stdio");
}
