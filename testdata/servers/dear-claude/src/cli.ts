/**
 * CLI Commands
 * Command-line interface for dear-claude
 */

import { Command } from "commander";
import { serve } from "bun";
import { DatabaseManager } from "./db/schema.js";
import { InstanceManager } from "./core/instance-manager.js";
import { ClaudeExecutor } from "./core/claude-executor.js";
import { TransportManager } from "./transport/transport.js";
import { createServer, type ServerConfig } from "./server.js";
import { startMCPServer } from "./mcp.js";
import { ObsidianVaultWatcher } from "./adapters/obsidian-watcher.js";

function getConfig(): ServerConfig {
  return {
    port: parseInt(process.env.DEAR_CLAUDE_PORT || "3334", 10),
    linear: {
      clientId: process.env.LINEAR_CLIENT_ID,
      clientSecret: process.env.LINEAR_CLIENT_SECRET,
      webhookSecret: process.env.LINEAR_WEBHOOK_SECRET,
      accessToken: process.env.LINEAR_ACCESS_TOKEN
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      webhookSecret: process.env.GITHUB_WEBHOOK_SECRET,
      accessToken: process.env.GITHUB_ACCESS_TOKEN
    },
    gitlab: {
      accessToken: process.env.GITLAB_ACCESS_TOKEN,
      webhookSecret: process.env.GITLAB_WEBHOOK_SECRET
    },
    jira: {
      domain: process.env.JIRA_DOMAIN,
      userEmail: process.env.JIRA_USER_EMAIL,
      apiToken: process.env.JIRA_API_TOKEN,
      webhookSecret: process.env.JIRA_WEBHOOK_SECRET
    },
    notion: {
      clientId: process.env.NOTION_CLIENT_ID,
      clientSecret: process.env.NOTION_CLIENT_SECRET,
      webhookSecret: process.env.NOTION_WEBHOOK_SECRET,
      accessToken: process.env.NOTION_ACCESS_TOKEN
    },
    obsidian: {
      vaultPath: process.env.OBSIDIAN_VAULT_PATH
    }
  };
}

export function createCLI(): Command {
  const program = new Command();

  program
    .name("dear-claude")
    .description("Trigger local Claude Code instances from external platforms")
    .version("1.0.0");

  // Start command
  program
    .command("start")
    .description("Start the dear-claude server")
    .option("-p, --port <port>", "Port to listen on", "3334")
    .option("--no-tunnel", "Disable Tailscale Funnel")
    .option("--mcp", "Run as MCP server (stdio mode)")
    .action(async (options) => {
      const config = getConfig();
      config.port = parseInt(options.port, 10);

      // Initialize components
      const db = new DatabaseManager();
      const instanceManager = new InstanceManager(db);
      const executor = new ClaudeExecutor(instanceManager);

      // Cleanup expired instances periodically
      setInterval(() => instanceManager.cleanupExpired(), 60 * 60 * 1000);

      if (options.mcp) {
        // Run as MCP server with HTTP webhook support
        await startMCPServer(instanceManager, executor, {
          instanceManager,
          executor,
          enableHttp: true,
          httpPort: config.port,
          enableTunnel: options.tunnel !== false,
          db,
          config
        });
        return;
      }

      // Start transport (Tailscale Funnel)
      let transport: TransportManager | undefined;
      if (options.tunnel !== false) {
        transport = new TransportManager({
          port: config.port
        });

        try {
          config.publicUrl = await transport.start();
          console.log(`\n🌐 Public URL: ${config.publicUrl}`);
        } catch (err) {
          console.error("Failed to start Tailscale Funnel:", err);
          console.log("Running without tunnel (webhooks will not work externally)");
        }
      }

      // Start Obsidian vault watcher if configured
      let obsidianWatcher: ObsidianVaultWatcher | undefined;
      if (config.obsidian?.vaultPath) {
        obsidianWatcher = new ObsidianVaultWatcher({
          vaultPath: config.obsidian.vaultPath,
          debounceMs: parseInt(process.env.OBSIDIAN_WATCH_DEBOUNCE_MS || "2000", 10)
        });
      }

      // Create Hono app
      const app = createServer(config, db, instanceManager, executor, obsidianWatcher);

      // Start Obsidian watcher after server is created (needs the processEvent pipeline)
      if (obsidianWatcher) {
        obsidianWatcher.start(instanceManager, async (event) => {
          // Check for trigger (already checked in watcher, but belt-and-suspenders)
          const { TriggerDetector } = await import("./core/trigger-detector.js");
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
          console.log(`[Obsidian] Trigger result for ${event.threadId}: ${result.action} - ${result.reason}`);

          if (result.action === "IGNORE") return;

          // For Obsidian, override working dir to be the vault path
          const instance = instanceManager.getInstance(result.instanceId!);
          if (instance && config.obsidian?.vaultPath) {
            // Update the instance working dir to be the vault
            db.getDatabase().prepare("UPDATE instances SET working_dir = ? WHERE id = ?")
              .run(config.obsidian.vaultPath, result.instanceId!);
          }

          // Import adapter for callbacks
          const { ObsidianAdapter } = await import("./adapters/obsidian-adapter.js");
          const adapter = new ObsidianAdapter(config.obsidian!.vaultPath!, obsidianWatcher);
          adapter.setInstanceId(result.instanceId!);
          const { sanitize } = await import("./utils/sanitize.js");

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
          executor.execute(result.instanceId!, isResume, callbacks).catch((err) => {
            console.error("[Obsidian] Execution error:", err);
          });
        });
      }

      // Start server
      const server = serve({
        fetch: app.fetch,
        port: config.port
      });

      console.log(`\n🚀 dear-claude server running on port ${config.port}`);

      if (config.publicUrl) {
        console.log(`\n📍 Webhook URLs:`);
        console.log(`   Linear:  ${config.publicUrl}/webhook/linear`);
        console.log(`   GitHub:  ${config.publicUrl}/webhook/github`);
        console.log(`   GitLab:  ${config.publicUrl}/webhook/gitlab`);
        console.log(`   Jira:    ${config.publicUrl}/webhook/jira`);
        console.log(`   Notion:  ${config.publicUrl}/webhook/notion`);
        console.log(`\n🔐 OAuth Setup:`);
        console.log(`   Linear:  ${config.publicUrl}/setup/linear`);
        console.log(`   GitHub:  ${config.publicUrl}/setup/github`);
        console.log(`   Notion:  ${config.publicUrl}/setup/notion`);
      }

      if (obsidianWatcher) {
        console.log(`\n📓 Obsidian vault: ${config.obsidian!.vaultPath}`);
      }

      console.log(`\n✅ Health check: http://localhost:${config.port}/health`);

      // Handle shutdown
      const shutdown = async () => {
        console.log("\n\nShutting down...");
        if (obsidianWatcher) obsidianWatcher.stop();
        await executor.cleanup();
        if (transport) await transport.stop();
        db.close();
        process.exit(0);
      };

      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
    });

  // Status command
  program
    .command("status")
    .description("Check server and platform status")
    .action(async () => {
      const config = getConfig();

      console.log("\n📊 dear-claude Status\n");

      // Check platforms
      console.log("Platforms:");
      console.log(`  Linear:  ${config.linear?.accessToken ? "✅ Connected" : config.linear?.clientId ? "⚠️  OAuth configured" : "❌ Not configured"}`);
      console.log(`  GitHub:  ${config.github?.accessToken ? "✅ Connected" : config.github?.clientId ? "⚠️  OAuth configured" : "❌ Not configured"}`);
      console.log(`  GitLab:  ${config.gitlab?.accessToken ? "✅ Connected" : "❌ Not configured"}`);
      console.log(`  Jira:    ${config.jira?.apiToken ? "✅ Connected" : config.jira?.domain ? "⚠️  Domain configured" : "❌ Not configured"}`);
      console.log(`  Notion:  ${config.notion?.accessToken ? "✅ Connected" : config.notion?.clientId ? "⚠️  OAuth configured" : "❌ Not configured"}`);
      console.log(`  Obsidian: ${config.obsidian?.vaultPath ? `✅ Vault: ${config.obsidian.vaultPath}` : "❌ Not configured"}`);

      // Check database
      try {
        const db = new DatabaseManager();
        const instanceManager = new InstanceManager(db);
        const instances = instanceManager.getAllInstances(100);
        const active = instances.filter(i => ["pending", "running", "idle"].includes(i.status));

        console.log(`\nInstances:`);
        console.log(`  Total:   ${instances.length}`);
        console.log(`  Active:  ${active.length}`);

        if (active.length > 0) {
          console.log(`\nActive instances:`);
          for (const instance of active.slice(0, 5)) {
            console.log(`  • ${instance.id.slice(0, 8)} [${instance.platform}] ${instance.status} - "${instance.original_prompt.slice(0, 40)}..."`);
          }
        }

        db.close();
      } catch (err) {
        console.log(`\nDatabase: ❌ Error - ${err}`);
      }
    });

  // Instances command
  program
    .command("instances")
    .description("List instances")
    .option("-s, --status <status>", "Filter by status (pending, running, completed, failed, idle)")
    .option("-n, --limit <n>", "Limit number of results", "20")
    .action(async (options) => {
      const db = new DatabaseManager();
      const instanceManager = new InstanceManager(db);

      let instances = instanceManager.getAllInstances(parseInt(options.limit, 10));

      if (options.status) {
        instances = instances.filter(i => i.status === options.status);
      }

      console.log(`\n📋 Instances (${instances.length})\n`);

      if (instances.length === 0) {
        console.log("No instances found.");
      } else {
        for (const instance of instances) {
          const date = new Date(instance.updated_at).toLocaleString();
          console.log(`${instance.id.slice(0, 8)}  [${instance.platform.padEnd(6)}]  ${instance.status.padEnd(9)}  ${date}`);
          console.log(`          "${instance.original_prompt.slice(0, 60)}${instance.original_prompt.length > 60 ? "..." : ""}"`);
          console.log();
        }
      }

      db.close();
    });

  // Logs command
  program
    .command("logs <instance-id>")
    .description("View instance conversation logs")
    .action(async (instanceId) => {
      const db = new DatabaseManager();
      const instanceManager = new InstanceManager(db);

      // Try to find by full ID or prefix
      let instance = instanceManager.getInstance(instanceId);

      if (!instance) {
        // Try prefix match
        const all = instanceManager.getAllInstances(1000);
        instance = all.find(i => i.id.startsWith(instanceId));
      }

      if (!instance) {
        console.error(`Instance not found: ${instanceId}`);
        process.exit(1);
      }

      const messages = instanceManager.getMessages(instance.id);

      console.log(`\n📝 Logs for ${instance.id}\n`);
      console.log(`Platform: ${instance.platform}`);
      console.log(`Status:   ${instance.status}`);
      console.log(`Created:  ${new Date(instance.created_at).toLocaleString()}`);
      console.log(`Updated:  ${new Date(instance.updated_at).toLocaleString()}`);
      console.log(`\n--- Messages (${messages.length}) ---\n`);

      for (const msg of messages) {
        const date = new Date(msg.created_at).toLocaleString();
        console.log(`[${msg.role.toUpperCase()}] ${date}`);
        console.log(msg.content);
        console.log();
      }

      db.close();
    });

  // Setup command
  program
    .command("setup <platform>")
    .description("Configure a platform (linear, github, jira, notion, obsidian)")
    .action(async (platform) => {
      const validPlatforms = ["linear", "github", "jira", "notion", "obsidian"];
      if (!validPlatforms.includes(platform)) {
        console.error(`Invalid platform: ${platform}`);
        console.log(`Valid platforms: ${validPlatforms.join(", ")}`);
        process.exit(1);
      }

      const config = getConfig();

      console.log(`\n🔧 Setting up ${platform}...\n`);

      if (platform === "jira") {
        console.log("Jira uses API token auth (no OAuth flow needed).\n");
        console.log("Set the following environment variables:\n");
        console.log("  JIRA_DOMAIN=mycompany           # → mycompany.atlassian.net");
        console.log("  JIRA_USER_EMAIL=user@example.com");
        console.log("  JIRA_API_TOKEN=...               # From id.atlassian.com/manage-profile/security/api-tokens");
        console.log("  JIRA_WEBHOOK_SECRET=...           # Optional shared secret for webhook validation");
        console.log("\nThen configure a webhook in Jira Admin → System → Webhooks:");
        console.log(`  URL: <your-public-url>/webhook/jira${config.jira?.webhookSecret ? `?secret=${config.jira.webhookSecret}` : ""}`);
        console.log("  Events: issue_created, issue_updated, comment_created");
        console.log("\nOnce configured, run 'dear-claude start' and Jira will be active.");
        return;
      }

      if (platform === "notion") {
        console.log("Notion supports OAuth or internal integration tokens.\n");
        console.log("Option A: Internal Integration (simpler)");
        console.log("  1. Go to https://www.notion.so/my-integrations → New integration");
        console.log("  2. Copy the Internal Integration Secret → set NOTION_ACCESS_TOKEN");
        console.log("  3. Share pages/databases with the integration\n");
        console.log("Option B: OAuth (public integration)");
        console.log("  Set: NOTION_CLIENT_ID, NOTION_CLIENT_SECRET");
        console.log("  Visit: <your-public-url>/setup/notion\n");
        console.log("For webhooks:");
        console.log("  Set: NOTION_WEBHOOK_SECRET");
        console.log(`  URL: <your-public-url>/webhook/notion`);
        console.log("  Events: comment.created, page.content_updated");
        return;
      }

      if (platform === "obsidian") {
        console.log("Obsidian uses direct file watching (no API needed).\n");
        console.log("Set the following environment variable:\n");
        console.log("  OBSIDIAN_VAULT_PATH=/absolute/path/to/your/vault");
        console.log("");
        console.log("Optional:");
        console.log("  OBSIDIAN_WATCH_DEBOUNCE_MS=2000  # Debounce delay (default 2s)");
        console.log("\nHow it works:");
        console.log("  1. Create or edit any .md file in your vault");
        console.log("  2. Include 'Dear Claude' anywhere in the note");
        console.log("  3. Claude reads the note, processes the request");
        console.log("  4. Response is appended as a > [!claude] callout block");
        console.log("  5. Claude gets full vault access — can read any note or image");
        console.log("\nOnce configured, run 'dear-claude start' and Obsidian watcher will be active.");
        return;
      }

      console.log("This will start a temporary server for OAuth authentication.");
      console.log("Make sure you have configured the following environment variables:\n");

      if (platform === "linear") {
        console.log("  LINEAR_CLIENT_ID");
        console.log("  LINEAR_CLIENT_SECRET");
        console.log("\n(Get these from Linear Settings → API → OAuth Applications)");
      } else if (platform === "github") {
        console.log("  GITHUB_CLIENT_ID");
        console.log("  GITHUB_CLIENT_SECRET");
        console.log("\n(Get these from GitHub Settings → Developer settings → OAuth Apps)");
      }

      console.log("\nOnce configured, run 'dear-claude start' and visit:");
      console.log(`  http://localhost:${config.port}/setup/${platform}`);
      console.log("\nOr use the Tailscale Funnel URL if running with a tunnel.");
    });

  return program;
}
