/**
 * Claude Executor
 * Runs Claude Code sessions using the Agent SDK
 */

import { query, type SDKMessage } from "@anthropic-ai/claude-agent-sdk";
import { readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { InstanceManager, RepoMeta } from "./instance-manager.js";
import type { Instance } from "../db/schema.js";

export interface PlatformCredentials {
  type: "linear" | "jira" | "github" | "gitlab" | "notion";
  token?: string;        // Linear access token, GitHub token, or Notion token
  basicAuth?: string;    // Jira base64-encoded email:token
  baseUrl?: string;      // Jira base URL
  teamId?: string;       // Linear team ID
  projectKey?: string;   // Jira project key or Linear team key
}

export interface AllPlatformCredentials {
  linear?: { token: string; teamId?: string };
  jira?: { basicAuth: string; baseUrl: string; projectKey?: string };
  notion?: { token: string };
  github?: { token: string; apiUrl?: string };
  gitlab?: { token: string; apiUrl?: string };
}

export interface IssueContext {
  title?: string;
  issueUrl?: string;
  parentIssueId?: string;
  projectKey?: string;
}

export interface ExecutionResult {
  instanceId: string;
  success: boolean;
  output: string;
  summary?: string;
}

export interface PlatformCallbacks {
  onStart?: (instanceId: string, message: string) => Promise<void>;
  onProgress?: (instanceId: string, message: string) => Promise<void>;
  onComplete?: (instanceId: string, summary: string) => Promise<void>;
  onError?: (instanceId: string, error: string) => Promise<void>;
}

interface ActiveExecution {
  abortController: AbortController;
  output: string[];
  startedAt: Date;
}

export class ClaudeExecutor {
  private instanceManager: InstanceManager;
  private activeExecutions: Map<string, ActiveExecution> = new Map();

  constructor(instanceManager: InstanceManager) {
    this.instanceManager = instanceManager;
  }

  /**
   * Execute a task using the Claude Agent SDK
   */
  async execute(
    instanceId: string,
    isResume: boolean = false,
    callbacks?: PlatformCallbacks,
    eventMeta?: {
      isPullRequest?: boolean;
      diffContent?: string;
      repoMeta?: RepoMeta;
      platformCredentials?: PlatformCredentials;
      issueContext?: IssueContext;
      allCredentials?: AllPlatformCredentials;
      spawnPort?: number;
    }
  ): Promise<void> {
    const instance = this.instanceManager.getInstance(instanceId);
    if (!instance) {
      throw new Error(`Instance ${instanceId} not found`);
    }

    // Check if already running
    if (this.activeExecutions.has(instanceId)) {
      console.log(`[ClaudeExecutor] Instance ${instanceId} is already running`);
      return;
    }

    // Get the latest user message as the request
    const messages = this.instanceManager.getMessages(instanceId);
    const latestUserMessage = [...messages].reverse().find(m => m.role === "user");

    if (!latestUserMessage) {
      throw new Error(`No user message found for instance ${instanceId}`);
    }

    // Build prompt
    let prompt: string;
    if (isResume) {
      prompt = await this.instanceManager.buildResumePrompt(instanceId, latestUserMessage.content, eventMeta?.allCredentials);
    } else {
      prompt = this.buildNewPrompt(instance, latestUserMessage.content, eventMeta?.isPullRequest, eventMeta?.diffContent, eventMeta?.repoMeta, eventMeta?.platformCredentials, eventMeta?.issueContext, eventMeta?.allCredentials, eventMeta?.spawnPort);
    }

    // Update status to running
    this.instanceManager.updateStatus(instanceId, "running");

    // Notify platform that we're starting
    if (callbacks?.onStart) {
      const resumeHint = instance.claude_session_id
        ? `\nResume in terminal: \`claude --resume ${instance.claude_session_id}\``
        : "";
      const message = isResume
        ? `**Resuming Previous Session** (Instance: \`${instanceId}\`)\nOriginal request: "${instance.original_prompt.slice(0, 100)}..."${resumeHint}\nContinuing from where we left off...`
        : `**Claude Instance Started** (Instance: \`${instanceId}\`)\nProcessing your request...`;
      await callbacks.onStart(instanceId, message);
    }

    console.log(`[ClaudeExecutor] Starting ${isResume ? "resumed" : "new"} execution for ${instanceId}`);
    console.log(`[ClaudeExecutor] Working directory: ${instance.working_dir}`);

    const abortController = new AbortController();
    const execution: ActiveExecution = {
      abortController,
      output: [],
      startedAt: new Date()
    };
    this.activeExecutions.set(instanceId, execution);

    // Run in background so execute() returns immediately
    this.runQuery(instanceId, instance, prompt, execution, callbacks, isResume).catch((err) => {
      console.error(`[ClaudeExecutor] Unhandled error for ${instanceId}:`, err);
    });
  }

  private async runQuery(
    instanceId: string,
    instance: Instance,
    prompt: string,
    execution: ActiveExecution,
    callbacks?: PlatformCallbacks,
    isResume: boolean = false
  ): Promise<void> {
    try {
      const mcpServers = this.getMcpServers();
      console.log(`[ClaudeExecutor] MCP servers for ${instanceId.slice(0, 8)}:`, Object.keys(mcpServers));

      // If resuming and we have a stored session ID, use SDK's native resume
      const canNativeResume = isResume && instance.claude_session_id;
      if (canNativeResume) {
        console.log(`[ClaudeExecutor] Native resume with session ${instance.claude_session_id}`);
      }

      const queryOptions: any = {
        abortController: execution.abortController,
        cwd: instance.working_dir,
        permissionMode: "bypassPermissions",
        allowDangerouslySkipPermissions: true,
        systemPrompt: {
          type: "preset",
          preset: "claude_code",
          append: `You are working on behalf of a user who contacted you via ${instance.platform}. Complete their request thoroughly.`
        },
        tools: { type: "preset", preset: "claude_code" },
        mcpServers,
        maxTurns: 50,
        stderr: (data: string) => {
          console.error(`[Claude:${instanceId.slice(0, 8)}:stderr] ${data.trim()}`);
        },
      };

      if (canNativeResume) {
        queryOptions.resume = instance.claude_session_id;
      }

      const conversation = query({
        prompt,
        options: queryOptions,
      });

      // Check MCP server status
      try {
        const mcpStatus = await conversation.mcpServerStatus();
        console.log(`[ClaudeExecutor] MCP status for ${instanceId.slice(0, 8)}:`, JSON.stringify(mcpStatus));
      } catch (e: any) {
        console.warn(`[ClaudeExecutor] Could not get MCP status: ${e.message}`);
      }

      let resultText = "";
      let sessionCaptured = false;

      for await (const message of conversation) {
        // Capture session_id from first message that has it
        if (!sessionCaptured && "session_id" in message && (message as any).session_id) {
          const sessionId = (message as any).session_id as string;
          this.instanceManager.updateSessionId(instanceId, sessionId);
          sessionCaptured = true;
          console.log(`[ClaudeExecutor] Captured session ${sessionId} for instance ${instanceId.slice(0, 8)}`);
        }

        if (message.type === "assistant") {
          const content = message.message.content;
          if (Array.isArray(content)) {
            for (const block of content) {
              if (block.type === "text") {
                execution.output.push(block.text);
                console.log(`[Claude:${instanceId.slice(0, 8)}] ${block.text.slice(0, 200)}`);
              } else if (block.type === "tool_use") {
                console.log(`[Claude:${instanceId.slice(0, 8)}:tool] ${block.name}(${JSON.stringify(block.input).slice(0, 200)})`);
              }
            }
          }
        } else if (message.type === "result") {
          if (message.subtype === "success") {
            resultText = message.result;
          } else {
            // Error result
            const errors = "errors" in message ? (message.errors as string[]).join(", ") : "Unknown error";
            throw new Error(`SDK error (${message.subtype}): ${errors}`);
          }
        }
      }

      // Success
      const fullOutput = execution.output.join("\n");
      const summary = resultText || this.extractSummary(fullOutput);

      this.activeExecutions.delete(instanceId);
      this.instanceManager.updateStatus(instanceId, "idle", summary);
      this.instanceManager.addMessage(instanceId, "assistant", fullOutput);

      await this.instanceManager.updateContext(
        instanceId,
        { role: "assistant", content: fullOutput },
        summary
      );

      console.log(`[ClaudeExecutor] Instance ${instanceId} completed successfully`);

      if (callbacks?.onComplete) {
        // Fetch latest instance to get session ID (captured during streaming)
        const latest = this.instanceManager.getInstance(instanceId);
        const resumeCmd = latest?.claude_session_id
          ? `\n\nResume in terminal: \`claude --resume ${latest.claude_session_id}\``
          : "";
        await callbacks.onComplete(instanceId, `**Task Completed** (Instance: \`${instanceId}\`)${resumeCmd}\n${summary}`);
      }
    } catch (err: any) {
      this.activeExecutions.delete(instanceId);
      const fullOutput = execution.output.join("\n");

      if (err.name === "AbortError") {
        this.instanceManager.updateStatus(instanceId, "failed");
        console.log(`[ClaudeExecutor] Instance ${instanceId} was aborted`);
      } else {
        this.instanceManager.updateStatus(instanceId, "failed");
        console.error(`[ClaudeExecutor] Instance ${instanceId} failed:`, err.message);

        if (callbacks?.onError) {
          await callbacks.onError(instanceId, `Claude failed: ${err.message}\n\nOutput:\n${fullOutput.slice(-500)}`);
        }
      }
    }
  }

  /**
   * Read MCP server configs from ~/.claude.json for the spawned instance.
   * Only include better-call-claude (not dear-claude to avoid recursion).
   */
  private getMcpServers(): Record<string, any> {
    try {
      const configPath = join(homedir(), ".claude.json");
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      const servers: Record<string, any> = {};

      if (config.mcpServers) {
        for (const [name, serverConfig] of Object.entries(config.mcpServers)) {
          // Skip dear-claude to avoid recursive spawning
          if (name === "dear-claude") continue;
          // Only include servers that are relevant
          if (name === "better-call-claude") {
            servers[name] = serverConfig;
          }
        }
      }

      return servers;
    } catch (e) {
      console.warn("[ClaudeExecutor] Could not read MCP config:", e);
      return {};
    }
  }

  /**
   * Build Linear API section for prompt
   */
  private buildLinearApiSection(creds: { token: string; teamId?: string }, issueContext?: IssueContext): string {
    return `
## Linear API Access

You can interact with Linear directly using curl. Your access token is already embedded.

### Create a sub-issue
\`\`\`bash
curl -s -X POST https://api.linear.app/graphql \\
  -H "Content-Type: application/json" \\
  -H "Authorization: ${creds.token}" \\
  -d '{"query":"mutation { issueCreate(input: { title: \\"TITLE\\", description: \\"DESC\\"${creds.teamId ? `, teamId: \\"${creds.teamId}\\"` : ""}${issueContext?.parentIssueId ? `, parentId: \\"${issueContext.parentIssueId}\\"` : ""} }) { success issue { id identifier url } } }"}'
\`\`\`

### Query workflow states (to find state IDs for status transitions)
\`\`\`bash
curl -s -X POST https://api.linear.app/graphql \\
  -H "Content-Type: application/json" \\
  -H "Authorization: ${creds.token}" \\
  -d '{"query":"{ workflowStates { nodes { id name type } } }"}'
\`\`\`

### Update issue status
\`\`\`bash
curl -s -X POST https://api.linear.app/graphql \\
  -H "Content-Type: application/json" \\
  -H "Authorization: ${creds.token}" \\
  -d '{"query":"mutation { issueUpdate(id: \\"ISSUE_ID\\", input: { stateId: \\"STATE_ID\\" }) { success } }"}'
\`\`\`
`;
  }

  /**
   * Build Jira API section for prompt
   */
  private buildJiraApiSection(creds: { basicAuth: string; baseUrl: string; projectKey?: string }, issueContext?: IssueContext): string {
    return `
## Jira API Access

You can interact with Jira directly using curl. Your credentials are already embedded.

### Create a sub-task
\`\`\`bash
curl -s -X POST ${creds.baseUrl}/rest/api/2/issue \\
  -H "Authorization: Basic ${creds.basicAuth}" \\
  -H "Content-Type: application/json" \\
  -d '{"fields":{"project":{"key":"${creds.projectKey || "PROJECT"}"},"summary":"TITLE","description":"DESC","issuetype":{"name":"Sub-task"}${issueContext?.parentIssueId ? `,"parent":{"key":"${issueContext.parentIssueId}"}` : ""}}}'
\`\`\`

### Query available transitions (to find transition IDs for status changes)
\`\`\`bash
curl -s ${creds.baseUrl}/rest/api/2/issue/ISSUE_KEY/transitions \\
  -H "Authorization: Basic ${creds.basicAuth}" \\
  -H "Accept: application/json"
\`\`\`

### Transition issue status
\`\`\`bash
curl -s -X POST ${creds.baseUrl}/rest/api/2/issue/ISSUE_KEY/transitions \\
  -H "Authorization: Basic ${creds.basicAuth}" \\
  -H "Content-Type: application/json" \\
  -d '{"transition":{"id":"TRANSITION_ID"}}'
\`\`\`

### Add a comment
\`\`\`bash
curl -s -X POST ${creds.baseUrl}/rest/api/2/issue/ISSUE_KEY/comment \\
  -H "Authorization: Basic ${creds.basicAuth}" \\
  -H "Content-Type: application/json" \\
  -d '{"body":"Comment text"}'
\`\`\`
`;
  }

  /**
   * Build Notion API section for prompt
   */
  private buildNotionApiSection(creds: { token: string }): string {
    return `
## Notion API Access

You can interact with Notion directly using curl. Your access token is already embedded.

### Query a database (with optional filter)
\`\`\`bash
curl -s -X POST https://api.notion.com/v1/databases/DATABASE_ID/query \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Notion-Version: 2022-06-28" \\
  -H "Content-Type: application/json" \\
  -d '{"filter":{"property":"Status","select":{"equals":"In Progress"}}}'
\`\`\`

### Create a database entry
\`\`\`bash
curl -s -X POST https://api.notion.com/v1/pages \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Notion-Version: 2022-06-28" \\
  -H "Content-Type: application/json" \\
  -d '{"parent":{"database_id":"DATABASE_ID"},"properties":{"Name":{"title":[{"text":{"content":"TITLE"}}]},"Status":{"select":{"name":"To Do"}}}}'
\`\`\`

### Create a sub-page
\`\`\`bash
curl -s -X POST https://api.notion.com/v1/pages \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Notion-Version: 2022-06-28" \\
  -H "Content-Type: application/json" \\
  -d '{"parent":{"page_id":"PARENT_PAGE_ID"},"properties":{"title":{"title":[{"text":{"content":"TITLE"}}]}},"children":[{"object":"block","type":"paragraph","paragraph":{"rich_text":[{"text":{"content":"Content here"}}]}}]}'
\`\`\`

### Update page properties
\`\`\`bash
curl -s -X PATCH https://api.notion.com/v1/pages/PAGE_ID \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Notion-Version: 2022-06-28" \\
  -H "Content-Type: application/json" \\
  -d '{"properties":{"Status":{"select":{"name":"Done"}}}}'
\`\`\`
`;
  }

  /**
   * Build GitHub API section for prompt
   */
  private buildGitHubApiSection(creds: { token: string; apiUrl?: string }): string {
    const apiBase = creds.apiUrl || "https://api.github.com";
    return `
## GitHub API Access

You can interact with GitHub directly using curl or the \`gh\` CLI. Your token is already embedded.

### Create an issue
\`\`\`bash
curl -s -X POST ${apiBase}/repos/OWNER/REPO/issues \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Accept: application/vnd.github+json" \\
  -d '{"title":"TITLE","body":"DESCRIPTION","labels":["bug"]}'
\`\`\`

### Create a pull request
\`\`\`bash
curl -s -X POST ${apiBase}/repos/OWNER/REPO/pulls \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Accept: application/vnd.github+json" \\
  -d '{"title":"TITLE","body":"DESCRIPTION","head":"BRANCH","base":"main"}'
\`\`\`

### Add a comment to an issue or PR
\`\`\`bash
curl -s -X POST ${apiBase}/repos/OWNER/REPO/issues/NUMBER/comments \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Accept: application/vnd.github+json" \\
  -d '{"body":"Comment text"}'
\`\`\`

### Add labels
\`\`\`bash
curl -s -X POST ${apiBase}/repos/OWNER/REPO/issues/NUMBER/labels \\
  -H "Authorization: Bearer ${creds.token}" \\
  -H "Accept: application/vnd.github+json" \\
  -d '{"labels":["label-name"]}'
\`\`\`
`;
  }

  /**
   * Build GitLab API section for prompt
   */
  private buildGitLabApiSection(creds: { token: string; apiUrl?: string }): string {
    const apiBase = creds.apiUrl || "https://gitlab.com/api/v4";
    return `
## GitLab API Access

You can interact with GitLab directly using curl. Your token is already embedded.

### Create an issue
\`\`\`bash
curl -s -X POST "${apiBase}/projects/PROJECT_ID/issues" \\
  -H "PRIVATE-TOKEN: ${creds.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"title":"TITLE","description":"DESC","labels":"bug"}'
\`\`\`

### Create a merge request
\`\`\`bash
curl -s -X POST "${apiBase}/projects/PROJECT_ID/merge_requests" \\
  -H "PRIVATE-TOKEN: ${creds.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"source_branch":"BRANCH","target_branch":"main","title":"TITLE","description":"DESC"}'
\`\`\`

### Add a comment to an issue
\`\`\`bash
curl -s -X POST "${apiBase}/projects/PROJECT_ID/issues/ISSUE_IID/notes" \\
  -H "PRIVATE-TOKEN: ${creds.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"body":"Comment text"}'
\`\`\`

### Add a comment to a merge request
\`\`\`bash
curl -s -X POST "${apiBase}/projects/PROJECT_ID/merge_requests/MR_IID/notes" \\
  -H "PRIVATE-TOKEN: ${creds.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"body":"Comment text"}'
\`\`\`
`;
  }

  /**
   * Build all platform API sections from AllPlatformCredentials
   */
  private buildAllPlatformApiSections(allCredentials?: AllPlatformCredentials, issueContext?: IssueContext): string {
    if (!allCredentials) return "";
    let sections = "";
    if (allCredentials.linear) sections += this.buildLinearApiSection(allCredentials.linear, issueContext);
    if (allCredentials.jira) sections += this.buildJiraApiSection(allCredentials.jira, issueContext);
    if (allCredentials.notion) sections += this.buildNotionApiSection(allCredentials.notion);
    if (allCredentials.github) sections += this.buildGitHubApiSection(allCredentials.github);
    if (allCredentials.gitlab) sections += this.buildGitLabApiSection(allCredentials.gitlab);
    return sections;
  }

  /**
   * Build prompt for a new instance
   */
  private buildNewPrompt(instance: Instance, request: string, isPR?: boolean, diffContent?: string, repoMeta?: RepoMeta, platformCredentials?: PlatformCredentials, issueContext?: IssueContext, allCredentials?: AllPlatformCredentials, spawnPort?: number): string {
    let prSection = "";
    if (isPR && diffContent) {
      prSection = `
## Pull Request / Merge Request Review

You are reviewing a pull request. Analyze the diff below and provide constructive code review.
Focus on: bugs, security issues, performance, readability, and best practices.
Be specific with file paths and line numbers when suggesting changes.

### Diff Content
\`\`\`diff
${diffContent.slice(0, 15000)}
\`\`\`
`;
    }

    let repoSection = "";
    if (repoMeta) {
      repoSection = `
## Repository Access

Base repo location: ~/dev/${repoMeta.repoName}

### Setup (run these commands):
\`\`\`bash
if [ -d ~/dev/${repoMeta.repoName}/.git ]; then
  cd ~/dev/${repoMeta.repoName}
  git fetch origin
  git worktree add .worktrees/${repoMeta.branch} -b ${repoMeta.branch} origin/${repoMeta.baseBranch} 2>/dev/null || \\
    git worktree add .worktrees/${repoMeta.branch} ${repoMeta.branch} 2>/dev/null || \\
    (cd ~/dev/${repoMeta.repoName} && git checkout ${repoMeta.branch} && git pull origin ${repoMeta.branch})
else
  git clone ${repoMeta.authCloneUrl} ~/dev/${repoMeta.repoName}
  cd ~/dev/${repoMeta.repoName}
fi
\`\`\`

If using worktree, work in: ~/dev/${repoMeta.repoName}/.worktrees/${repoMeta.branch}
Otherwise: ~/dev/${repoMeta.repoName}

### After making changes:
\`\`\`bash
git add -A && git commit -m "description" && git push origin ${repoMeta.branch}
\`\`\`

The clone URL includes auth — no password needed.
`;
    }

    let reviewFormatSection = "";
    if (isPR) {
      reviewFormatSection = `
## Review Output Format

Structure your review as:
1. Summary at the top
2. For file-specific comments, use:
   ### FILE:path/to/file.ts LINE:42
   Your comment here
   ### FILE:path/to/file.ts LINE:108-112
   \`\`\`suggestion
   fixed code
   \`\`\`
These become inline comments with one-click Apply buttons.
`;
    }

    const giphyKey = process.env.GIPHY_API_KEY;
    const gifSection = giphyKey ? `
## GIF Reactions

To make responses engaging, you can embed GIFs. Use curl to search Giphy:
  curl -s "https://api.giphy.com/v1/gifs/search?api_key=${giphyKey}&q=QUERY&limit=1&rating=g"
Then embed: ![description](gif_url)
Use sparingly - one per response max, only when it adds value (celebrations, humor).
` : "";

    let issueContextSection = "";
    if (issueContext) {
      issueContextSection = `
## Issue Context

${issueContext.title ? `**Title**: ${issueContext.title}` : ""}
${issueContext.issueUrl ? `**URL**: ${issueContext.issueUrl}` : ""}
${issueContext.projectKey ? `**Project**: ${issueContext.projectKey}` : ""}
${issueContext.parentIssueId ? `**Parent Issue**: ${issueContext.parentIssueId}` : ""}
`;
    }

    // Build API sections for ALL configured platforms (not just triggering platform)
    const platformApiSection = this.buildAllPlatformApiSections(allCredentials, issueContext);

    let obsidianSection = "";
    if (instance.platform === "obsidian") {
      obsidianSection = `
## Obsidian Vault Access

Your working directory IS the Obsidian vault at ${instance.working_dir}.
You have direct filesystem access to the entire knowledge base.

- Read any note with the Read tool. Create/edit notes by writing markdown files.
- Wikilinks use [[note-name]] syntax. Files are .md in the vault directory.
- Attachments are typically in an "attachments" or "assets" subdirectory.
- Your response will be appended to the source file as a callout block automatically.

When images are referenced below, use the Read tool to view them — you can see and analyze images directly.
`;
    }

    return `
You received a request from a user via ${instance.platform}. Their request was:
"${request}"

## Instructions

1. **Execute the task**: Complete the user's request as described
2. **Work locally**: Create files and directories in the current working directory (${instance.working_dir})
3. **Be thorough**: Implement complete, working solutions
4. **Document your work**: Provide a summary of what you created/changed
${prSection}${repoSection}${reviewFormatSection}${issueContextSection}${platformApiSection}${obsidianSection}
## Working Directory

You are working in: ${instance.working_dir}

All files you create will be saved here. The user will be notified of the results via ${instance.platform}.

## Available MCP Tools

You have access to MCP (Model Context Protocol) servers that provide additional capabilities:

- **better-call-claude**: Send WhatsApp messages and SMS via Twilio. Use \`send_whatsapp\` or \`send_sms\` tools.

When the user asks you to send a WhatsApp message or SMS, use the better-call-claude MCP tools directly. The credentials are already configured - just call the tool.
${gifSection}${spawnPort ? `
## Instance Orchestration

Your instance ID: ${instance.id}
Dear-claude API: http://localhost:${spawnPort}

### Spawn a parallel instance (for parallel coding tasks):
\`\`\`bash
curl -s -X POST http://localhost:${spawnPort}/api/spawn \\
  -H "Content-Type: application/json" \\
  -d '{"prompt":"TASK DESCRIPTION","branch":"feature/task-name","repo_url":"https://github.com/OWNER/REPO","parent_instance_id":"${instance.id}","project_id":"${instance.project_id || instance.id}"}'
\`\`\`

### Check instance status:
\`\`\`bash
curl -s http://localhost:${spawnPort}/api/instances/INSTANCE_ID
\`\`\`

### List project instances:
\`\`\`bash
curl -s "http://localhost:${spawnPort}/api/instances?project_id=${instance.project_id || instance.id}"
\`\`\`

Use this to parallelize work: spawn one instance per task/branch, each works in its own git worktree.
` : ""}
Start now. Execute the task.
`.trim();
  }

  /**
   * Extract a summary from Claude's output
   */
  private extractSummary(output: string): string {
    const lines = output.trim().split("\n");

    // Look for summary section markers and take content after them
    const summaryMarkers = ["## summary", "### summary", "**summary**", "summary:"];
    const lowerOutput = output.toLowerCase();

    for (const marker of summaryMarkers) {
      const idx = lowerOutput.indexOf(marker);
      if (idx !== -1) {
        const afterMarker = output.slice(idx + marker.length).trim();
        const nextSection = afterMarker.search(/\n#{2,}\s/);
        let summaryText = nextSection > 0 ? afterMarker.slice(0, nextSection) : afterMarker;

        if (summaryText.trim().endsWith(":")) {
          const listMatch = afterMarker.match(/^[^]*?:\n+((?:[-*]\s+[^\n]+\n?)+)/);
          if (listMatch) {
            summaryText = afterMarker.slice(0, afterMarker.indexOf(listMatch[1]) + listMatch[1].length);
          }
        }

        if (summaryText.length > 20) {
          return summaryText.slice(0, 500).trim();
        }
      }
    }

    const creationPatterns = [
      /I (?:created|built|implemented|wrote|made|added|developed)[^]*?(?:\.(?:\s|$)|!)/i,
      /(?:Created|Built|Implemented|Added)[^]*?(?:\.(?:\s|$)|!)/i
    ];

    for (const pattern of creationPatterns) {
      const match = output.match(pattern);
      if (match && match[0].length > 20) {
        const cleaned = match[0].trim();
        if (cleaned.length > 500) {
          const breakPoint = cleaned.slice(0, 500).lastIndexOf('. ');
          return breakPoint > 100 ? cleaned.slice(0, breakPoint + 1) : cleaned.slice(0, 500);
        }
        return cleaned;
      }
    }

    const meaningfulLines = lines
      .filter(l => {
        const trimmed = l.trim();
        return trimmed &&
          !trimmed.startsWith("[") &&
          !trimmed.startsWith("```") &&
          !trimmed.startsWith(">") &&
          trimmed.length > 10;
      })
      .slice(-5);

    return meaningfulLines.join("\n").slice(0, 500) || "Task completed successfully.";
  }

  /**
   * Kill a running instance
   */
  kill(instanceId: string): boolean {
    const execution = this.activeExecutions.get(instanceId);
    if (execution) {
      execution.abortController.abort();
      this.activeExecutions.delete(instanceId);
      this.instanceManager.updateStatus(instanceId, "failed");
      console.log(`[ClaudeExecutor] Killed instance ${instanceId}`);
      return true;
    }
    return false;
  }

  /**
   * Check if an instance is currently running
   */
  isRunning(instanceId: string): boolean {
    return this.activeExecutions.has(instanceId);
  }

  /**
   * Get all running instance IDs
   */
  getRunningInstances(): string[] {
    return Array.from(this.activeExecutions.keys());
  }

  /**
   * Cleanup - kill all running instances
   */
  async cleanup(): Promise<void> {
    for (const [instanceId, execution] of this.activeExecutions) {
      execution.abortController.abort();
      this.instanceManager.updateStatus(instanceId, "failed");
    }
    this.activeExecutions.clear();
    console.log("[ClaudeExecutor] Cleaned up all running instances");
  }
}

export interface ParsedReviewOutput {
  summary: string;
  inlineComments: Array<{ path: string; startLine: number; endLine?: number; body: string }>;
}

/**
 * Parse Claude's review output into summary + inline comments.
 * Looks for ### FILE:path/to/file LINE:N or LINE:N-M markers.
 */
export function parseReviewOutput(output: string): ParsedReviewOutput {
  const marker = /^### FILE:(\S+)\s+LINE:(\d+)(?:-(\d+))?/gm;
  const parts = output.split(marker);

  // parts[0] is the summary (before first marker)
  // Then groups of 4: [path, startLine, endLine?, body] repeating
  const summary = parts[0].trim();
  const inlineComments: ParsedReviewOutput["inlineComments"] = [];

  // After split with capture groups, layout is:
  // [summary, path1, line1, endLine1, body1, path2, line2, endLine2, body2, ...]
  for (let i = 1; i + 3 < parts.length; i += 4) {
    const path = parts[i];
    const startLine = parseInt(parts[i + 1], 10);
    const endLine = parts[i + 2] ? parseInt(parts[i + 2], 10) : undefined;
    const body = parts[i + 3].trim();
    if (path && body) {
      inlineComments.push({ path, startLine, endLine, body });
    }
  }

  return { summary: summary || output.trim(), inlineComments };
}
