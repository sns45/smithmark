/**
 * Obsidian Adapter
 * Handles responses back to Obsidian vault files.
 * Trigger detection is handled by ObsidianVaultWatcher — this adapter
 * provides response methods (postResponse, setStatus) only.
 */

import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { join, resolve } from "path";
import type { Context } from "hono";
import type { PlatformAdapter, PlatformEvent } from "./platform-adapter.js";
import type { ObsidianVaultWatcher } from "./obsidian-watcher.js";

export class ObsidianAdapter implements PlatformAdapter {
  readonly platform = "obsidian" as const;
  private vaultPath: string;
  private watcher: ObsidianVaultWatcher | null;
  private currentInstanceId: string | undefined;
  private currentSessionId: string | undefined;

  constructor(vaultPath: string, watcher?: ObsidianVaultWatcher) {
    this.vaultPath = resolve(vaultPath);
    this.watcher = watcher || null;
  }

  /** Set the instance ID to embed in response callout blocks */
  setInstanceId(id: string): void {
    this.currentInstanceId = id;
  }

  /** Set the Claude session ID for resume instructions */
  setSessionId(id: string): void {
    this.currentSessionId = id;
  }

  isConfigured(): boolean {
    return existsSync(this.vaultPath);
  }

  // --- No-op stubs (watcher bypasses webhook path) ---

  async verifySignature(_ctx: Context, _body: string): Promise<boolean> {
    return true; // Not used — watcher bypasses webhooks
  }

  async parseWebhook(_ctx: Context, _body: unknown): Promise<PlatformEvent | null> {
    return null; // Not used — watcher produces events directly
  }

  // --- Response Methods ---

  /**
   * Append a > [!claude] callout block to the source markdown file.
   * Uses the watcher's write lock to prevent re-triggering.
   */
  async postResponse(threadId: string, message: string): Promise<void> {
    const filePath = this.resolveThreadPath(threadId);
    if (!filePath || !existsSync(filePath)) {
      console.error(`[ObsidianAdapter] File not found for thread ${threadId}`);
      return;
    }

    // Acquire write lock so the watcher ignores this change
    const unlock = this.watcher?.lockFile(filePath) || (() => {});

    try {
      const content = await readFile(filePath, "utf-8");

      // Format response as Obsidian callout block
      const timestamp = new Date().toISOString().replace("T", " ").slice(0, 16);
      const displayId = this.currentInstanceId || "unknown";
      const calloutLines = message.split("\n").map(line => `> ${line}`).join("\n");
      const resumeHint = this.currentSessionId ? `\n> \`claude --resume ${this.currentSessionId}\`` : "";
      const callout = `\n---\n\n> [!claude] Claude Response\n${calloutLines}\n>\n> *Instance: ${displayId} | ${timestamp}*${resumeHint}\n`;

      await writeFile(filePath, content + callout, "utf-8");
      console.log(`[ObsidianAdapter] Appended response to ${filePath}`);
    } finally {
      // Small delay before unlocking so fs.watch doesn't race
      setTimeout(unlock, 500);
    }
  }

  /**
   * Update YAML frontmatter with claude-status property.
   */
  async setStatus(threadId: string, status: "processing" | "done" | "error"): Promise<void> {
    const filePath = this.resolveThreadPath(threadId);
    if (!filePath || !existsSync(filePath)) return;

    const unlock = this.watcher?.lockFile(filePath) || (() => {});

    try {
      const content = await readFile(filePath, "utf-8");
      const updated = this.updateFrontmatter(content, "claude-status", status);
      if (updated !== content) {
        await writeFile(filePath, updated, "utf-8");
        console.log(`[ObsidianAdapter] Set frontmatter claude-status: ${status} in ${filePath}`);
      }
    } finally {
      setTimeout(unlock, 500);
    }
  }

  // --- Helpers ---

  /**
   * Convert threadId (obsidian:relative/path.md) to absolute file path
   */
  private resolveThreadPath(threadId: string): string | null {
    const relPath = threadId.replace("obsidian:", "");
    const absPath = join(this.vaultPath, relPath);
    return absPath;
  }

  /**
   * Update or insert a key in YAML frontmatter.
   * Creates frontmatter if none exists.
   */
  private updateFrontmatter(content: string, key: string, value: string): string {
    const fmMatch = content.match(/^---\n([\s\S]*?)\n---\n/);

    if (fmMatch) {
      const fmBody = fmMatch[1];
      // Check if key already exists in frontmatter
      const keyRegex = new RegExp(`^${key}:.*$`, "m");
      if (keyRegex.test(fmBody)) {
        const updatedFm = fmBody.replace(keyRegex, `${key}: ${value}`);
        return content.replace(fmMatch[0], `---\n${updatedFm}\n---\n`);
      }
      // Key doesn't exist — append it
      return content.replace(fmMatch[0], `---\n${fmBody}\n${key}: ${value}\n---\n`);
    }

    // No frontmatter — create it
    return `---\n${key}: ${value}\n---\n${content}`;
  }
}
