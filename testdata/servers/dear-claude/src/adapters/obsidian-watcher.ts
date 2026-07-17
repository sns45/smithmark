/**
 * Obsidian Vault File Watcher
 * Watches for .md file changes containing "dear-claude" triggers.
 * No webhooks, no plugins — pure filesystem watching.
 */

import { watch, type FSWatcher } from "fs";
import { readFile, stat } from "fs/promises";
import { join, relative, extname, resolve, dirname, basename } from "path";
import { createHash } from "crypto";
import { existsSync } from "fs";
import { TriggerDetector } from "../core/trigger-detector.js";
import type { InstanceManager } from "../core/instance-manager.js";
import type { PlatformEvent } from "./platform-adapter.js";

/** Strip > [!claude] callout blocks so quoted triggers don't re-fire */
const CALLOUT_BLOCK_RE = /\n---\n\n> \[!claude\][^\n]*(?:\n> [^\n]*)*/g;

/** Match standard markdown images: ![alt](path) */
const MD_IMAGE_RE = /!\[([^\]]*)\]\(([^)]+)\)/g;

/** Match Obsidian wikilink images: ![[image.png]] */
const WIKI_IMAGE_RE = /!\[\[([^\]]+)\]\]/g;

/** Match Obsidian wikilinks: [[note-name]] (not images) */
const WIKILINK_RE = /(?<!!)\[\[([^\]|]+)(?:\|[^\]]+)?\]\]/g;

export interface ObsidianWatcherConfig {
  vaultPath: string;
  debounceMs?: number;
}

export class ObsidianVaultWatcher {
  private vaultPath: string;
  private debounceMs: number;
  private watcher: FSWatcher | null = null;
  private instanceManager: InstanceManager | null = null;
  private processEventFn: ((event: PlatformEvent) => Promise<void>) | null = null;

  /** Map of filePath -> contentHash to deduplicate triggers */
  private fileHashes: Map<string, string> = new Map();

  /** Set of files currently being written by the adapter — skip these changes */
  private writeLock: Set<string> = new Set();

  /** Debounce timers per file */
  private debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  /** Excluded directories */
  private excludeDirs = [".obsidian", ".trash", "node_modules", ".git"];

  constructor(config: ObsidianWatcherConfig) {
    this.vaultPath = resolve(config.vaultPath);
    this.debounceMs = config.debounceMs ?? 2000;
  }

  /**
   * Set the write lock for a file (called by ObsidianAdapter before appending response).
   * Returns an unlock function.
   */
  lockFile(filePath: string): () => void {
    const abs = resolve(filePath);
    this.writeLock.add(abs);
    return () => {
      this.writeLock.delete(abs);
      // Update the hash so we don't re-trigger on our own write
      this.rehashFile(abs).catch(() => {});
    };
  }

  /**
   * Start watching the vault directory
   */
  start(
    instanceManager: InstanceManager,
    processEvent: (event: PlatformEvent) => Promise<void>
  ): void {
    this.instanceManager = instanceManager;
    this.processEventFn = processEvent;

    if (!existsSync(this.vaultPath)) {
      console.error(`[ObsidianWatcher] Vault path does not exist: ${this.vaultPath}`);
      return;
    }

    try {
      this.watcher = watch(this.vaultPath, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        this.handleFileEvent(filename);
      });

      console.log(`[ObsidianWatcher] Watching vault: ${this.vaultPath}`);
    } catch (err) {
      console.error("[ObsidianWatcher] Failed to start watcher:", err);
    }
  }

  stop(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();
    console.log("[ObsidianWatcher] Stopped watching");
  }

  private handleFileEvent(filename: string): void {
    // Only .md files
    if (extname(filename) !== ".md") return;

    // Exclude internal directories
    const parts = filename.split("/");
    if (parts.some(part => this.excludeDirs.includes(part))) return;

    const absPath = join(this.vaultPath, filename);

    // Skip if under write lock (we're writing a response to this file)
    if (this.writeLock.has(absPath)) return;

    // Debounce rapid changes to the same file
    const existing = this.debounceTimers.get(absPath);
    if (existing) clearTimeout(existing);

    this.debounceTimers.set(absPath, setTimeout(() => {
      this.debounceTimers.delete(absPath);
      this.processFile(absPath, filename).catch(err => {
        console.error(`[ObsidianWatcher] Error processing ${filename}:`, err);
      });
    }, this.debounceMs));
  }

  private async processFile(absPath: string, relPath: string): Promise<void> {
    // Verify file still exists
    try {
      await stat(absPath);
    } catch {
      return; // File was deleted
    }

    const rawContent = await readFile(absPath, "utf-8");

    // Compute hash of content
    const hash = createHash("sha256").update(rawContent).digest("hex");
    const prevHash = this.fileHashes.get(absPath);

    if (prevHash === hash) {
      return; // Content unchanged, skip
    }

    this.fileHashes.set(absPath, hash);

    // Strip existing Claude callout blocks before checking for trigger
    // This prevents re-triggering when Claude's response quotes "dear claude"
    const contentForTrigger = rawContent.replace(CALLOUT_BLOCK_RE, "");

    if (!TriggerDetector.containsTrigger(contentForTrigger)) {
      return;
    }

    console.log(`[ObsidianWatcher] Trigger found in: ${relPath}`);

    // Parse images referenced in the note
    const images = this.resolveImages(rawContent);

    // Parse wikilinks and load linked note content
    const linkedNotes = await this.resolveWikilinks(rawContent);

    // Build the platform event
    const threadId = `obsidian:${relPath}`;

    // Build enriched content with image paths and linked note context
    let enrichedContent = rawContent.replace(CALLOUT_BLOCK_RE, "");

    if (images.length > 0) {
      enrichedContent += "\n\n[Referenced images — use the Read tool to view these:]\n";
      for (const img of images) {
        enrichedContent += `- ${img.alt || basename(img.path)}: ${img.path}\n`;
      }
    }

    if (linkedNotes.length > 0) {
      enrichedContent += "\n\n[Linked notes included as context:]\n";
      for (const note of linkedNotes) {
        enrichedContent += `\n--- [[${note.name}]] ---\n${note.content.slice(0, 3000)}\n`;
      }
    }

    const event: PlatformEvent = {
      platform: "obsidian",
      threadId,
      content: enrichedContent,
      isDescription: true, // File content is treated as a "description"
      raw: { filePath: absPath, relPath, images, linkedNotes: linkedNotes.map(n => n.name) }
    };

    if (this.processEventFn) {
      await this.processEventFn(event);
    }
  }

  private resolveImages(content: string): Array<{ alt: string; path: string }> {
    const images: Array<{ alt: string; path: string }> = [];

    // Standard markdown images: ![alt](path)
    let match;
    while ((match = MD_IMAGE_RE.exec(content)) !== null) {
      const imgPath = match[2];
      if (imgPath.startsWith("http")) continue; // Skip URLs
      const resolved = this.resolveVaultPath(imgPath);
      if (resolved) images.push({ alt: match[1], path: resolved });
    }

    // Obsidian wikilink images: ![[image.png]]
    while ((match = WIKI_IMAGE_RE.exec(content)) !== null) {
      const imgName = match[1];
      const resolved = this.resolveVaultPath(imgName);
      if (resolved) images.push({ alt: imgName, path: resolved });
    }

    return images;
  }

  private async resolveWikilinks(content: string): Promise<Array<{ name: string; content: string }>> {
    const notes: Array<{ name: string; content: string }> = [];
    const seen = new Set<string>();

    let match;
    while ((match = WIKILINK_RE.exec(content)) !== null) {
      const noteName = match[1].trim();
      if (seen.has(noteName)) continue;
      seen.add(noteName);

      const resolved = this.resolveVaultPath(noteName.endsWith(".md") ? noteName : `${noteName}.md`);
      if (resolved) {
        try {
          const noteContent = await readFile(resolved, "utf-8");
          notes.push({ name: noteName, content: noteContent });
        } catch {
          // Note file might not exist or be unreadable
        }
      }
    }

    return notes;
  }

  /**
   * Resolve a path/name to an absolute path in the vault.
   * Checks: exact path, common attachments folders, vault-wide search by basename.
   */
  private resolveVaultPath(pathOrName: string): string | null {
    // If it's already absolute and exists
    if (existsSync(pathOrName)) return resolve(pathOrName);

    // Try relative to vault root
    const fromRoot = join(this.vaultPath, pathOrName);
    if (existsSync(fromRoot)) return fromRoot;

    // Try common attachment directories
    const attachDirs = ["attachments", "Attachments", "assets", "Assets", "images", "Images", "media", "Media"];
    for (const dir of attachDirs) {
      const fromAttach = join(this.vaultPath, dir, basename(pathOrName));
      if (existsSync(fromAttach)) return fromAttach;
    }

    return null;
  }

  /**
   * Re-hash a file after we've written to it, so the watcher doesn't re-trigger
   */
  private async rehashFile(absPath: string): Promise<void> {
    try {
      const content = await readFile(absPath, "utf-8");
      const hash = createHash("sha256").update(content).digest("hex");
      this.fileHashes.set(absPath, hash);
    } catch {
      // File might be gone
    }
  }

  /** Expose vault path for adapter */
  getVaultPath(): string {
    return this.vaultPath;
  }
}
