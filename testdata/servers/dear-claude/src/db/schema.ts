/**
 * Database Schema
 * SQLite schema using Bun's built-in SQLite support
 */

import { Database } from "bun:sqlite";
import { join } from "path";
import { mkdirSync, existsSync } from "fs";
import { homedir } from "os";

export interface Instance {
  id: string;
  thread_id: string;           // Platform-specific thread/issue ID
  platform: "linear" | "github" | "gitlab" | "jira" | "notion" | "obsidian";
  status: "pending" | "running" | "completed" | "failed" | "idle" | "expired";
  working_dir: string;
  original_prompt: string;
  completion_summary?: string;
  claude_session_id?: string;  // SDK session ID for `claude --resume`
  parent_instance_id?: string; // Parent instance that spawned this one
  project_id?: string;         // Groups related instances together
  created_at: number;
  updated_at: number;
  expires_at: number;          // 7 days from last activity
}

export interface Message {
  id: string;
  instance_id: string;
  role: "user" | "assistant";
  content: string;
  platform_message_id?: string;
  created_at: number;
}

export interface OAuthToken {
  id: string;
  provider: "linear" | "github" | "gitlab" | "jira" | "notion";
  user_id: string;
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  scope: string;
  platform_username?: string;  // GitHub login, Linear user ID, etc.
  created_at: number;
  updated_at: number;
}

export interface WebhookConfig {
  id: string;
  platform: "linear" | "github" | "gitlab" | "jira" | "notion" | "obsidian";
  webhook_id?: string;
  webhook_secret?: string;
  subscription_id?: string;
  created_at: number;
}

const SCHEMA = `
-- Instances table
CREATE TABLE IF NOT EXISTS instances (
  id TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'idle', 'expired')),
  working_dir TEXT NOT NULL,
  original_prompt TEXT NOT NULL,
  completion_summary TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_instances_thread_platform ON instances (thread_id, platform);
CREATE INDEX IF NOT EXISTS idx_instances_status ON instances (status);
CREATE INDEX IF NOT EXISTS idx_instances_expires ON instances (expires_at);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  instance_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  platform_message_id TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_instance ON messages (instance_id);

-- OAuth tokens table
CREATE TABLE IF NOT EXISTS oauth_tokens (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL CHECK (provider IN ('linear', 'github', 'gitlab', 'jira', 'notion')),
  user_id TEXT NOT NULL,
  access_token TEXT NOT NULL,
  refresh_token TEXT,
  expires_at INTEGER,
  scope TEXT NOT NULL,
  platform_username TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_tokens (provider, user_id);

-- Webhook configurations table
CREATE TABLE IF NOT EXISTS webhook_configs (
  id TEXT PRIMARY KEY,
  platform TEXT NOT NULL UNIQUE CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
  webhook_id TEXT,
  webhook_secret TEXT,
  subscription_id TEXT,
  created_at INTEGER NOT NULL
);
`;

export class DatabaseManager {
  private db: Database;

  constructor(dbPath?: string) {
    const dataDir = process.env.DEAR_CLAUDE_DATA_DIR
      || join(homedir(), ".dear-claude", "data");
    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }
    const path = dbPath || join(dataDir, "dear-claude.db");
    this.db = new Database(path);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA foreign_keys = ON");
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(SCHEMA);
    this.runMigrations();
    console.log("[Database] Initialized schema");
  }

  private runMigrations(): void {
    // Migration: Fix messages FK if it references a stale table (e.g. instances_old)
    try {
      const fkInfo = this.db.prepare("PRAGMA foreign_key_list(messages)").all() as Array<{ table: string }>;
      const badFk = fkInfo.some(fk => fk.table !== "instances");
      if (badFk) {
        console.log("[Database] Migration: Fixing messages FK reference");
        this.db.exec("PRAGMA foreign_keys = OFF");
        this.db.exec("BEGIN TRANSACTION");
        this.db.exec("ALTER TABLE messages RENAME TO messages_broken_fk");
        this.db.exec(`CREATE TABLE messages (
          id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
          content TEXT NOT NULL, platform_message_id TEXT, created_at INTEGER NOT NULL,
          FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE
        )`);
        this.db.exec("INSERT INTO messages SELECT * FROM messages_broken_fk");
        this.db.exec("DROP TABLE messages_broken_fk");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_messages_instance ON messages (instance_id)");
        this.db.exec("COMMIT");
        this.db.exec("PRAGMA foreign_keys = ON");
        console.log("[Database] Migration: Fixed messages FK");
      }
    } catch (err) {
      console.error("[Database] Migration error (messages FK):", err);
      try { this.db.exec("ROLLBACK"); } catch {}
      this.db.exec("PRAGMA foreign_keys = ON");
    }

    // Migration: Add platform_username column to oauth_tokens if it doesn't exist
    try {
      const tableInfo = this.db.prepare("PRAGMA table_info(oauth_tokens)").all() as Array<{ name: string }>;
      const hasColumn = tableInfo.some(col => col.name === "platform_username");
      if (!hasColumn) {
        this.db.exec("ALTER TABLE oauth_tokens ADD COLUMN platform_username TEXT");
        console.log("[Database] Migration: Added platform_username column to oauth_tokens");
      }
    } catch (err) {
      console.error("[Database] Migration error:", err);
    }

    // Migration: Add 'jira' to CHECK constraints (SQLite requires table rebuild)
    try {
      this.db.prepare("INSERT INTO instances (id, thread_id, platform, status, working_dir, original_prompt, expires_at, created_at, updated_at) VALUES ('__migration_test', 'test', 'jira', 'pending', '/tmp', 'test', 0, 0, 0)").run();
      this.db.prepare("DELETE FROM instances WHERE id = '__migration_test'").run();
    } catch {
      // Constraint doesn't support 'jira' — rebuild tables
      console.log("[Database] Migration: Rebuilding tables to add 'jira' platform support");
      try {
        this.db.exec("BEGIN TRANSACTION");
        // Instances
        this.db.exec("ALTER TABLE instances RENAME TO instances_old");
        this.db.exec(`CREATE TABLE instances (
          id TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
          platform TEXT NOT NULL CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'idle', 'expired')),
          working_dir TEXT NOT NULL, original_prompt TEXT NOT NULL, completion_summary TEXT,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO instances SELECT * FROM instances_old");
        this.db.exec("DROP TABLE instances_old");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_thread_platform ON instances (thread_id, platform)");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_status ON instances (status)");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_expires ON instances (expires_at)");
        // Rebuild messages table too (FK may point to instances_old after rename)
        this.db.exec("ALTER TABLE messages RENAME TO messages_old");
        this.db.exec(`CREATE TABLE messages (
          id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
          content TEXT NOT NULL, platform_message_id TEXT, created_at INTEGER NOT NULL,
          FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE
        )`);
        this.db.exec("INSERT INTO messages SELECT * FROM messages_old");
        this.db.exec("DROP TABLE messages_old");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_messages_instance ON messages (instance_id)");
        // OAuth tokens
        this.db.exec("ALTER TABLE oauth_tokens RENAME TO oauth_tokens_old");
        this.db.exec(`CREATE TABLE oauth_tokens (
          id TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK (provider IN ('linear', 'github', 'gitlab', 'jira', 'notion')),
          user_id TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT, expires_at INTEGER,
          scope TEXT NOT NULL, platform_username TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO oauth_tokens SELECT * FROM oauth_tokens_old");
        this.db.exec("DROP TABLE oauth_tokens_old");
        this.db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_tokens (provider, user_id)");
        // Webhook configs
        this.db.exec("ALTER TABLE webhook_configs RENAME TO webhook_configs_old");
        this.db.exec(`CREATE TABLE webhook_configs (
          id TEXT PRIMARY KEY, platform TEXT NOT NULL UNIQUE CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
          webhook_id TEXT, webhook_secret TEXT, subscription_id TEXT, created_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO webhook_configs SELECT * FROM webhook_configs_old");
        this.db.exec("DROP TABLE webhook_configs_old");
        this.db.exec("COMMIT");
        console.log("[Database] Migration: Successfully added 'jira' platform support");
      } catch (err) {
        this.db.exec("ROLLBACK");
        console.error("[Database] Migration error (jira platform):", err);
      }
    }

    // Migration: Add 'notion' and 'obsidian' to CHECK constraints (same table rebuild pattern)
    try {
      this.db.prepare("INSERT INTO instances (id, thread_id, platform, status, working_dir, original_prompt, expires_at, created_at, updated_at) VALUES ('__migration_test_notion', 'test', 'notion', 'pending', '/tmp', 'test', 0, 0, 0)").run();
      this.db.prepare("DELETE FROM instances WHERE id = '__migration_test_notion'").run();
    } catch {
      console.log("[Database] Migration: Rebuilding tables to add 'notion'/'obsidian' platform support");
      try {
        this.db.exec("BEGIN TRANSACTION");
        this.db.exec("ALTER TABLE instances RENAME TO instances_old");
        this.db.exec(`CREATE TABLE instances (
          id TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
          platform TEXT NOT NULL CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
          status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'idle', 'expired')),
          working_dir TEXT NOT NULL, original_prompt TEXT NOT NULL, completion_summary TEXT,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO instances SELECT * FROM instances_old");
        this.db.exec("DROP TABLE instances_old");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_thread_platform ON instances (thread_id, platform)");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_status ON instances (status)");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_expires ON instances (expires_at)");
        this.db.exec("ALTER TABLE messages RENAME TO messages_old");
        this.db.exec(`CREATE TABLE messages (
          id TEXT PRIMARY KEY, instance_id TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
          content TEXT NOT NULL, platform_message_id TEXT, created_at INTEGER NOT NULL,
          FOREIGN KEY (instance_id) REFERENCES instances(id) ON DELETE CASCADE
        )`);
        this.db.exec("INSERT INTO messages SELECT * FROM messages_old");
        this.db.exec("DROP TABLE messages_old");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_messages_instance ON messages (instance_id)");
        this.db.exec("ALTER TABLE oauth_tokens RENAME TO oauth_tokens_old");
        this.db.exec(`CREATE TABLE oauth_tokens (
          id TEXT PRIMARY KEY, provider TEXT NOT NULL CHECK (provider IN ('linear', 'github', 'gitlab', 'jira', 'notion')),
          user_id TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT, expires_at INTEGER,
          scope TEXT NOT NULL, platform_username TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO oauth_tokens SELECT * FROM oauth_tokens_old");
        this.db.exec("DROP TABLE oauth_tokens_old");
        this.db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_tokens (provider, user_id)");
        this.db.exec("ALTER TABLE webhook_configs RENAME TO webhook_configs_old");
        this.db.exec(`CREATE TABLE webhook_configs (
          id TEXT PRIMARY KEY, platform TEXT NOT NULL UNIQUE CHECK (platform IN ('linear', 'github', 'gitlab', 'jira', 'notion', 'obsidian')),
          webhook_id TEXT, webhook_secret TEXT, subscription_id TEXT, created_at INTEGER NOT NULL
        )`);
        this.db.exec("INSERT INTO webhook_configs SELECT * FROM webhook_configs_old");
        this.db.exec("DROP TABLE webhook_configs_old");
        this.db.exec("COMMIT");
        console.log("[Database] Migration: Successfully added 'notion'/'obsidian' platform support");
      } catch (err) {
        this.db.exec("ROLLBACK");
        console.error("[Database] Migration error (notion/obsidian platform):", err);
      }
    }

    // Migration: Add claude_session_id column to instances
    try {
      const tableInfo = this.db.prepare("PRAGMA table_info(instances)").all() as Array<{ name: string }>;
      const hasColumn = tableInfo.some(col => col.name === "claude_session_id");
      if (!hasColumn) {
        this.db.exec("ALTER TABLE instances ADD COLUMN claude_session_id TEXT");
        console.log("[Database] Migration: Added claude_session_id column to instances");
      }
    } catch (err) {
      console.error("[Database] Migration error (claude_session_id):", err);
    }

    // Migration: Add parent_instance_id and project_id columns to instances
    try {
      const tableInfo = this.db.prepare("PRAGMA table_info(instances)").all() as Array<{ name: string }>;
      if (!tableInfo.some(col => col.name === "parent_instance_id")) {
        this.db.exec("ALTER TABLE instances ADD COLUMN parent_instance_id TEXT");
        console.log("[Database] Migration: Added parent_instance_id column to instances");
      }
      if (!tableInfo.some(col => col.name === "project_id")) {
        this.db.exec("ALTER TABLE instances ADD COLUMN project_id TEXT");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_project ON instances (project_id)");
        this.db.exec("CREATE INDEX IF NOT EXISTS idx_instances_parent ON instances (parent_instance_id)");
        console.log("[Database] Migration: Added project_id column to instances");
      }
    } catch (err) {
      console.error("[Database] Migration error (parent_instance_id/project_id):", err);
    }
  }

  getDatabase(): Database {
    return this.db;
  }

  // Instance operations
  createInstance(instance: Omit<Instance, "created_at" | "updated_at">): Instance {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT INTO instances (id, thread_id, platform, status, working_dir, original_prompt, expires_at, parent_instance_id, project_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      instance.id,
      instance.thread_id,
      instance.platform,
      instance.status,
      instance.working_dir,
      instance.original_prompt,
      instance.expires_at,
      instance.parent_instance_id ?? null,
      instance.project_id ?? null,
      now,
      now
    );
    return { ...instance, created_at: now, updated_at: now };
  }

  getInstance(id: string): Instance | undefined {
    const stmt = this.db.prepare("SELECT * FROM instances WHERE id = ?");
    return stmt.get(id) as Instance | undefined;
  }

  getInstanceByThread(threadId: string, platform: string): Instance | undefined {
    const stmt = this.db.prepare(
      "SELECT * FROM instances WHERE thread_id = ? AND platform = ? AND status NOT IN ('expired') ORDER BY created_at DESC LIMIT 1"
    );
    return stmt.get(threadId, platform) as Instance | undefined;
  }

  updateSessionId(id: string, sessionId: string): void {
    this.db.prepare("UPDATE instances SET claude_session_id = ?, updated_at = ? WHERE id = ?")
      .run(sessionId, Date.now(), id);
  }

  updateInstanceStatus(id: string, status: Instance["status"], summary?: string): void {
    const now = Date.now();
    const expiresAt = now + 7 * 24 * 60 * 60 * 1000; // 7 days
    if (summary) {
      const stmt = this.db.prepare(
        "UPDATE instances SET status = ?, completion_summary = ?, updated_at = ?, expires_at = ? WHERE id = ?"
      );
      stmt.run(status, summary, now, expiresAt, id);
    } else {
      const stmt = this.db.prepare(
        "UPDATE instances SET status = ?, updated_at = ?, expires_at = ? WHERE id = ?"
      );
      stmt.run(status, now, expiresAt, id);
    }
  }

  getActiveInstances(): Instance[] {
    const stmt = this.db.prepare(
      "SELECT * FROM instances WHERE status IN ('pending', 'running', 'idle') ORDER BY updated_at DESC"
    );
    return stmt.all() as Instance[];
  }

  getAllInstances(limit: number = 50): Instance[] {
    const stmt = this.db.prepare(
      "SELECT * FROM instances ORDER BY updated_at DESC LIMIT ?"
    );
    return stmt.all(limit) as Instance[];
  }

  getChildInstances(parentId: string): Instance[] {
    const stmt = this.db.prepare(
      "SELECT * FROM instances WHERE parent_instance_id = ? ORDER BY created_at ASC"
    );
    return stmt.all(parentId) as Instance[];
  }

  getProjectInstances(projectId: string): Instance[] {
    const stmt = this.db.prepare(
      "SELECT * FROM instances WHERE project_id = ? ORDER BY created_at ASC"
    );
    return stmt.all(projectId) as Instance[];
  }

  // Message operations
  addMessage(message: Omit<Message, "created_at">): Message {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT INTO messages (id, instance_id, role, content, platform_message_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(message.id, message.instance_id, message.role, message.content, message.platform_message_id ?? null, now);
    return { ...message, created_at: now };
  }

  getMessages(instanceId: string): Message[] {
    const stmt = this.db.prepare("SELECT * FROM messages WHERE instance_id = ? ORDER BY created_at ASC");
    return stmt.all(instanceId) as Message[];
  }

  // OAuth operations
  saveOAuthToken(token: Omit<OAuthToken, "created_at" | "updated_at">): void {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO oauth_tokens (id, provider, user_id, access_token, refresh_token, expires_at, scope, platform_username, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(token.id, token.provider, token.user_id, token.access_token, token.refresh_token ?? null, token.expires_at ?? null, token.scope, token.platform_username ?? null, now, now);
  }

  getOAuthToken(provider: string, userId: string): OAuthToken | undefined {
    const stmt = this.db.prepare("SELECT * FROM oauth_tokens WHERE provider = ? AND user_id = ?");
    return stmt.get(provider, userId) as OAuthToken | undefined;
  }

  getOAuthTokenByProvider(provider: string): OAuthToken | undefined {
    const stmt = this.db.prepare("SELECT * FROM oauth_tokens WHERE provider = ? ORDER BY updated_at DESC LIMIT 1");
    return stmt.get(provider) as OAuthToken | undefined;
  }

  getPlatformUsername(provider: string): string | undefined {
    const token = this.getOAuthTokenByProvider(provider);
    return token?.platform_username ?? undefined;
  }

  // Webhook config operations
  saveWebhookConfig(config: Omit<WebhookConfig, "created_at">): void {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO webhook_configs (id, platform, webhook_id, webhook_secret, subscription_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(config.id, config.platform, config.webhook_id ?? null, config.webhook_secret ?? null, config.subscription_id ?? null, now);
  }

  getWebhookConfig(platform: string): WebhookConfig | undefined {
    const stmt = this.db.prepare("SELECT * FROM webhook_configs WHERE platform = ?");
    return stmt.get(platform) as WebhookConfig | undefined;
  }

  // Cleanup expired instances
  cleanupExpired(): number {
    const now = Date.now();
    const stmt = this.db.prepare("UPDATE instances SET status = 'expired' WHERE expires_at < ? AND status != 'expired'");
    const result = stmt.run(now);
    return result.changes;
  }

  close(): void {
    this.db.close();
  }
}
