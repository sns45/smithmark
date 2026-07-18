/**
 * Transport Layer - Tailscale Funnel
 * Provides public URLs via Tailscale Funnel (free, unlimited tunnels)
 * Includes guided setup when prerequisites are missing
 */

import { exec, spawn } from "child_process";
import type { ChildProcess } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export interface TransportConfig {
  port: number;
}

interface TailscaleStatus {
  installed: boolean;
  running: boolean;
  authenticated: boolean;
  funnelEnabled: boolean;
  hostname?: string;
  error?: string;
}

/**
 * Transport Manager
 * Uses Tailscale Funnel for public webhook access
 */
export class TransportManager {
  private publicUrl: string = "";
  private hostname: string = "";
  private config: TransportConfig;
  private healthCheckInterval?: ReturnType<typeof setInterval>;

  constructor(config: TransportConfig) {
    this.config = config;
  }

  async start(): Promise<string> {
    console.log("[Tailscale] Checking setup...");

    // Check all prerequisites and provide guidance
    const status = await this.checkTailscaleStatus();

    if (!status.installed) {
      await this.guidedInstall();
      throw new Error("Tailscale installation required - see instructions above");
    }

    if (!status.running) {
      console.log("[Tailscale] Tailscale daemon not running, attempting to start...");
      await this.startTailscaleDaemon();
    }

    if (!status.authenticated) {
      console.log("[Tailscale] Not authenticated, starting login...");
      await this.authenticate();
      // Re-check status after auth
      const newStatus = await this.checkTailscaleStatus();
      if (!newStatus.authenticated) {
        throw new Error("Tailscale authentication required - please complete the login in your browser");
      }
    }

    // Get hostname
    this.hostname = status.hostname || await this.getHostname();
    console.log(`[Tailscale] Hostname: ${this.hostname}`);

    // Check if funnel is enabled
    if (!status.funnelEnabled) {
      this.printFunnelInstructions();
      throw new Error("Tailscale Funnel not enabled - see instructions above");
    }

    // Start funnel
    console.log("[Tailscale] Starting Funnel...");
    await this.enableFunnel(this.config.port);

    this.publicUrl = `https://${this.hostname}/dc`;
    console.log(`[Tailscale] Funnel active: ${this.publicUrl}`);
    return this.publicUrl;
  }

  private async checkTailscaleStatus(): Promise<TailscaleStatus> {
    const status: TailscaleStatus = {
      installed: false,
      running: false,
      authenticated: false,
      funnelEnabled: false,
    };

    // Check if tailscale is installed
    try {
      await execAsync("which tailscale");
      status.installed = true;
    } catch {
      // Try common installation paths
      const paths = ["/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale", "/usr/bin/tailscale"];
      for (const path of paths) {
        try {
          await execAsync(`${path} version`);
          status.installed = true;
          break;
        } catch {
          continue;
        }
      }
      if (!status.installed) {
        return status;
      }
    }

    // Check if tailscale is running and get status
    try {
      const { stdout } = await execAsync("tailscale status --json");
      const tsStatus = JSON.parse(stdout);

      status.running = true;
      status.authenticated = tsStatus.BackendState === "Running";
      status.hostname = tsStatus.Self?.DNSName?.replace(/\.$/, "");

      // Check funnel capability
      if (status.authenticated) {
        try {
          const { stdout: funnelOut } = await execAsync("tailscale funnel status 2>&1");
          // If we get output without "error" or "not enabled", funnel is available
          status.funnelEnabled = !funnelOut.toLowerCase().includes("not enabled") &&
                                  !funnelOut.toLowerCase().includes("funnel is not available") &&
                                  !funnelOut.toLowerCase().includes("policy does not allow");
        } catch (e) {
          const errorMsg = e instanceof Error ? e.message : String(e);
          // Parse error to determine if it's a policy issue
          if (errorMsg.includes("policy") || errorMsg.includes("not enabled") || errorMsg.includes("not available")) {
            status.funnelEnabled = false;
          } else {
            // Other errors might mean funnel is enabled but no active funnels
            status.funnelEnabled = true;
          }
        }
      }
    } catch (e) {
      const errorMsg = e instanceof Error ? e.message : String(e);

      if (errorMsg.includes("not running") || errorMsg.includes("connection refused")) {
        status.running = false;
      } else if (errorMsg.includes("NeedsLogin") || errorMsg.includes("Logged out")) {
        status.running = true;
        status.authenticated = false;
      } else {
        status.error = errorMsg;
      }
    }

    return status;
  }

  private async guidedInstall(): Promise<void> {
    const platform = process.platform;

    console.log("\n" + "=".repeat(60));
    console.log("  TAILSCALE INSTALLATION REQUIRED");
    console.log("=".repeat(60));
    console.log("\nTailscale provides free, stable public URLs for webhooks.\n");

    if (platform === "darwin") {
      console.log("Install on macOS:");
      console.log("  brew install tailscale");
      console.log("\nOr download from: https://tailscale.com/download/mac");
    } else if (platform === "linux") {
      console.log("Install on Linux:");
      console.log("  curl -fsSL https://tailscale.com/install.sh | sh");
      console.log("\nOr see: https://tailscale.com/download/linux");
    } else if (platform === "win32") {
      console.log("Install on Windows:");
      console.log("  Download from: https://tailscale.com/download/windows");
    } else {
      console.log("Download Tailscale from: https://tailscale.com/download");
    }

    console.log("\nAfter installation, restart this server.");
    console.log("=".repeat(60) + "\n");
  }

  private async startTailscaleDaemon(): Promise<void> {
    const platform = process.platform;

    try {
      if (platform === "darwin") {
        // On macOS, open the Tailscale app
        console.log("[Tailscale] Opening Tailscale app...");
        await execAsync("open -a Tailscale");
        // Wait for daemon to start
        await new Promise(resolve => setTimeout(resolve, 3000));
      } else if (platform === "linux") {
        console.log("[Tailscale] Starting tailscaled service...");
        await execAsync("sudo systemctl start tailscaled");
      }
    } catch (e) {
      console.log("[Tailscale] Could not auto-start daemon.");
      console.log("  macOS: Open the Tailscale app from Applications");
      console.log("  Linux: sudo systemctl start tailscaled");
    }
  }

  private async authenticate(): Promise<void> {
    console.log("\n" + "=".repeat(60));
    console.log("  TAILSCALE AUTHENTICATION");
    console.log("=".repeat(60));
    console.log("\nOpening browser for Tailscale login...\n");

    try {
      // tailscale up will open browser for authentication
      const child = spawn("tailscale", ["up"], {
        stdio: ["ignore", "pipe", "pipe"],
      });

      // Capture output for any auth URLs
      child.stdout?.on("data", (data: Buffer) => {
        const output = data.toString();
        console.log(output);
      });

      child.stderr?.on("data", (data: Buffer) => {
        const output = data.toString();
        if (output.includes("https://")) {
          console.log("\nPlease visit this URL to authenticate:");
          console.log(output);
        }
      });

      // Wait for auth to complete (with timeout)
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          child.kill();
          reject(new Error("Authentication timeout - please run 'tailscale up' manually"));
        }, 120000); // 2 minute timeout

        child.on("close", (code: number | null) => {
          clearTimeout(timeout);
          if (code === 0) {
            console.log("[Tailscale] Authentication successful!");
            resolve();
          } else {
            reject(new Error(`Authentication failed with code ${code}`));
          }
        });
      });
    } catch (e) {
      console.log("\n[Tailscale] Please authenticate manually:");
      console.log("  Run: tailscale up");
      throw e;
    }
  }

  private printFunnelInstructions(): void {
    console.log("\n" + "=".repeat(60));
    console.log("  TAILSCALE FUNNEL SETUP REQUIRED");
    console.log("=".repeat(60));
    console.log("\nFunnel needs to be enabled in your Tailscale admin console.");
    console.log("\n1. Go to: https://login.tailscale.com/admin/acls");
    console.log("\n2. Add this to your ACL policy (in the JSON editor):");
    console.log(`
   "nodeAttrs": [
     {
       "target": ["autogroup:member"],
       "attr": ["funnel"]
     }
   ]
`);
    console.log("3. Save the policy and restart this server.");
    console.log("\nAlternatively, use the policy file template at:");
    console.log("  https://tailscale.com/kb/1223/funnel#prerequisites");
    console.log("=".repeat(60) + "\n");
  }

  private async getHostname(): Promise<string> {
    const envHostname = process.env.TAILSCALE_HOSTNAME;
    if (envHostname) {
      console.log("[Tailscale] Using hostname from TAILSCALE_HOSTNAME env");
      return envHostname;
    }

    const { stdout } = await execAsync("tailscale status --json");
    const status = JSON.parse(stdout);
    const hostname = status.Self?.DNSName?.replace(/\.$/, "");

    if (!hostname) {
      throw new Error("Could not determine Tailscale hostname");
    }

    return hostname;
  }

  /**
   * Read current serve config via LocalAPI to avoid overwriting other paths.
   * Returns the parsed config or null if none exists.
   */
  private async getServeConfig(): Promise<Record<string, any> | null> {
    try {
      const { stdout } = await execAsync("tailscale serve status --json 2>/dev/null");
      const config = JSON.parse(stdout);
      // Empty config check
      if (!config || (Object.keys(config).length === 0)) return null;
      return config;
    } catch {
      return null;
    }
  }

  /**
   * Set serve config by merging our /dc path into the existing config,
   * preserving other paths (e.g. /bcc from better-call-claude).
   *
   * Tailscale serve config structure:
   * {
   *   "TCP": { "443": { "HTTPS": true } },
   *   "Web": { "${hostname}:443": { "Handlers": { "/dc": { "Proxy": "http://127.0.0.1:${port}" } } } },
   *   "AllowFunnel": { "${hostname}:443": true }
   * }
   */
  private async setMergedFunnelConfig(port: number): Promise<void> {
    const hostPort = `${this.hostname}:443`;
    const existing = await this.getServeConfig() || {};

    // Merge TCP
    const tcp = existing.TCP || {};
    tcp["443"] = { HTTPS: true };

    // Merge Web handlers — preserve existing paths, add/update /dc
    const web = existing.Web || {};
    const handlers = web[hostPort]?.Handlers || {};
    handlers["/dc"] = { Proxy: `http://127.0.0.1:${port}` };
    web[hostPort] = { Handlers: handlers };

    // Merge AllowFunnel
    const allowFunnel = existing.AllowFunnel || {};
    allowFunnel[hostPort] = true;

    const merged = { ...existing, TCP: tcp, Web: web, AllowFunnel: allowFunnel };

    // Write config atomically via stdin to avoid shell escaping issues
    const configJson = JSON.stringify(merged);
    await new Promise<void>((resolve, reject) => {
      const child = spawn("tailscale", ["serve", "--set-raw"], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stderr = "";
      child.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
      child.on("close", (code: number | null) => {
        if (code === 0) resolve();
        else reject(new Error(`tailscale serve --set-raw failed (${code}): ${stderr}`));
      });
      child.on("error", reject);
      child.stdin?.write(configJson);
      child.stdin?.end();
    });
  }

  private async enableFunnel(port: number): Promise<void> {
    try {
      // Try merge-aware config first (preserves other paths like /bcc)
      try {
        await this.setMergedFunnelConfig(port);
        console.log("[Tailscale Funnel] Config merged — /dc path set, other paths preserved");
        this.startFunnelHealthCheck(port);
        return;
      } catch (mergeErr) {
        // --set-raw may not be available on older Tailscale versions; fall back to CLI
        const msg = mergeErr instanceof Error ? mergeErr.message : String(mergeErr);
        console.log(`[Tailscale] Merge-aware config failed (${msg}), falling back to CLI...`);
      }

      // Fallback: use --bg --set-path (may overwrite other paths on buggy versions)
      const { stdout, stderr } = await execAsync(`tailscale funnel --bg --set-path=/dc ${port} 2>&1`);
      const output = stdout + stderr;

      if (output.includes("error") && !output.includes("Available on the internet")) {
        throw new Error(output);
      }

      console.log(`[Tailscale Funnel] ${output.trim()}`);
      this.startFunnelHealthCheck(port);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (message.includes("not enabled") || message.includes("policy")) {
        this.printFunnelInstructions();
        throw new Error("Tailscale Funnel not enabled on your tailnet");
      }

      if (message.includes("foreground listener")) {
        console.log("[Tailscale] Foreground listener blocking port 443, killing it...");
        try {
          await execAsync(`pkill -f "tailscale funnel" 2>/dev/null; pkill -f "tailscale serve" 2>/dev/null`).catch(() => {});
          await new Promise(r => setTimeout(r, 2000));
          await this.enableFunnel(port);
          return;
        } catch (retryError) {
          throw new Error(`Failed to start Tailscale Funnel after retry: ${retryError instanceof Error ? retryError.message : retryError}`);
        }
      }

      throw new Error(`Failed to start Tailscale Funnel: ${message}`);
    }
  }

  private startFunnelHealthCheck(port: number): void {
    // Check every 10 seconds that our /dc path is still in the config
    this.healthCheckInterval = setInterval(async () => {
      try {
        const config = await this.getServeConfig();
        const hostPort = `${this.hostname}:443`;
        const hasPath = config?.Web?.[hostPort]?.Handlers?.["/dc"];

        if (!hasPath) {
          console.log("[Tailscale] Health check: /dc path missing, re-merging config...");
          try {
            await this.setMergedFunnelConfig(port);
            console.log("[Tailscale] Config re-merged successfully");
          } catch {
            // Fall back to CLI
            await execAsync(`tailscale funnel --bg --set-path=/dc ${port} 2>&1`);
            console.log("[Tailscale] Funnel restarted via CLI fallback");
          }
        }
      } catch {
        // Silently ignore health check errors
      }
    }, 10_000);
  }

  async stop(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    console.log("[Tailscale] Funnel runs in background - use 'tailscale funnel off' to disable");
  }

  getPublicUrl(): string {
    return this.publicUrl;
  }

  isConnected(): boolean {
    return !!this.publicUrl;
  }
}
