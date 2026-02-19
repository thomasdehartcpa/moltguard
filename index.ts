/**
 * MoltGuard - Local PII Sanitization Gateway Plugin
 *
 * Sanitizes PII in tool calls and API requests before they leave
 * the local machine. All processing is local — no data is sent
 * to any MoltGuard cloud endpoint.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import type { OpenClawGuardConfig, Logger } from "./agent/config.js";
import { resolveConfig } from "./agent/config.js";
import { GatewayManager } from "./gateway-manager.js";
import { sanitize } from "./gateway/sanitizer.js";
import type { SanitizationState } from "./gateway/sanitizer.js";
import type { MappingTable } from "./gateway/types.js";
import { restore } from "./gateway/restorer.js";
import { TokenVault } from "./gateway/token-vault.js";

// =============================================================================
// Constants
// =============================================================================

const PLUGIN_ID = "moltguard";
const PLUGIN_NAME = "MoltGuard";
const LOG_PREFIX = `[${PLUGIN_ID}]`;

// =============================================================================
// Tool-Call Sanitization Helpers
// =============================================================================

/** External-facing CLI commands that send data off-machine */
const EXTERNAL_CMDS = ["curl", "gog", "wget", "http", "httpie", "ssh", "scp", "sftp", "rsync"];
const EXTERNAL_CMD_RE = new RegExp(`\\b(${EXTERNAL_CMDS.join("|")})\\b`);

/**
 * Detect whether a Bash command sends data to an external service.
 * Checks for external CLI tools anywhere in the command string — covers:
 * - Direct invocation: `curl ...`
 * - Chained commands: `cd /tmp && gog gmail send ...`
 * - Piped commands: `echo x | curl -d @- ...`
 * - Subshells: `$(curl ...)` and backticks
 * - Wrappers: `env X=y gog ...`, `bash -c "curl ..."`, `nohup curl ...`
 */
function isExternalBashCommand(command: string): boolean {
  return EXTERNAL_CMD_RE.test(command);
}

/**
 * CLI flags whose values are local credential lookups, not outbound PII.
 * These are used by tools like `gog` to select which OAuth token to use
 * and must not be sanitized — doing so breaks authentication.
 */
const AUTH_FLAGS = ["--account", "--client"];

/**
 * Temporarily shield auth-related flag values from sanitization.
 *
 * Replaces `--account user@example.com` (and `--account=...`, quoted forms)
 * with inert markers that the sanitizer will ignore, then returns a restore
 * function to swap the originals back into the sanitized output.
 */
export function shieldAuthArgs(command: string): {
  shielded: string;
  restore: (s: string) => string;
} {
  const replacements: Array<{ marker: string; original: string }> = [];
  let shielded = command;

  for (const flag of AUTH_FLAGS) {
    // Match --flag=value or --flag <space> value
    // Value can be double-quoted, single-quoted, or bare (non-whitespace)
    const escaped = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(
      `(${escaped})(?:(=)("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\\S+)|(\\s+)("(?:[^"\\\\]|\\\\.)*"|'(?:[^'\\\\]|\\\\.)*'|\\S+))`,
      "g",
    );
    shielded = shielded.replace(pattern, (_match, flagName, eq, eqVal, sp, spVal) => {
      const value = eq ? eqVal : spVal;
      const sep = eq ? eq : sp;
      const marker = `__MOLTGUARD_AUTH_${replacements.length}__`;
      replacements.push({ marker, original: value });
      return `${flagName}${sep}${marker}`;
    });
  }

  return {
    shielded,
    restore: (s: string) => {
      let result = s;
      for (const { marker, original } of replacements) {
        result = result.split(marker).join(original);
      }
      return result;
    },
  };
}

/**
 * Replace placeholders in a tool result message with original values.
 * Handles the various message content formats (string, array of content blocks, etc.)
 */
function restoreMessageContent(message: unknown, mappingTable: MappingTable): unknown {
  if (!message || typeof message !== "object" || mappingTable.size === 0) {
    return message;
  }
  return restore(message, mappingTable);
}

// =============================================================================
// Logger
// =============================================================================

function createLogger(baseLogger: Logger): Logger {
  return {
    info: (msg: string) => baseLogger.info(`${LOG_PREFIX} ${msg}`),
    warn: (msg: string) => baseLogger.warn(`${LOG_PREFIX} ${msg}`),
    error: (msg: string) => baseLogger.error(`${LOG_PREFIX} ${msg}`),
    debug: (msg: string) => baseLogger.debug?.(`${LOG_PREFIX} ${msg}`),
  };
}

// =============================================================================
// Plugin Definition
// =============================================================================

// Store gateway manager and vault instances for cleanup (closure variables)
let globalGatewayManager: GatewayManager | null = null;
let globalVault: TokenVault | null = null;

const openClawGuardPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  description:
    "Local PII sanitization gateway powered by MoltGuard",

  register(api: OpenClawPluginApi) {
    const pluginConfig = (api.pluginConfig ?? {}) as OpenClawGuardConfig;
    const config = resolveConfig(pluginConfig);
    const log = createLogger(api.logger);

    if (!config.sanitizePrompt) {
      log.info("Plugin disabled via config (sanitizePrompt is false)");
      return;
    }

    // Initialize gateway
    globalGatewayManager = new GatewayManager(
      {
        port: config.gatewayPort || 8900,
        autoStart: config.gatewayAutoStart ?? true,
      },
      log,
    );

    // Start gateway
    globalGatewayManager.start().catch((error) => {
      log.error(`Failed to start gateway: ${error}`);
    });

    log.info(`Gateway enabled on port ${config.gatewayPort || 8900}`);
    log.info(
      `Configure your model to use: http://127.0.0.1:${config.gatewayPort || 8900}`
    );

    // =========================================================================
    // Tool-Call PII Sanitization (before_tool_call + result restoration)
    // ALWAYS active — independent of gateway proxy.
    // Even without the gateway proxy, tool calls must be sanitized because
    // they send data to external services (Gmail, Notion, web search, etc.)
    // =========================================================================

    // Vault-backed sanitization state: accumulates mappings across tool calls
    // so the same PII value always gets the same placeholder within a session.
    // Session is created lazily on the first tool call that requires sanitization.
    globalVault = new TokenVault({ ttlSeconds: config.vaultTtlSeconds });
    let currentSessionId: string | null = null;
    let sanitizationState: SanitizationState | null = null;
    let toolCallSanitizationCount = 0;

    function ensureSession(): SanitizationState {
      if (!sanitizationState) {
        currentSessionId = globalVault!.createSession();
        sanitizationState = globalVault!.getSessionState(currentSessionId);
        log.info(`Vault session created: ${currentSessionId}`);
      }
      return sanitizationState;
    }

    // --- before_tool_call: sanitize outbound params ---
    api.on("before_tool_call", (event, ctx) => {
      const { toolName, params } = event;

      // Determine if this tool call is external-facing
      let shouldSanitize = false;
      let isBashCommand = false;

      if (toolName === "Bash" || toolName === "bash") {
        const command = params.command as string | undefined;
        if (command && isExternalBashCommand(command)) {
          shouldSanitize = true;
          isBashCommand = true;
        }
      } else if (toolName === "WebSearch" || toolName === "web_search") {
        shouldSanitize = true;
      } else if (toolName === "WebFetch" || toolName === "web_fetch") {
        shouldSanitize = true;
      }

      if (!shouldSanitize) return;

      // Shield auth-related flag values (--account, --client) from
      // sanitization. These are local credential lookups, not outbound PII.
      let restoreAuth: ((s: string) => string) | null = null;
      const paramsToSanitize = { ...params };
      if (isBashCommand && typeof paramsToSanitize.command === "string") {
        const { shielded, restore: restoreFn } = shieldAuthArgs(paramsToSanitize.command);
        paramsToSanitize.command = shielded;
        restoreAuth = restoreFn;
      }

      const state = ensureSession();
      const { sanitized: sanitizedParams, redactionCount, redactionsByCategory } =
        sanitize(paramsToSanitize, state);

      // Restore shielded auth arguments in the sanitized command
      if (restoreAuth && typeof sanitizedParams.command === "string") {
        sanitizedParams.command = restoreAuth(sanitizedParams.command);
      }

      if (redactionCount > 0) {
        toolCallSanitizationCount++;
        const cats = Object.entries(redactionsByCategory)
          .map(([k, v]) => `${k}=${v}`)
          .join(", ");
        log.warn(
          `Tool call sanitized: ${toolName} — ${redactionCount} redactions (${cats})`,
        );
        return { params: sanitizedParams };
      }

      return;
    });

    // --- tool_result_persist: restore placeholders in results ---
    api.on("tool_result_persist", (event, _ctx) => {
      if (!sanitizationState || sanitizationState.mappingTable.size === 0) return;

      const restored = restoreMessageContent(event.message, sanitizationState.mappingTable);
      if (restored !== event.message) {
        return { message: restored as typeof event.message };
      }
      return;
    }, { priority: 10 });

    // --- session_end: log sanitization summary and destroy vault session ---
    api.on("session_end", (_event, _ctx) => {
      if (toolCallSanitizationCount > 0) {
        log.info(
          `Session summary: ${toolCallSanitizationCount} tool calls sanitized, ` +
          `${sanitizationState?.mappingTable.size ?? 0} unique PII items tracked`,
        );
      }
      if (currentSessionId && globalVault) {
        const destroyed = globalVault.destroySession(currentSessionId);
        log.info(`Vault session destroyed: ${currentSessionId} (${destroyed} entries purged)`);
        currentSessionId = null;
        sanitizationState = null;
      }
    });

    log.info("Tool-call PII sanitization enabled (before_tool_call hook active)");

    // Register gateway management commands
    if (globalGatewayManager) {
      api.registerCommand({
        name: "mg_status",
        description: "Show MoltGuard gateway status",
        requireAuth: true,
        handler: async () => {
          const status = globalGatewayManager!.getStatus();
          const lines = [
            "**MoltGuard Gateway Status**",
            "",
            `- Running: ${status.running ? "✓ Yes" : "✗ No"}`,
            `- Ready: ${status.ready ? "✓ Yes" : "✗ No"}`,
            `- Port: ${status.port}`,
            `- Endpoint: http://127.0.0.1:${status.port}`,
            "",
            "**Configuration**",
            "To use the gateway, configure your model provider:",
            "```json",
            `{`,
            `  "models": {`,
            `    "providers": {`,
            `      "moltguard-protected": {`,
            `        "baseUrl": "http://127.0.0.1:${status.port}",`,
            `        "api": "anthropic-messages",  // or "openai-completions"`,
            `        "apiKey": "\${ANTHROPIC_API_KEY}"`,
            `      }`,
            `    }`,
            `  }`,
            `}`,
            "```",
          ];
          return { text: lines.join("\n") };
        },
      });

      api.registerCommand({
        name: "mg_start",
        description: "Start the MoltGuard gateway",
        requireAuth: true,
        handler: async () => {
          try {
            await globalGatewayManager!.start();
            return { text: "Gateway started successfully" };
          } catch (error) {
            return {
              text: `Failed to start gateway: ${error instanceof Error ? error.message : String(error)}`,
            };
          }
        },
      });

      api.registerCommand({
        name: "mg_stop",
        description: "Stop the MoltGuard gateway",
        requireAuth: true,
        handler: async () => {
          try {
            await globalGatewayManager!.stop();
            return { text: "Gateway stopped" };
          } catch (error) {
            return {
              text: `Failed to stop gateway: ${error instanceof Error ? error.message : String(error)}`,
            };
          }
        },
      });

      api.registerCommand({
        name: "mg_restart",
        description: "Restart the MoltGuard gateway",
        requireAuth: true,
        handler: async () => {
          try {
            await globalGatewayManager!.restart();
            return { text: "Gateway restarted successfully" };
          } catch (error) {
            return {
              text: `Failed to restart gateway: ${error instanceof Error ? error.message : String(error)}`,
            };
          }
        },
      });
    }
  },

  // Cleanup: stop gateway and close vault when plugin unloads
  async unregister() {
    if (globalVault) {
      try {
        globalVault.close();
      } catch (error) {
        console.error("[moltguard] Failed to close vault during cleanup:", error);
      }
      globalVault = null;
    }
    if (globalGatewayManager) {
      try {
        await globalGatewayManager.stop();
      } catch (error) {
        console.error("[moltguard] Failed to stop gateway during cleanup:", error);
      }
    }
  },
};

export default openClawGuardPlugin;
