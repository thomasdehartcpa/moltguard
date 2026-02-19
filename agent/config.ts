/**
 * MoltGuard configuration
 */

import path from "node:path";
import os from "node:os";

// =============================================================================
// Configuration Types
// =============================================================================

export type OpenClawGuardConfig = {
  sanitizePrompt?: boolean;
  gatewayPort?: number;
  gatewayAutoStart?: boolean;
  blockOnRisk?: boolean;
  timeoutMs?: number;
  logPath?: string;
  /** TTL in seconds for token vault entries. Defaults to 3600 (1 hour). */
  vaultTtlSeconds?: number;
};

// =============================================================================
// Logger Type
// =============================================================================

export type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug?: (msg: string) => void;
};

// =============================================================================
// Default Configuration
// =============================================================================

export const DEFAULT_CONFIG: Required<OpenClawGuardConfig> = {
  sanitizePrompt: false,
  gatewayPort: 8900,
  gatewayAutoStart: true,
  blockOnRisk: true,
  timeoutMs: 60000,
  logPath: path.join(os.homedir(), ".openclaw", "logs"),
  vaultTtlSeconds: 3600,
};

// =============================================================================
// Configuration Helpers
// =============================================================================

export function resolveConfig(config?: Partial<OpenClawGuardConfig>): Required<OpenClawGuardConfig> {
  return {
    sanitizePrompt: config?.sanitizePrompt ?? DEFAULT_CONFIG.sanitizePrompt,
    gatewayPort: config?.gatewayPort ?? DEFAULT_CONFIG.gatewayPort,
    gatewayAutoStart: config?.gatewayAutoStart ?? DEFAULT_CONFIG.gatewayAutoStart,
    blockOnRisk: config?.blockOnRisk ?? DEFAULT_CONFIG.blockOnRisk,
    timeoutMs: config?.timeoutMs ?? DEFAULT_CONFIG.timeoutMs,
    logPath: config?.logPath ?? DEFAULT_CONFIG.logPath,
    vaultTtlSeconds: config?.vaultTtlSeconds ?? DEFAULT_CONFIG.vaultTtlSeconds,
  };
}
