/**
 * Tests for MoltGuard plugin
 */

import { describe, it, expect } from "vitest";
import { resolveConfig, DEFAULT_CONFIG } from "./agent/config.js";
import { shieldAuthArgs } from "./index.js";

// =============================================================================
// Config Tests
// =============================================================================

describe("Config", () => {
  it("should have sensible defaults", () => {
    expect(DEFAULT_CONFIG.sanitizePrompt).toBe(false);
    expect(DEFAULT_CONFIG.blockOnRisk).toBe(true);
    expect(DEFAULT_CONFIG.timeoutMs).toBe(60000);
    expect(DEFAULT_CONFIG.vaultTtlSeconds).toBe(3600);
  });

  it("should resolve partial config with defaults", () => {
    const config = resolveConfig({ blockOnRisk: false });

    expect(config.blockOnRisk).toBe(false); // overridden
    expect(config.sanitizePrompt).toBe(false); // default
  });

  it("should resolve empty config to defaults", () => {
    const config = resolveConfig({});

    expect(config).toEqual(DEFAULT_CONFIG);
  });

  it("should not have chunking options", () => {
    const config = resolveConfig({});

    expect("maxChunkSize" in config).toBe(false);
    expect("overlapSize" in config).toBe(false);
  });

  it("should not have cloud API config fields", () => {
    const config = resolveConfig({});

    expect("apiKey" in config).toBe(false);
    expect("autoRegister" in config).toBe(false);
    expect("apiBaseUrl" in config).toBe(false);
    expect("enabled" in config).toBe(false);
  });
});

// =============================================================================
// shieldAuthArgs Tests
// =============================================================================

describe("shieldAuthArgs", () => {
  it("should shield --account with space-separated value", () => {
    const cmd = "gog gmail messages search \"newer_than:1d\" --max 30 --account user@example.com";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(shielded).toContain("--account");
    expect(restore(shielded)).toBe(cmd);
  });

  it("should shield --account with equals-separated value", () => {
    const cmd = "gog gmail search --account=user@example.com --max 10";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(restore(shielded)).toBe(cmd);
  });

  it("should shield double-quoted --account value", () => {
    const cmd = 'gog gmail search --account "user@example.com" --max 10';
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(restore(shielded)).toBe(cmd);
  });

  it("should shield single-quoted --account value", () => {
    const cmd = "gog gmail search --account 'user@example.com' --max 10";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(restore(shielded)).toBe(cmd);
  });

  it("should shield --client flag value", () => {
    const cmd = "gog gmail search --client my-oauth-client --account user@example.com";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(shielded).not.toContain("my-oauth-client");
    expect(restore(shielded)).toBe(cmd);
  });

  it("should not modify commands without auth flags", () => {
    const cmd = "gog gmail send --to recipient@example.com --subject \"Hi\" --body \"Hello\"";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).toBe(cmd);
    expect(restore(shielded)).toBe(cmd);
  });

  it("should leave non-auth emails untouched for sanitizer to process", () => {
    const cmd = "gog gmail send --to recipient@example.com --account owner@example.com --body \"Hello\"";
    const { shielded } = shieldAuthArgs(cmd);

    // --to email should remain (for the sanitizer to catch)
    expect(shielded).toContain("recipient@example.com");
    // --account email should be shielded
    expect(shielded).not.toContain("owner@example.com");
  });

  it("should handle command with no flags at all", () => {
    const cmd = "curl https://api.example.com/data";
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).toBe(cmd);
    expect(restore(shielded)).toBe(cmd);
  });

  it("should handle --account=quoted value", () => {
    const cmd = 'gog gmail search --account="user@example.com"';
    const { shielded, restore } = shieldAuthArgs(cmd);

    expect(shielded).not.toContain("user@example.com");
    expect(restore(shielded)).toBe(cmd);
  });
});
