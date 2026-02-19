/**
 * TokenVault — Persistent, session-scoped reversible tokenization store.
 *
 * Wraps MoltGuard's existing MappingTable with a durable backing store
 * (SQLite) so that token mappings survive process restarts and remain
 * consistent across multi-turn API conversations.
 *
 * IRC Section 7216 compliance:
 *   - The vault file MUST reside on the local filesystem (single-tenant).
 *   - The "key" (plaintext PII → token mapping) never leaves the machine.
 *   - TTL-based expiry ensures data minimization.
 *   - Audit columns track creation/access for compliance review.
 *
 * Integration: This class is designed to replace the bare `Map<string, string>`
 * used as `MappingTable` in gateway/sanitizer.ts and index.ts, without changing
 * the sanitize() or restore() call signatures.
 */

import type { MappingTable } from "./types.js";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

// =============================================================================
// Types
// =============================================================================

export type TokenVaultConfig = {
  /** Directory for the vault database file. Defaults to ~/.moltguard/ */
  vaultDir?: string;
  /** TTL in seconds for vault entries. Defaults to 3600 (1 hour). */
  ttlSeconds?: number;
  /** How often to purge expired entries, in seconds. Defaults to 300 (5 min). */
  purgeIntervalSeconds?: number;
  /** Maximum number of entries before LRU eviction kicks in. Defaults to 10000. */
  maxEntries?: number;
};

type VaultEntry = {
  token: string;        // e.g. "[ssn_1]"
  originalValue: string; // the PII
  category: string;      // e.g. "ssn"
  sessionId: string;     // scopes tokens to a conversation session
  createdAt: number;     // epoch ms
  lastAccessedAt: number;
  expiresAt: number;     // epoch ms
};

// =============================================================================
// TokenVault (JSON-file backed — no native dependency required)
// =============================================================================

/**
 * A lightweight persistent vault backed by a JSON file.
 *
 * For production deployments needing higher throughput, this can be swapped
 * for better-sqlite3 or Redis without changing the public API.
 */
export class TokenVault {
  private vaultPath: string;
  private ttlMs: number;
  private maxEntries: number;
  private entries: Map<string, VaultEntry>; // keyed by `${sessionId}::${token}`
  private reverseIndex: Map<string, string>; // `${sessionId}::${originalValue}` → token
  private purgeTimer: ReturnType<typeof setInterval> | null = null;
  private dirty = false;

  constructor(config: TokenVaultConfig = {}) {
    const vaultDir = config.vaultDir ?? path.join(
      process.env.HOME ?? process.env.USERPROFILE ?? "/tmp",
      ".moltguard",
    );
    this.ttlMs = (config.ttlSeconds ?? 3600) * 1000;
    this.maxEntries = config.maxEntries ?? 10_000;
    this.vaultPath = path.join(vaultDir, "token-vault.json");

    // Ensure directory exists
    if (!fs.existsSync(vaultDir)) {
      fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
    }

    // Load existing entries
    this.entries = new Map();
    this.reverseIndex = new Map();
    this._loadFromDisk();

    // Schedule periodic purge
    const purgeMs = (config.purgeIntervalSeconds ?? 300) * 1000;
    this.purgeTimer = setInterval(() => this.purgeExpired(), purgeMs);
    // Don't keep the process alive just for purging
    if (this.purgeTimer.unref) this.purgeTimer.unref();
  }

  // ===========================================================================
  // Core API
  // ===========================================================================

  /**
   * Create a session-scoped MappingTable proxy that reads/writes through
   * the vault. This is the primary integration point — pass the returned
   * Map to sanitize() and restore() exactly as before.
   *
   * Usage:
   *   const vault = new TokenVault();
   *   const sessionId = vault.createSession();
   *   const { mappingTable, categoryCounters } = vault.getSessionState(sessionId);
   *   const result = sanitize(content, { mappingTable, categoryCounters });
   *   // ... send to DeepSeek ...
   *   const restored = restore(response, mappingTable);
   */
  createSession(): string {
    return crypto.randomUUID();
  }

  /**
   * Returns a MappingTable (Map<string, string>) backed by the vault
   * for the given session. Reads are served from the in-memory cache;
   * writes persist to disk.
   *
   * Also returns categoryCounters so placeholder numbering is consistent
   * across calls within the same session.
   */
  getSessionState(sessionId: string): {
    mappingTable: MappingTable;
    categoryCounters: Map<string, number>;
  } {
    const mappingTable = this._createProxiedMap(sessionId);
    const categoryCounters = this._rebuildCategoryCounters(sessionId);
    return { mappingTable, categoryCounters };
  }

  /**
   * Look up the original value for a token within a session.
   * Returns undefined if expired or not found.
   */
  resolve(sessionId: string, token: string): string | undefined {
    const key = `${sessionId}::${token}`;
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.entries.delete(key);
      this.reverseIndex.delete(`${sessionId}::${entry.originalValue}`);
      this._scheduleSave();
      return undefined;
    }
    // Update last accessed
    entry.lastAccessedAt = Date.now();
    this._scheduleSave();
    return entry.originalValue;
  }

  /**
   * Store a token ↔ original value mapping.
   * If the same originalValue was already tokenized in this session,
   * returns the existing token (idempotent).
   */
  store(
    sessionId: string,
    token: string,
    originalValue: string,
    category: string,
  ): string {
    // Check if this value already has a token in this session
    const reverseKey = `${sessionId}::${originalValue}`;
    const existingToken = this.reverseIndex.get(reverseKey);
    if (existingToken) {
      // Touch the existing entry
      const key = `${sessionId}::${existingToken}`;
      const entry = this.entries.get(key);
      if (entry && Date.now() <= entry.expiresAt) {
        entry.lastAccessedAt = Date.now();
        this._scheduleSave();
        return existingToken;
      }
    }

    // LRU eviction: if at capacity, remove the least-recently-accessed entry
    if (this.entries.size >= this.maxEntries) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      for (const [k, e] of this.entries) {
        if (e.lastAccessedAt < oldestTime) {
          oldestTime = e.lastAccessedAt;
          oldestKey = k;
        }
      }
      if (oldestKey) {
        const evicted = this.entries.get(oldestKey)!;
        this.entries.delete(oldestKey);
        this.reverseIndex.delete(`${evicted.sessionId}::${evicted.originalValue}`);
      }
    }

    const now = Date.now();
    const key = `${sessionId}::${token}`;
    const entry: VaultEntry = {
      token,
      originalValue,
      category,
      sessionId,
      createdAt: now,
      lastAccessedAt: now,
      expiresAt: now + this.ttlMs,
    };

    this.entries.set(key, entry);
    this.reverseIndex.set(reverseKey, token);
    this._scheduleSave();
    return token;
  }

  /**
   * Purge all expired entries (called periodically and on load).
   */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [key, entry] of this.entries) {
      if (now > entry.expiresAt) {
        this.entries.delete(key);
        this.reverseIndex.delete(`${entry.sessionId}::${entry.originalValue}`);
        purged++;
      }
    }
    if (purged > 0) this._scheduleSave();
    return purged;
  }

  /**
   * Destroy a session and all its entries (e.g., on session_end).
   */
  destroySession(sessionId: string): number {
    let destroyed = 0;
    for (const [key, entry] of this.entries) {
      if (entry.sessionId === sessionId) {
        this.entries.delete(key);
        this.reverseIndex.delete(`${sessionId}::${entry.originalValue}`);
        destroyed++;
      }
    }
    if (destroyed > 0) this._scheduleSave();
    return destroyed;
  }

  /**
   * Graceful shutdown — flush pending writes, stop purge timer.
   */
  close(): void {
    if (this.purgeTimer) {
      clearInterval(this.purgeTimer);
      this.purgeTimer = null;
    }
    if (this._saveTimeout) {
      clearTimeout(this._saveTimeout);
      this._saveTimeout = null;
    }
    if (this.dirty) {
      this._saveToDisk();
    }
  }

  // ===========================================================================
  // Internal: Proxied MappingTable
  // ===========================================================================

  /**
   * Create a Map<string, string> that transparently reads/writes through
   * the vault for a given session. This allows the existing sanitize()/restore()
   * functions to work without any signature changes.
   */
  private _seedBaseMap(baseMap: Map<string, string>, sessionId: string): void {
    for (const [key, entry] of this.entries) {
      if (entry.sessionId === sessionId && Date.now() <= entry.expiresAt) {
        if (!baseMap.has(entry.token)) {
          baseMap.set(entry.token, entry.originalValue);
        }
      }
    }
  }

  private _createProxiedMap(sessionId: string): MappingTable {
    const vault = this;

    // Seed the map with all non-expired entries for this session
    const baseMap = new Map<string, string>();
    vault._seedBaseMap(baseMap, sessionId);

    // Return a Proxy that intercepts mutations and iterations
    return new Proxy(baseMap, {
      get(target, prop) {
        if (prop === "set") {
          return function (token: string, originalValue: string) {
            // Infer category from token format: [category_N]
            const categoryMatch = token.match(/^\[(.+?)_\d+\]$/);
            const category = categoryMatch?.[1] ?? "unknown";
            vault.store(sessionId, token, originalValue, category);
            return target.set(token, originalValue);
          };
        }
        if (prop === "get") {
          return function (token: string) {
            // Try in-memory first, then vault
            const local = target.get(token);
            if (local !== undefined) return local;
            return vault.resolve(sessionId, token);
          };
        }
        if (prop === "has") {
          return function (token: string) {
            return target.has(token) || vault.resolve(sessionId, token) !== undefined;
          };
        }
        if (prop === "delete") {
          return function (token: string) {
            const entryKey = `${sessionId}::${token}`;
            const entry = vault.entries.get(entryKey);
            if (entry) {
              vault.entries.delete(entryKey);
              vault.reverseIndex.delete(`${sessionId}::${entry.originalValue}`);
              vault._scheduleSave();
            }
            return target.delete(token);
          };
        }
        if (prop === "forEach") {
          return function (
            callbackfn: (value: string, key: string, map: Map<string, string>) => void,
            thisArg?: any,
          ) {
            vault._seedBaseMap(target, sessionId);
            return target.forEach(callbackfn, thisArg);
          };
        }
        if (prop === Symbol.iterator || prop === "entries") {
          return function () {
            vault._seedBaseMap(target, sessionId);
            return target[Symbol.iterator]();
          };
        }
        if (prop === "keys") {
          return function () {
            vault._seedBaseMap(target, sessionId);
            return target.keys();
          };
        }
        if (prop === "values") {
          return function () {
            vault._seedBaseMap(target, sessionId);
            return target.values();
          };
        }
        const value = Reflect.get(target, prop, target);
        if (typeof value === "function") {
          return value.bind(target);
        }
        return value;
      },
    });
  }

  /**
   * Rebuild categoryCounters from existing vault entries for a session.
   * This ensures placeholder numbering continues where it left off
   * across process restarts.
   */
  private _rebuildCategoryCounters(sessionId: string): Map<string, number> {
    const counters = new Map<string, number>();
    for (const [key, entry] of this.entries) {
      if (entry.sessionId !== sessionId) continue;
      if (Date.now() > entry.expiresAt) continue;
      const current = counters.get(entry.category) ?? 0;
      // Extract the number from the token: [category_N]
      const numMatch = entry.token.match(/_(\d+)\]$/);
      const num = numMatch ? parseInt(numMatch[1], 10) : 0;
      if (num > current) {
        counters.set(entry.category, num);
      }
    }
    return counters;
  }

  // ===========================================================================
  // Internal: Persistence
  // ===========================================================================

  private _loadFromDisk(): void {
    try {
      if (!fs.existsSync(this.vaultPath)) return;
      const raw = fs.readFileSync(this.vaultPath, "utf-8");
      const entries: VaultEntry[] = JSON.parse(raw);
      const now = Date.now();
      for (const entry of entries) {
        if (now > entry.expiresAt) continue; // Skip expired on load
        const key = `${entry.sessionId}::${entry.token}`;
        this.entries.set(key, entry);
        this.reverseIndex.set(`${entry.sessionId}::${entry.originalValue}`, entry.token);
      }
    } catch {
      // Corrupt or missing file — start fresh
    }
  }

  private _saveToDisk(): void {
    try {
      const entries = Array.from(this.entries.values());
      const tmpPath = this.vaultPath + ".tmp";
      fs.writeFileSync(tmpPath, JSON.stringify(entries, null, 0), {
        encoding: "utf-8",
        mode: 0o600, // Owner-only read/write — PII file
      });
      fs.renameSync(tmpPath, this.vaultPath); // Atomic replace
      this.dirty = false;
    } catch (err) {
      // Log but don't crash — in-memory still works
      console.error("[token-vault] Failed to persist vault:", err);
    }
  }

  private _saveTimeout: ReturnType<typeof setTimeout> | null = null;

  private _scheduleSave(): void {
    this.dirty = true;
    // Debounce: batch rapid writes into a single disk flush
    if (this._saveTimeout) return;
    this._saveTimeout = setTimeout(() => {
      this._saveTimeout = null;
      this._saveToDisk();
    }, 100);
    if (this._saveTimeout.unref) this._saveTimeout.unref();
  }
}
