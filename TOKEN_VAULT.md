# TokenVault: Reversible Tokenization Architecture

## Background

MoltGuard v6.0 introduced a local HTTP gateway that sanitizes PII before it reaches LLM APIs and restores it in responses. The original implementation used ephemeral `Map<string, string>` instances (one per HTTP request) as the mapping table between placeholders and original values. This worked for single request/response cycles but had three limitations:

1. **No cross-turn consistency**: In multi-turn conversations, the same PII could receive different placeholder numbers across requests (e.g., "John Smith" might be `[person_1]` in turn 1 but `[person_3]` in turn 2 if new entities appeared earlier in the conversation history).

2. **No crash resilience**: If the gateway process restarted mid-conversation, all mappings were lost.

3. **No data minimization**: The plugin-level `SanitizationState` accumulated PII indefinitely in memory with no TTL or cleanup.

## Architecture

TokenVault replaces bare `Map` instances with a persistent, session-scoped store that provides consistent tokenization across the lifecycle of a conversation.

```
                      ┌─────────────────────────────────────────────┐
                      │                TokenVault                    │
                      │                                             │
  sanitize() ───────▶ │  Proxy'd Map                                │
    (unchanged API)   │    │                                        │
                      │    ├── .set(token, pii)  ──▶  store()       │
                      │    ├── .get(token)        ──▶  resolve()    │
                      │    └── .has(token)        ──▶  resolve()    │
                      │                                             │
  restore()  ───────▶ │  (reads from same Map)                      │
    (unchanged API)   │                                             │
                      │  Persistence ──▶ ~/.moltguard/token-vault.json │
                      │  TTL ──────────▶ configurable (default 1h)  │
                      │  Purge ────────▶ periodic (default 5 min)   │
                      └─────────────────────────────────────────────┘
```

### Key design decision: Proxy'd Map

The vault returns a `Proxy`-wrapped `Map<string, string>` that is type-compatible with `MappingTable`. This means `sanitize()` and `restore()` required **zero signature changes** — they still accept a plain Map. The Proxy intercepts `.set()` calls to persist entries to the vault and `.get()` calls to check the vault for entries not yet in the local Map.

### Session scoping

Each conversation gets a unique session ID (UUID). Entries are keyed internally as `${sessionId}::${token}`, providing full isolation between concurrent sessions. The vault also maintains a reverse index (`${sessionId}::${originalValue}` -> token) for idempotency — the same PII value always receives the same placeholder number within a session.

## Integration points

### Gateway handlers (`gateway/handlers/*.ts`)

Each handler accepts a `vault: TokenVault` parameter and extracts the session from the `x-moltguard-session` HTTP header:

```typescript
const headerSession = req.headers["x-moltguard-session"] as string | undefined;
const sessionId = headerSession ?? vault.createSession();
const ephemeral = !headerSession;

const { mappingTable, categoryCounters } = vault.getSessionState(sessionId);
const { sanitized } = sanitize(requestData, { mappingTable, categoryCounters });

// ... forward to API, restore response ...

// Cleanup: ephemeral sessions are destroyed after the response
if (ephemeral) vault.destroySession(sessionId);
```

When no session header is provided, behavior is identical to pre-vault: a fresh session is created and destroyed per request. When a session header IS provided, mappings persist and accumulate across requests.

### Plugin hooks (`index.ts`)

The plugin creates a vault instance at registration time and lazily initializes a session on the first tool call that requires sanitization:

```
register()
  └── new TokenVault({ ttlSeconds: config.vaultTtlSeconds })

before_tool_call (first call)
  └── vault.createSession()
  └── vault.getSessionState(sessionId)

before_tool_call (subsequent)
  └── reuses existing session state

tool_result_persist
  └── restore(message, mappingTable)  // reads from vault-backed Map

session_end
  └── vault.destroySession(sessionId)
  └── reset session state to null

unregister()
  └── vault.close()
```

### Gateway entry point (`gateway/index.ts`)

A single vault instance is created in `startGateway()` and shared across all handlers. It is closed on SIGINT/SIGTERM.

## Files

| File | Role |
|------|------|
| `gateway/token-vault.ts` | TokenVault class — persistence, session management, TTL, Proxy'd Map |
| `gateway/handlers/openai.ts` | OpenAI handler — vault integration |
| `gateway/handlers/anthropic.ts` | Anthropic handler — vault integration |
| `gateway/handlers/gemini.ts` | Gemini handler — vault integration |
| `gateway/index.ts` | Gateway entry — vault singleton, shutdown cleanup |
| `index.ts` | Plugin — vault-backed session lifecycle in hooks |
| `agent/config.ts` | Config type and defaults — `vaultTtlSeconds: 3600` |

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `vaultTtlSeconds` | `3600` | TTL for vault entries in seconds. After this period, entries are purged automatically. Set lower for stricter data minimization. |

The vault file itself is stored at `~/.moltguard/token-vault.json` with permissions `0o600` (owner-only read/write). The directory is created with `0o700`.

## IRC Section 7216 compliance

The vault maintains the following compliance posture:

- **Single-tenant**: The vault file never leaves the local filesystem. Only tokenized placeholders cross the wire to LLM APIs.
- **No cloud endpoints**: MoltGuard is entirely local software. No data is sent to any MoltGuard server or third-party service beyond the configured LLM API backends.
- **Data minimization**: TTL-based expiry ensures PII is not retained beyond the configured window. `destroySession()` provides explicit cleanup.
- **No PII in logs**: Plugin logs record only metadata (category names, redaction counts, session IDs). Raw PII values are never logged.
- **Crash safety**: Writes use atomic rename (write to `.tmp`, then `rename()`). Corrupted files are discarded on load (start fresh).

## Session header protocol

Clients that want cross-request token consistency should send:

```
x-moltguard-session: <uuid>
```

on every request in the same conversation. The UUID should be generated once per conversation and reused for all turns. When the conversation ends, the client can stop sending the header — the vault's TTL will eventually purge the entries, or the client can explicitly start a new session with a new UUID.

If the header is omitted, the gateway falls back to ephemeral per-request sessions (backwards compatible with pre-vault behavior).

## Persistence format

The vault file is a JSON array of entry objects:

```json
[
  {
    "token": "[ssn_1]",
    "originalValue": "123-45-6789",
    "category": "ssn",
    "sessionId": "a1b2c3d4-...",
    "createdAt": 1708200000000,
    "lastAccessedAt": 1708200060000,
    "expiresAt": 1708203600000
  }
]
```

Writes are debounced (100ms) to batch rapid insertions into a single disk flush.

## Future considerations

- **SQLite backend**: For deployments needing concurrent access or higher throughput, the JSON persistence layer can be swapped for `better-sqlite3` without changing the public API (`createSession`, `getSessionState`, `destroySession`, `close`).
- **Encryption at rest**: The vault file contains plaintext PII. For environments requiring encryption at rest, the `_saveToDisk`/`_loadFromDisk` methods can be wrapped with symmetric encryption (e.g., AES-256-GCM with a key derived from a machine-local secret).
