# moltguard-src — MoltGuard OpenClaw Plugin

MoltGuard is a local PII sanitization plugin for OpenClaw. It intercepts AI conversations before they leave the machine, replaces sensitive data with numbered placeholders, forwards sanitized content to third-party LLMs, then restores the original values in the response — so conversations appear natural in Telegram while taxpayer PII is never transmitted to external servers.

## Why This Exists

Thomas is a CPA. Client data (SSNs, EINs, income figures, names) passes through AI conversations. IRC Section 7216 prohibits unauthorized disclosure of taxpayer information. MoltGuard enforces this at the transport layer — all processing is local, no data reaches any MoltGuard cloud endpoint.

## Core Data Flow

```
Abel / User message
        ↓
  sanitize()          ← replaces PII with [person_1], [ssn_1], etc.
        ↓
  TokenVault.store()  ← persists the token ↔ original mapping to disk
        ↓
  LLM API (DeepSeek, Claude, Gemini)  ← never sees real PII
        ↓
  LLM response with placeholders
        ↓
  restore()           ← swaps placeholders back to original values
        ↓
  Telegram / UI       ← response appears natural with real names/numbers
```

## The Token Vault (Key Feature)

`gateway/token-vault.ts` is the core custom component. It wraps the in-memory `MappingTable` (a `Map<string, string>`) with a persistent JSON-file backend at `~/.moltguard/token-vault.json`.

**Why it matters:** Without persistence, placeholders like `[person_1]` can't be resolved after a process restart. The vault ensures the same PII value always gets the same placeholder within a session, and that mappings survive restarts so multi-turn conversations remain coherent.

**How it works:**
- Session-scoped: each conversation gets a UUID session ID; mappings are keyed as `{sessionId}::{token}`
- Idempotent: the same PII value always returns the same token within a session
- Persisted: writes are debounced and flushed atomically to `token-vault.json` (mode 0600 — owner only)
- TTL: entries expire after 1 hour by default; purged periodically and on load
- LRU eviction: kicks in at 10,000 entries max
- Proxied Map: presents a standard `Map<string, string>` interface so existing `sanitize()` and `restore()` signatures are unchanged
- Destroyed on `session_end`: vault entries are purged when the OpenClaw session closes

## Two Sanitization Layers

### 1. Gateway Proxy (port 8900)
An HTTP proxy server that sits between OpenClaw and third-party LLM APIs. OpenClaw is configured to route Claude Haiku requests through `http://127.0.0.1:8900` instead of directly to Anthropic. The gateway:
- Intercepts the full message body
- Sanitizes it before forwarding to the real API
- Restores placeholders in the streaming/non-streaming response
- Handles Anthropic, OpenAI, and Gemini API formats (`gateway/handlers/`)

### 2. Tool-Call Sanitization (`before_tool_call` hook)
Active even without the gateway — catches data going to external services via tool calls:
- **Bash commands** containing `curl`, `gog`, `wget`, `http`, `ssh`, etc.
- **WebSearch** queries
- **WebFetch** URLs/bodies
- Results are restored in the `tool_result_persist` hook so the agent sees the original values

**Auth shielding:** `--account` and `--client` flags in bash commands are temporarily masked before sanitization and restored after — these are local OAuth credential selectors, not outbound PII.

## PII Detection (gateway/sanitizer.ts)

Detection runs in layers:

| Type | Method |
|---|---|
| SSN, ITIN, EIN | Regex (ITIN checked before SSN — both 9 digits, ITIN starts with 9) |
| Email, URL, Phone, IP | Regex |
| Addresses (full, partial, PO Box) | Regex |
| Credit card, IBAN, bank card | Regex |
| Currency (`$` prefix) | Regex |
| Currency (no `$`) | Context-aware: near financial keywords (wages, income, refund, etc.) |
| Tax years | Context-aware: 4-digit years near tax keywords (W-2, 1040, filing, etc.) |
| Dates of birth | Context-aware: dates near DOB keywords |
| All dates | Standalone date detection (validated MM/DD/YYYY, YYYY-MM-DD) |
| Bank accounts & routing numbers | Context-aware + ABA checksum validation for routing numbers |
| Person names | NLP (wink-nlp) + title-case heuristic + all-caps heuristic + salutation detection |
| API keys / secrets | Known prefixes (sk-, ghp_, AKIA, etc.), Bearer tokens, high-entropy strings |

**Defense-in-depth:** `assertNoLeakedPii()` runs a canary check after sanitization — throws if any SSN/EIN patterns remain in the outbound payload.

## Placeholder Restoration (gateway/restorer.ts)

Three-pass restoration:
1. **Canonical form:** `[person_1]` → original value
2. **Bracket-stripped form:** `person_1` → original value (LLMs, especially DeepSeek, frequently drop square brackets)
3. **Fabricated placeholders:** LLMs sometimes generate new placeholders (e.g. `[person_389]`) for values that were already properly tokenized with a different number — these are passed through as-is with a console warning rather than substituting wrong values

## Key Files

| File | Purpose |
|---|---|
| `index.ts` | OpenClaw plugin entry point; registers hooks and commands |
| `gateway/token-vault.ts` | Persistent tokenization store — the core custom component |
| `gateway/sanitizer.ts` | PII detection engine (regex + NLP + context-aware) |
| `gateway/restorer.ts` | Placeholder restoration (3-pass, handles LLM bracket-stripping) |
| `gateway/index.ts` | HTTP gateway server |
| `gateway/handlers/anthropic.ts` | Anthropic API proxy handler |
| `gateway/handlers/openai.ts` | OpenAI API proxy handler |
| `gateway/handlers/gemini.ts` | Gemini API proxy handler |
| `gateway-manager.ts` | Spawns/manages the gateway subprocess; tries bun first, falls back to node |
| `agent/config.ts` | Config types and defaults (port 8900, TTL 3600s, etc.) |
| `gateway/types.ts` | Shared types: MappingTable, SanitizeResult, GatewayConfig, EntityMatch |

## OpenClaw Commands

Registered as authenticated agent commands:
- `mg_status` — show gateway status and configuration snippet
- `mg_start` — start the gateway
- `mg_stop` — stop the gateway
- `mg_restart` — restart the gateway

## Configuration (in openclaw.json)

```json
{
  "plugins": {
    "entries": {
      "moltguard": {
        "enabled": true,
        "config": {
          "sanitizePrompt": true,
          "gatewayPort": 8900
        }
      }
    },
    "installs": {
      "moltguard": {
        "source": "path",
        "sourcePath": "/home/thomas/moltguard-src"
      }
    }
  }
}
```

## Dependencies

- `wink-nlp` + `wink-eng-lite-web-model` — NLP for person name detection (local, no network)
- `openclaw` (peer dep) — Plugin SDK types
- TypeScript 5.6, Vitest for tests

## Build & Test

```bash
npm run build       # tsc compile to dist/
npm run typecheck   # type-check without emit
npm test            # vitest run
npm run test:watch  # vitest watch mode
```

## Maintenance

**This file must be kept current.** When making substantive changes to this codebase, update the relevant sections of this CLAUDE.md before or as part of the same commit. Drift between the code and this document undermines its purpose.

Update this file when:
- The data flow through the sanitization pipeline changes
- New PII detection categories are added or removed from `gateway/sanitizer.ts`
- The token vault's persistence mechanism, TTL, or session model changes
- New gateway handlers are added (`gateway/handlers/`)
- Plugin config options change (`agent/config.ts`)
- The gateway proxy architecture changes (`gateway/index.ts`, `gateway-manager.ts`)
- New OpenClaw commands are registered
- Section 7216 compliance posture changes

Do **not** update this file for:
- Minor bug fixes that don't change architecture or behaviour
- Test-only changes
- Formatting or comment updates

---

## Section 7216 Compliance Notes

- The token vault file (`~/.moltguard/token-vault.json`) must remain on local filesystem only
- The plaintext PII ↔ token mapping never leaves the machine
- TTL-based expiry enforces data minimization
- Audit columns (`createdAt`, `lastAccessedAt`) are available for compliance review
- File is written with mode 0600 (owner read/write only)
