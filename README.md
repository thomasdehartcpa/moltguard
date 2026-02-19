# MoltGuard

[![npm version](https://img.shields.io/npm/v/@openguardrails/moltguard.svg)](https://www.npmjs.com/package/@openguardrails/moltguard)
[![GitHub](https://img.shields.io/github/license/openguardrails/moltguard)](https://github.com/openguardrails/moltguard)

**Local PII sanitization gateway for OpenClaw.** Strips sensitive data from prompts before they reach LLM APIs and restores original values in responses. All processing happens on your machine — no data is sent to any MoltGuard endpoint.

**GitHub**: [https://github.com/openguardrails/moltguard](https://github.com/openguardrails/moltguard)

**npm**: [https://www.npmjs.com/package/@openguardrails/moltguard](https://www.npmjs.com/package/@openguardrails/moltguard)

## Features

- **Local Prompt Sanitization Gateway** - Protect sensitive data (SSNs, bank cards, passwords, API keys, names, addresses) before sending to LLMs
- **Tool-Call PII Sanitization** - Automatically sanitize outbound tool calls (curl, web search, etc.) and restore in results
- **IRC Section 7216 Compliance** - Taxpayer PII (SSN, ITIN, EIN, tax years, financial amounts, names, addresses) is redacted before reaching cloud APIs
- **Privacy-First** - All processing happens locally on `127.0.0.1`. No cloud endpoints, no telemetry, no API keys

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Supported Data Types](#supported-data-types)
- [Gateway Setup](#gateway-setup)
- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
- [Privacy & Security](#privacy--security)

## Quick Start

```bash
# Install the plugin
openclaw plugins install @openguardrails/moltguard

# Restart OpenClaw
openclaw gateway restart
```

Enable in `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "moltguard": {
        "config": {
          "sanitizePrompt": true
        }
      }
    }
  }
}
```

## How It Works

The Gateway is a **local HTTP proxy** that automatically:

1. **Intercepts** your prompts before they reach the LLM
2. **Sanitizes** sensitive data (SSNs, names, addresses, bank cards, API keys, etc.)
3. **Sends** sanitized prompts to the LLM (Claude/GPT/DeepSeek/Gemini/etc.)
4. **Restores** original values in responses before they reach the client — streaming responses are automatically buffered for correct restoration

**Example:**

```
You: "My SSN is 123-45-6789, file my return"
  | Gateway sanitizes
LLM sees: "My SSN is [ssn_1], file my return"
  | LLM responds
LLM: "Filing return for [ssn_1]"
  | Gateway restores
Tool executes with: "Filing return for 123-45-6789"
```

The restorer handles both the canonical bracketed form (`[ssn_1]`) and the bracket-stripped form (`ssn_1`) that some LLMs produce when they interpret square brackets as formatting and drop them. Word-boundary matching prevents partial-token collisions.

For streaming responses (SSE), the gateway automatically switches the backend request to non-streaming when PII restoration is needed. This prevents placeholders from being fragmented across SSE delta chunks (e.g., `[person_1]` split into `[pers` + `on_1]`). The restored response is re-encoded as SSE events — including tool calls and all message fields — so the client's streaming parser and tool execution pipeline work transparently. Streaming-only request fields like `stream_options` are removed automatically to maintain compatibility with APIs that validate them (e.g., DeepSeek).

**Anti-hallucination defense:** LLMs can learn the `[category_N]` pattern and fabricate new placeholders for values the sanitizer didn't catch (e.g., `[person_159]` when the sanitizer only created up to `[person_158]`). MoltGuard defends against this in three ways: (1) a system-level instruction is injected telling the LLM to never invent new placeholders, (2) expanded name detection catches names in email headers (`From: Name <email>`), salutations (`Hi Karen,`), and angle-bracketed email contexts to reduce the number of unsanitized names the LLM sees, and (3) a post-restoration pass detects any remaining fabricated placeholder-shaped tokens that have no mapping table entry and leaves them visible rather than stripping them to empty strings.

**False-positive prevention:** The sanitizer uses multi-layer filtering to prevent non-PII text from being classified as person names. Markdown structural lines (headings, bold text, list items, emphasis) are automatically excluded. A set of 120+ common technical/structural terms (e.g., "Critical", "Schedule", "Gateway", "Configuration") supplements the existing tax/financial exclusion list. Title-case phrases with 3+ words require at least one known first name to match (preventing matches like "Screen Time Safeguard"), and ALL_CAPS matches are limited to 2-3 words (matching real tax form names like "JOHN SMITH" but not section headers like "CRITICAL CONSTRAINTS"). Dates inside file paths (preceded by `/` or followed by `.`) are excluded to prevent tool calls from breaking (e.g., `memory/2026-02-17.md` is not sanitized).

**LLM self-censoring conflict:** If the LLM has its own instructions to protect client data (e.g., system prompt rules about confidentiality, AICPA compliance, or Section 7216), it may attempt to redact sensitive values *on its own* — replacing client names or email subjects with arbitrary text from its context window (tool descriptions, section headers, etc.). MoltGuard cannot undo these ad-hoc substitutions because they don't follow the `[category_N]` placeholder format. **The fix is in the Agent's instructions, not in MoltGuard:** tell the LLM that MoltGuard handles sanitization at the gateway layer and it should use all data exactly as it appears in the conversation. The LLM's role should be to *alert* on suspected unsanitized PII, not to redact it. See the OpenClaw workspace `STRATEGY.md` for an example of how to configure this.

Additionally, tool calls to external services (curl, web search, etc.) are sanitized via OpenClaw plugin hooks, independent of the gateway proxy.

**Auth argument shielding:** Some external CLI tools (e.g., `gog`) use flags like `--account` and `--client` to look up local OAuth credentials. These values are not outbound PII — they never leave the machine — but the sanitizer would otherwise redact them (e.g., replacing `--account user@example.com` with `--account [email_1]`), breaking authentication. MoltGuard shields these auth-related flag values before sanitization and restores them afterward, so credential lookups work while all other PII in the command is still redacted.

## Supported Data Types

| Data Type | Placeholder Example | Detection Method |
|-----------|-------------------|-----------------|
| SSN | `[ssn_1]` | 123-45-6789, 123 45 6789, 123456789 |
| ITIN | `[itin_1]` | 9XX-XX-XXXX (starts with 9) |
| EIN | `[ein_1]` | XX-XXXXXXX |
| Person Names | `[person_1]` | NLP + title-case/all-caps/email-header/salutation heuristics (Mc/Mac/De/Le-prefixed surnames; structural-line and heading exclusion; 120+ technical term exclusions; 3+ word title-case requires known first name anchor) |
| Addresses | `[address_1]` | Street + city/state/zip patterns |
| Currency | `[currency_1]` | $-prefixed amounts + context-aware bare amounts |
| Tax Year | `[tax_year_1]` | Years near tax keywords (context-aware) |
| Standalone Date | `[date_1]` | MM/DD/YYYY and YYYY-MM-DD formats (file-path-aware: skips dates in paths like `memory/2026-02-17.md`) |
| Date of Birth | `[dob_1]` | Dates near DOB keywords (context-aware) |
| Bank Account | `[bank_account_1]` | 8-17 digit numbers near banking keywords |
| Routing Number | `[routing_number_1]` | 9-digit ABA-validated numbers |
| Credit Cards | `[credit_card_1]` | 4x4 digit patterns |
| Bank Cards | `[bank_card_1]` | 16-19 digit numbers |
| Email | `[email_1]` | user@example.com |
| Phone | `[phone_1]` | US/international formats |
| API Keys | `[secret_1]` | sk-..., ghp_..., Bearer tokens, high-entropy strings |
| IP Address | `[ip_1]` | 192.168.1.1 |
| IBAN | `[iban_1]` | International bank account numbers |
| URL | `[url_1]` | https://example.com |

## Gateway Setup

**1. Enable in config** (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "moltguard": {
        "config": {
          "sanitizePrompt": true,
          "gatewayPort": 8900,
          "gatewayAutoStart": true
        }
      }
    }
  }
}
```

**2. Configure your model to use the gateway**:

```json
{
  "models": {
    "providers": {
      "claude-protected": {
        "baseUrl": "http://127.0.0.1:8900",
        "api": "anthropic-messages",
        "apiKey": "${ANTHROPIC_API_KEY}",
        "models": [...]
      }
    }
  }
}
```

**3. Restart OpenClaw**:

```bash
openclaw gateway restart
```

## Installation

```bash
# Install from npm
openclaw plugins install @openguardrails/moltguard

# Restart gateway to load the plugin
openclaw gateway restart
```

## Verify Installation

```bash
# Check plugin list, confirm moltguard status is "loaded"
openclaw plugins list
```

You should see:
```
| MoltGuard | moltguard | loaded | ...
```

## Configuration

Edit OpenClaw config file (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "moltguard": {
        "enabled": true,
        "config": {
          "sanitizePrompt": true,
          "gatewayPort": 8900,
          "gatewayAutoStart": true,
          "vaultTtlSeconds": 3600
        }
      }
    }
  }
}
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `sanitizePrompt` | `false` | Enable local prompt sanitization gateway |
| `gatewayPort` | `8900` | Port for the gateway server |
| `gatewayAutoStart` | `true` | Automatically start gateway when OpenClaw starts |
| `vaultTtlSeconds` | `3600` | TTL for token vault entries in seconds (data minimization) |
| `vaultMaxEntries` | `10000` | Maximum token vault entries before LRU eviction |
| `blockOnRisk` | `true` | Block tool calls when a risk is detected |
| `timeoutMs` | `60000` | Timeout for gateway operations in milliseconds |

## Commands

| Command | Description |
|---------|-------------|
| `/mg_status` | View gateway status and configuration |
| `/mg_start` | Start the sanitization gateway |
| `/mg_stop` | Stop the sanitization gateway |
| `/mg_restart` | Restart the sanitization gateway |

## Privacy & Security

MoltGuard is **entirely local software**. It makes zero network calls to any MoltGuard server.

### Network Architecture

```
Your prompts
     |
     v
[MoltGuard Gateway @ 127.0.0.1:8900]  <-- local only
     |
     | PII stripped, placeholders inserted
     v
[LLM API: Anthropic / OpenAI / Gemini / DeepSeek]
     |
     | Response with placeholders
     v
[MoltGuard Gateway]  <-- restores original values
     |
     v
Your tools execute with real data
```

### What Leaves Your Machine

Only **tokenized placeholders** (e.g., `[ssn_1]`, `[person_1]`) reach cloud LLM APIs. The mapping between placeholders and original values never leaves `~/.moltguard/token-vault.json` (owner-only permissions, `0o600`). If an LLM strips the brackets, the restorer still matches the bare token (e.g., `ssn_1`) using word-boundary-aware replacement.

A post-sanitization canary check scans every outbound payload for residual SSN/EIN patterns before forwarding, aborting the request if any are detected. Session IDs are validated as UUID v4 format.

### Session Management

The gateway maintains a **persistent session** for its lifetime, ensuring consistent placeholder mappings across all API calls in a conversation (e.g., `[person_1]` always maps to the same name across turns). The session is created at gateway startup and destroyed on shutdown (SIGINT/SIGTERM). Clients can still override the session by sending an `x-moltguard-session` header with a valid UUID v4.

### Data Minimization

- Vault entries expire after a configurable TTL (default: 1 hour)
- LRU eviction caps vault size at `maxEntries` (default: 10,000)
- The gateway session is destroyed on shutdown; vault entries are cleaned up
- Periodic purge removes expired entries (every 5 minutes)
- The gateway binds to `127.0.0.1` only and serves no CORS headers
- See [TOKEN_VAULT.md](./TOKEN_VAULT.md) for architecture details

### Auditable Source

All code is open source. Key files:
- `gateway/sanitizer.ts` - NLP-powered sanitization patterns and logic (including multi-cap surname detection, email-header/salutation-context name extraction)
- `gateway/restorer.ts` - Placeholder restoration logic (bracket-aware, bracket-stripped, and fabricated-placeholder preservation)
- `gateway/token-vault.ts` - Persistent session-scoped token vault
- `gateway/handlers/*.ts` - Anthropic, OpenAI, and Gemini protocol handlers
- `index.ts` - Plugin hooks for tool-call sanitization

## Uninstall

```bash
openclaw plugins uninstall @openguardrails/moltguard
openclaw gateway restart
```

To also remove local vault data:

```bash
rm -rf ~/.moltguard/
```

## Development

```bash
# Clone repository
git clone https://github.com/openguardrails/moltguard.git
cd moltguard

# Install dependencies
npm install

# Local development install
openclaw plugins install -l .
openclaw gateway restart

# Type check
npm run typecheck

# Run tests
npm test
```

## License

MIT
