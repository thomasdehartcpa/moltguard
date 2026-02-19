# MoltGuard Security Audit Prompt

> Paste the contents of this file as your opening message in a fresh Claude Code session
> opened in the `/home/thomas/moltguard-src` directory.

---

Please perform a security audit of this codebase. Read this entire prompt before touching any files.

## Context

This is **MoltGuard**, a local PII sanitization plugin for an AI agent called OpenClaw. It sits between an AI assistant (Abel) and third-party LLM APIs (Anthropic, DeepSeek, Gemini). Its job is to ensure taxpayer PII never leaves the local machine in plaintext.

**Why this matters:** The operator (Thomas) is a CPA. Client data — SSNs, EINs, names, income figures, bank accounts — flows through AI conversations. IRC Section 7216 prohibits unauthorized disclosure of taxpayer information. A failure in this system is a regulatory and professional liability event, not just a technical bug.

**The core guarantee MoltGuard must uphold:**
> PII present in a message sent to any third-party LLM API must be replaced with an opaque, numbered placeholder before transmission. The mapping between placeholder and original value must never leave the local machine.

## System Architecture (read this before exploring code)

```
User/Agent message
      ↓
 sanitize()          ← replaces PII with [person_1], [ssn_1], etc.
      ↓
 TokenVault.store()  ← persists token ↔ original mapping to ~/.moltguard/token-vault.json
      ↓
 Third-party LLM API ← receives sanitized content only
      ↓
 LLM response (contains placeholders)
      ↓
 restore()           ← swaps placeholders back to original values
      ↓
 Telegram / UI       ← user sees natural response with real values
```

**Two sanitization layers exist:**
1. **Gateway proxy** (`gateway/index.ts`) — HTTP proxy on port 8900; intercepts full LLM API requests/responses
2. **Tool-call hooks** (`index.ts`) — `before_tool_call` hook sanitizes bash commands, web searches, web fetches before they execute

OpenClaw loads MoltGuard as a plugin from this directory. OpenClaw's configuration lives at `~/.openclaw/openclaw.json`. Abel (the agent) runs inside OpenClaw and communicates via Telegram.

## Key Files to Audit

### MoltGuard (this repo)
| File | What to look for |
|---|---|
| `gateway/sanitizer.ts` | PII detection completeness, false negatives, regex correctness |
| `gateway/restorer.ts` | Placeholder injection attacks, restoration correctness |
| `gateway/token-vault.ts` | File permissions, session isolation, race conditions, token predictability |
| `gateway/handlers/anthropic.ts` | Does sanitization actually run before forwarding? Streaming edge cases? |
| `gateway/handlers/openai.ts` | Same as above for OpenAI format |
| `gateway/handlers/gemini.ts` | Same as above for Gemini format |
| `index.ts` | Tool-call hook coverage, auth flag shielding robustness, hook registration order |
| `gateway-manager.ts` | Process isolation, environment variable leakage, failure modes |

### OpenClaw configuration (read-only reference)
| Path | What to look for |
|---|---|
| `~/.openclaw/openclaw.json` | Plugin load order, gateway auth token strength, tool deny-list completeness, channel access controls |
| `~/.openclaw/workspace/SOUL.md` | Does the agent's core identity instruct it to protect PII, or could it be talked out of it? |
| `~/.openclaw/workspace/STRATEGY.md` | Are the IRS security policies reflected in how Abel is instructed to behave? |
| `~/.openclaw/sandboxes/agent-main-*/skills/` | Do any installed skills have direct external network access that bypasses MoltGuard? |

## Security Properties to Verify

### 1. PII Detection Completeness
- Are there PII formats that bypass all detection? (e.g. SSNs with unusual separators, names in non-standard casing, EINs embedded in longer strings)
- Does the canary check (`assertNoLeakedPii`) cover enough patterns, or does it only catch SSN/EIN while other PII slips through?
- Can PII appear in API request fields that `sanitizeValue()` skips (structural keys: `tool_call_id`, `model`, `role`, etc.)? Are any of those fields exploitable to carry PII?

### 2. Placeholder Injection / Prompt Injection
- Can an attacker (or a malicious document Abel reads) inject `[person_1]`-style strings into content to manipulate the restorer into substituting arbitrary values from the mapping table?
- Can the LLM be prompted to output real PII values directly (bypassing the placeholder system) in a way that reaches the user without being caught?
- The restorer handles fabricated placeholders by passing them through — could this be exploited?
- Can a prompt injection in an email, document, or web page Abel reads instruct Abel to call `mg_stop` or `mg_restart`, effectively disabling the gateway without Thomas's approval?

### 3. Architecture Bypass via OpenClaw
- Can Abel (or a prompt injected into Abel) instruct OpenClaw to route model traffic directly to an LLM API, bypassing the port 8900 gateway entirely?
- Are the `mg_stop`, `mg_start`, `mg_restart` commands registered with `requireAuth: true`? What does "requireAuth" actually enforce — is it sufficient to prevent abuse from injected prompts?
- If MoltGuard fails to start or crashes, does OpenClaw fall back to an unprotected direct API connection, or does it fail closed?
- The `tool deny-list` in `openclaw.json` blocks `process` and `browser` — are there other tools that could be used to exfiltrate data or reconfigure the gateway?
- Can Abel be instructed via a Telegram message (from an unknown sender in a group) to disable or reconfigure MoltGuard? Review the group policy and allowlist in `openclaw.json`.

### 4. Skill-Level Bypass
- Review the installed skills in `~/.openclaw/sandboxes/agent-main-*/skills/`. Do any skills make direct HTTP calls to external services in a way that would not pass through the MoltGuard tool-call hook? (e.g. skills that use fetch/curl internally rather than via the Bash tool)
- If a skill sends an email (Himalaya), posts to Slack, or sends a Telegram message directly, does that traffic pass through MoltGuard's `before_tool_call` sanitization?

### 5. Token Vault Security
- `token-vault.json` is written with mode `0600` — verify this is actually enforced and that the parent directory also has appropriate permissions
- Are session IDs (UUIDs) generated with a cryptographically secure source?
- Can one session's tokens be resolved by another session (cross-session leakage)?
- What happens if the vault file is corrupted or tampered with?
- Is there a risk of token collision across sessions with the same PII value?

### 6. Auth Flag Shielding
- The `shieldAuthArgs()` function protects `--account` and `--client` flags from sanitization. Is the regex robust? Can it be bypassed by unusual quoting, escaping, or flag ordering?
- Are there other flags in common tools (gog, curl, etc.) that could carry non-PII auth values that should also be shielded?

### 7. Gateway Process Security
- Does the gateway subprocess inherit environment variables it shouldn't (API keys, secrets from the parent process)?
- The gateway is protected by a static token in `openclaw.json`. Is this token adequate? Could another local process on the machine call port 8900 directly and use the gateway as an unsanitized proxy?
- What happens if the gateway crashes mid-request — does the unsanitized original get forwarded, or does the request fail safely?

### 8. Streaming Response Handling
- SSE streaming restores placeholders line-by-line (`restoreSSELine`). Can a placeholder span two chunks and escape restoration?
- Is there a scenario where partial restoration produces output that looks like natural text but contains a raw placeholder?

### 9. Tool-Call Coverage Gaps
- The `before_tool_call` hook only sanitizes Bash (external commands), WebSearch, and WebFetch. Are there other OpenClaw tools that could send PII externally that aren't covered?
- The `EXTERNAL_CMDS` list — is it complete? Could PII leak via a tool not on the list?

## What to Produce

For each finding, provide:

1. **Severity** — Critical / High / Medium / Low / Informational
2. **Location** — file path and line number (or config path for OpenClaw findings)
3. **Description** — what the vulnerability or gap is
4. **Proof of concept** — a concrete example of how it could manifest (a specific input, a specific failure mode, a specific prompt injection string)
5. **Recommended fix** — specific and actionable

At the end, provide:
- A **summary table** of all findings by severity
- An **overall assessment** of whether the core guarantee (PII never transmitted in plaintext) is currently upheld, with confidence level
- A **bypass risk assessment** specifically addressing whether the architecture can be disabled or circumvented by a prompt injection attack reaching Abel via Telegram, email, or a document it reads

## Scope

**In scope:**
- All source files in this repository (`moltguard-src/`)
- OpenClaw configuration at `~/.openclaw/openclaw.json`
- OpenClaw agent workspace files at `~/.openclaw/workspace/` (identity, soul, strategy)
- Installed skill definitions at `~/.openclaw/sandboxes/agent-main-*/skills/*/SKILL.md`

**Out of scope:** Network-level attacks, physical machine access, the OpenClaw runtime binary itself.

**Constraint:** Do not modify any source or configuration files during the audit. Read-only. Report findings only.
