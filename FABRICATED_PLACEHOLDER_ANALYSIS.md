# MoltGuard: Fabricated Placeholder Analysis & Fix

## Context

MoltGuard is a local PII sanitization gateway for OpenClaw at `/home/thomas/moltguard-src/`. It intercepts LLM API requests, replaces PII with numbered placeholders like `[person_1]`, sends the sanitized request to DeepSeek, then restores the original values in the response before returning to the client.

The gateway runs a1s a systemd service (`moltguard-gateway.service`) on port 8900. DeepSeek requests are routed through it via the OpenClaw config at `~/.openclaw/openclaw.json`. The gateway config is at `~/.moltguard/gateway.json`. Logs: `journalctl --user -u moltguard-gateway.service`.

## The Problem

DeepSeek learns the `[category_N]` placeholder pattern from the sanitized input and **fabricates new placeholders** for values the NLP sanitizer missed. For example, if the sanitizer creates `[person_1]` through `[person_158]`, DeepSeek will invent `[person_159]` through `[person_166]` for names it encounters that weren't sanitized.

These fabricated placeholders have **no entry** in the gateway's mapping table, so the restorer can't replace them with original values.

### Evidence from gateway logs

```
# Sanitizer created up to person=158:
Redacted 238 items: person=158, partial_address=8, ...

# But user saw person_159-166 and partial_address_9 in the output
```

### What's been done so far

1. **Anti-hallucination system message** (`gateway/handlers/openai.ts` lines 50-63, `gateway/handlers/anthropic.ts`): Injects a system message telling the LLM to never invent new placeholders. This helps but isn't 100% effective — LLMs don't always follow instructions.

2. **Post-restoration cleanup** (`gateway/restorer.ts` lines 29-42, called at line 42): `stripFabricatedPlaceholders()` detects placeholder-shaped tokens that aren't in the mapping table and replaces them with empty string `""`.

### Current symptom

The `[person_159]` brackets no longer leak through, but the **names are now missing entirely** — the fabricated tokens are stripped to empty strings, leaving garbled text like:
- "5.  request (2026-02-16)" instead of "5. Karen request (2026-02-16)"
- " needs tax contract amendment" instead of "Mike needs tax contract amendment"

## Your Task

Thoroughly analyze the end-to-end sanitization and restoration pipeline and implement a robust fix. Here are the key areas to investigate and the specific files involved:

### Key files to read and understand

- `gateway/sanitizer.ts` — The NLP sanitizer. Focus on `collectNlpMatches()` (person name detection), `sanitizeText()` (how counters and mapping table interact), and `collectMatches()` (match ordering).
- `gateway/restorer.ts` — The restorer. Understand the 3-pass approach (bracketed, bracket-stripped, fabricated cleanup).
- `gateway/handlers/openai.ts` — The OpenAI/DeepSeek handler. Understand the ephemeral session lifecycle: session created → sanitize → forward → restore → destroy session. Each request gets its own session with counters starting at 0.
- `gateway/token-vault.ts` — The vault proxy. Understand `_createProxiedMap()`, `_seedBaseMap()`, and how `mappingTable.set()` interacts with `vault.store()`.
- `gateway/handlers/anthropic.ts` — The Anthropic handler (same pattern as OpenAI).
- `index.ts` — Plugin hooks for tool-call sanitization (`before_tool_call`, `tool_result_persist`).
- `gateway/index.ts` — Gateway server routing.

### Investigation areas

1. **Why does the NLP sanitizer miss names?** Run the sanitizer against realistic email content (from `gog gmail search` output) and identify which names are missed and why. Common gaps:
   - Single-word names (just "Karen" without a surname)
   - Names in email "From" headers (e.g., "From: Karen Wilson <karen@example.com>")
   - Names embedded in subject lines or quoted text
   - Non-English names or unusual capitalization

2. **Is `sanitizeText()` losing mappings?** The counter increments for every unique match (line 831) but `mappingTable.set()` only fires when `parts.length > 1` (line 837-840). If a shorter match was already consumed by a longer one, the counter increments but no mapping is created. This means the `redactionsByCategory` counter (e.g., person=158) may OVERCOUNT the actual number of mapped placeholders. Verify whether this gap is what allows DeepSeek to fabricate placeholders in the "gap" numbers.

3. **The stripping approach is wrong.** Replacing fabricated placeholders with `""` destroys information. The LLM was trying to refer to a real value — we just don't know what it is. Better approaches:
   - Instead of stripping, try to **infer the original value** from context (the fabricated placeholder was created by DeepSeek from text it saw — that text came from our sanitized request, so the original must be somewhere in the mapping table or the conversation).
   - Or: instead of empty string, leave the text as-is but strip only the bracket scaffolding (so `[person_159]` becomes the actual name DeepSeek saw, if we can recover it).
   - Or: improve the sanitizer to catch more names so fabrication doesn't happen.

4. **Counter/mapping desync with vault proxy.** When the Proxy's `set` trap calls `vault.store()`, and the vault's reverse index returns an EXISTING token for the same original value, the store returns early — but the Proxy still writes the NEW token to the baseMap. This means the baseMap can have tokens that don't exist in the vault. Trace this flow and determine if it causes any restoration failures.

5. **Are there edge cases in the restorer?** The Pass 2 word-boundary regex `\bperson_1\b` should NOT match `person_10` — but verify this with test cases. Also check: what happens when the response contains a mix of bracketed and bare placeholders for the same token?

### What to fix

1. **Improve the NLP sanitizer** to catch more person names, especially:
   - Single-word names in context (e.g., "From: Karen" near email headers)
   - Names in structured data formats (JSON email output from `gog`)
   - Names that appear as values in key-value pairs

2. **Fix the stripping behavior** in `stripFabricatedPlaceholders()` — don't return empty string. Either leave the original text or find a way to map fabricated placeholders back to the values DeepSeek was trying to reference.

3. **Fix the counter/mapping desync** if it contributes to the problem — the counter should only increment when a mapping is actually created.

4. **Add test coverage** for the fabrication scenario: sanitize a request with many names, simulate a DeepSeek response that includes fabricated placeholders, and verify the restorer handles it correctly.

### How to test

```bash
# Type check
cd /home/thomas/moltguard-src && npx tsc --noEmit

# Run existing tests
npm test

# Build
npx tsc

# Restart gateway after changes
systemctl --user restart moltguard-gateway.service

# Check logs
journalctl --user -u moltguard-gateway.service --no-pager -n 50
```

### Important constraints

- The gateway runs the COMPILED JS from `dist/`, not TypeScript directly. Always `npx tsc` after changes.
- Ephemeral sessions: each request creates a fresh session with counters starting at 0. The session is destroyed after the response is sent.
- The token vault at `~/.moltguard/token-vault.json` is typically empty (ephemeral sessions are destroyed).
- Don't break the existing test suite in `gateway/sanitizer.test.ts`.
- The sanitizer's `STRUCTURAL_KEYS` set must never be modified — these protect protocol-level fields from being sanitized.
