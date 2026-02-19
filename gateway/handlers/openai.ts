/**
 * OpenAI Chat Completions API handler
 *
 * Handles POST /v1/chat/completions requests in OpenAI's format.
 * Also compatible with OpenAI-compatible APIs (Kimi, DeepSeek, etc.)
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { type GatewayConfig, type MappingTable, isValidUuidV4 } from "../types.js";
import { sanitize, assertNoLeakedPii } from "../sanitizer.js";
import { restore, restoreSSELine } from "../restorer.js";
import type { TokenVault } from "../token-vault.js";

/**
 * Handle OpenAI API request
 */
export async function handleOpenAIRequest(
  req: IncomingMessage,
  res: ServerResponse,
  config: GatewayConfig,
  vault: TokenVault,
  gatewaySessionId: string,
): Promise<void> {
  // Resolve session: use client-provided header (if valid UUID v4) or fall
  // back to the shared gateway session for cross-request consistency.
  const rawSession = req.headers["x-moltguard-session"] as string | undefined;
  const headerSession = rawSession && isValidUuidV4(rawSession) ? rawSession : undefined;
  const sessionId = headerSession ?? gatewaySessionId;

  try {
    // 1. Parse request body
    const body = await readBody(req);
    const requestData = JSON.parse(body);

    // 2. Sanitize the entire request body (messages, tools, metadata, etc.)
    const clientWantsStream = requestData.stream ?? false;
    const { mappingTable, categoryCounters } = vault.getSessionState(sessionId);
    const { sanitized: sanitizedRequest, redactionCount, redactionsByCategory } = sanitize(requestData, { mappingTable, categoryCounters });

    // Force non-streaming when PII restoration is needed.
    // Streaming fragments placeholders across SSE delta chunks (e.g.
    // "[person_1]" becomes "[pers" + "on_1]"), preventing the restorer
    // from matching them.  We restore the full response, then re-encode
    // as SSE if the client requested streaming.
    const needsRestoration = mappingTable.size > 0;
    if (needsRestoration && clientWantsStream) {
      sanitizedRequest.stream = false;
      delete sanitizedRequest.stream_options; // DeepSeek requires this only with stream=true
    }

    // DeepSeek-Reasoner (R1) does NOT support the "system" or "developer"
    // role — all instructions must be in user messages.  Convert any
    // system/developer messages from the upstream client (e.g. OpenClaw's
    // system prompt) so the request is valid for reasoner models.
    // Note: "developer" is the OpenAI o1/o3 equivalent of "system".
    const modelName = (sanitizedRequest.model ?? "").toLowerCase();
    const isReasonerModel = modelName.includes("reasoner") || modelName.includes("-r1");
    const isInstructionRole = (role: string) => role === "system" || role === "developer";

    if (isReasonerModel && Array.isArray(sanitizedRequest.messages)) {
      const systemMsgs = sanitizedRequest.messages.filter((m: any) => isInstructionRole(m.role));
      if (systemMsgs.length > 0) {
        sanitizedRequest.messages = sanitizedRequest.messages.filter((m: any) => !isInstructionRole(m.role));
        const systemContent = systemMsgs
          .map((m: any) => typeof m.content === "string" ? m.content : JSON.stringify(m.content))
          .join("\n\n");
        const firstUserMsg = sanitizedRequest.messages.find((m: any) => m.role === "user");
        if (firstUserMsg && typeof firstUserMsg.content === "string") {
          firstUserMsg.content = systemContent + "\n\n" + firstUserMsg.content;
        } else if (firstUserMsg && Array.isArray(firstUserMsg.content)) {
          firstUserMsg.content.unshift({ type: "text", text: systemContent });
        } else {
          // No user message yet — wrap system content as a user message
          sanitizedRequest.messages.unshift({ role: "user", content: systemContent });
        }
      }
    }

    // Inject an instruction to prevent the LLM from fabricating its own
    // placeholders or self-censoring data.  LLMs (especially DeepSeek) learn
    // the [category_N] pattern and create new tokens the gateway can't restore.
    if (needsRestoration && Array.isArray(sanitizedRequest.messages)) {
      const antiHallucinationText =
        "IMPORTANT: Some values in this conversation have been replaced with " +
        "bracketed placeholders like [person_1] or [ssn_1]. You MUST use these " +
        "placeholders exactly as they appear — never invent new ones, never " +
        "change their numbers, and never create placeholders for values that " +
        "are not already bracketed. ALL UN-BRACKETED VALUES ARE SAFE TO USE " +
        "EXACTLY AS-IS. Do NOT redact, obscure, replace, or paraphrase any " +
        "names, subjects, locations, or other data that appears without " +
        "brackets. Do NOT substitute them with text from tool descriptions " +
        "or other parts of your context. A gateway-level sanitization system " +
        "already protects this conversation — respond naturally using the " +
        "exact text provided to you.";

      if (isReasonerModel) {
        // Reasoner models: prepend to first user message
        const firstUserMsg = sanitizedRequest.messages.find((m: any) => m.role === "user");
        if (firstUserMsg && typeof firstUserMsg.content === "string") {
          firstUserMsg.content = antiHallucinationText + "\n\n" + firstUserMsg.content;
        }
      } else {
        sanitizedRequest.messages.unshift({
          role: "system",
          content: antiHallucinationText,
        });
      }
    }

    // Log redaction summary
    if (redactionCount > 0) {
      const cats = Object.entries(redactionsByCategory).map(([k, v]) => `${k}=${v}`).join(", ");
      console.log(`[moltguard-gateway] Redacted ${redactionCount} items: ${cats}`);
    } else {
      console.log(`[moltguard-gateway] No redactions needed`);
    }

    // 4. Post-sanitization canary check (defense-in-depth)
    const serializedPayload = JSON.stringify(sanitizedRequest);
    assertNoLeakedPii(serializedPayload);

    // 5. Get backend config
    const backend = config.backends.openai;
    if (!backend) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "OpenAI backend not configured" }));
      return;
    }

    // 6. Forward to OpenAI (or compatible) API
    const apiUrl = `${backend.baseUrl}/v1/chat/completions`;
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${backend.apiKey}`,
      },
      body: serializedPayload,
    });

    if (!response.ok) {
      // Forward error response
      res.writeHead(response.status, { "Content-Type": "application/json" });
      const errorBody = await response.text();
      res.end(errorBody);
      return;
    }

    // 6. Handle streaming or non-streaming response
    if (clientWantsStream && needsRestoration) {
      // Backend returned non-streaming (we forced it); restore and re-encode as SSE
      await handleOpenAINonStreamAsSSE(response, res, mappingTable);
    } else if (clientWantsStream) {
      // No PII in session — safe to pass-through stream directly
      await handleOpenAIStream(response, res, mappingTable);
    } else {
      await handleOpenAINonStream(response, res, mappingTable);
    }
  } catch (error) {
    console.error("[moltguard-gateway] OpenAI handler error:", error);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "Internal gateway error",
        message: error instanceof Error ? error.message : String(error),
      }),
    );
  }
}

/**
 * Handle streaming response (SSE)
 */
async function handleOpenAIStream(
  response: Response,
  res: ServerResponse,
  mappingTable: MappingTable,
): Promise<void> {
  // Set SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
  });

  const reader = response.body?.getReader();
  if (!reader) {
    res.end();
    return;
  }

  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      // Decode chunk
      buffer += decoder.decode(value, { stream: true });

      // Process complete lines
      const lines = buffer.split("\n");
      buffer = lines.pop() || ""; // Keep incomplete line in buffer

      for (const line of lines) {
        if (!line.trim()) {
          res.write("\n");
          continue;
        }

        // Restore placeholders in SSE line
        const restoredLine = restoreSSELine(line, mappingTable);
        res.write(restoredLine + "\n");
      }
    }

    // Write any remaining buffer
    if (buffer.trim()) {
      const restoredLine = restoreSSELine(buffer, mappingTable);
      res.write(restoredLine + "\n");
    }

    res.end();
  } catch (error) {
    console.error("[moltguard-gateway] Stream error:", error);
    res.end();
  }
}

/**
 * Handle non-streaming response
 */
async function handleOpenAINonStream(
  response: Response,
  res: ServerResponse,
  mappingTable: MappingTable,
): Promise<void> {
  const responseBody = await response.text();
  const responseData = JSON.parse(responseBody);

  // Restore placeholders in response
  const restoredData = restore(responseData, mappingTable);

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(restoredData));
}

/**
 * Handle a non-streaming backend response when the client expects SSE.
 *
 * Used when we forced `stream: false` on the backend request to prevent
 * placeholder fragmentation.  Restores PII in the full response, then
 * re-encodes it as a single SSE chunk so the client's streaming parser
 * still works.
 */
async function handleOpenAINonStreamAsSSE(
  response: Response,
  res: ServerResponse,
  mappingTable: MappingTable,
): Promise<void> {
  const responseBody = await response.text();
  const responseData = JSON.parse(responseBody);

  // Restore placeholders in the full response
  const restoredData = restore(responseData, mappingTable);

  // Re-encode as SSE: convert chat.completion → chat.completion.chunk
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
  });

  // Convert choices[].message → choices[].delta for streaming format.
  // Must preserve ALL message fields (content, tool_calls, function_call,
  // refusal, etc.) — not just content — or tool calls get silently dropped.
  const choices = restoredData.choices?.map((c: any, i: number) => {
    const delta: any = { ...c.message };
    // Streaming tool_calls require an index field on each entry
    if (delta.tool_calls) {
      delta.tool_calls = delta.tool_calls.map((tc: any, idx: number) => ({
        index: idx,
        ...tc,
      }));
    }
    return {
      index: c.index ?? i,
      delta,
      finish_reason: c.finish_reason,
    };
  });

  const chunk = {
    id: restoredData.id,
    object: "chat.completion.chunk",
    created: restoredData.created,
    model: restoredData.model,
    choices,
    usage: restoredData.usage,
  };

  res.write(`data: ${JSON.stringify(chunk)}\n\n`);
  res.write("data: [DONE]\n\n");
  res.end();
}

/**
 * Read request body as string
 */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}
