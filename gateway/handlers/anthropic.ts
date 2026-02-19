/**
 * Anthropic Messages API handler
 *
 * Handles POST /v1/messages requests in Anthropic's native format.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { type GatewayConfig, type MappingTable, isValidUuidV4 } from "../types.js";
import { sanitize, assertNoLeakedPii } from "../sanitizer.js";
import { restore, restoreSSELine } from "../restorer.js";
import type { TokenVault } from "../token-vault.js";

/**
 * Handle Anthropic API request
 */
export async function handleAnthropicRequest(
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

    // 2. Sanitize the entire request body (messages, system, tools, metadata, etc.)
    const clientWantsStream = requestData.stream ?? false;
    const { mappingTable, categoryCounters } = vault.getSessionState(sessionId);
    const { sanitized: sanitizedRequest, redactionCount, redactionsByCategory } = sanitize(requestData, { mappingTable, categoryCounters });

    // Force non-streaming when PII restoration is needed.
    // Streaming fragments placeholders across SSE delta chunks, preventing
    // the restorer from matching them. We restore the full response, then
    // re-encode as SSE if the client requested streaming.
    const needsRestoration = mappingTable.size > 0;
    if (needsRestoration && clientWantsStream) {
      sanitizedRequest.stream = false;
    }

    // Inject a system-level instruction to prevent the LLM from fabricating
    // its own placeholders.  Anthropic uses a top-level "system" field.
    if (needsRestoration) {
      const antiHallucination =
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
      if (typeof sanitizedRequest.system === "string") {
        sanitizedRequest.system = antiHallucination + "\n\n" + sanitizedRequest.system;
      } else {
        sanitizedRequest.system = antiHallucination;
      }
    }

    // Log redaction summary
    if (redactionCount > 0) {
      const cats = Object.entries(redactionsByCategory).map(([k, v]) => `${k}=${v}`).join(", ");
      console.log(`[moltguard-gateway] Redacted ${redactionCount} items: ${cats}`);
    } else {
      console.log(`[moltguard-gateway] No redactions needed`);
    }

    // 5. Post-sanitization canary check (defense-in-depth)
    const serializedPayload = JSON.stringify(sanitizedRequest);
    assertNoLeakedPii(serializedPayload);

    // 6. Get backend config
    const backend = config.backends.anthropic;
    if (!backend) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Anthropic backend not configured" }));
      return;
    }

    // 7. Forward to real Anthropic API
    const apiUrl = `${backend.baseUrl}/v1/messages`;
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "anthropic-version": req.headers["anthropic-version"] as string || "2023-06-01",
        "x-api-key": backend.apiKey,
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

    // 7. Handle streaming or non-streaming response
    if (clientWantsStream && needsRestoration) {
      // Backend returned non-streaming (we forced it); restore and re-encode as SSE
      await handleAnthropicNonStreamAsSSE(response, res, mappingTable);
    } else if (clientWantsStream) {
      // No PII in session — safe to pass-through stream directly
      await handleAnthropicStream(response, res, mappingTable);
    } else {
      await handleAnthropicNonStream(response, res, mappingTable);
    }
  } catch (error) {
    console.error("[moltguard-gateway] Anthropic handler error:", error);
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
 * Handle streaming response
 */
async function handleAnthropicStream(
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
async function handleAnthropicNonStream(
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
 * re-encodes it as Anthropic SSE events so the client's streaming parser
 * still works.
 */
async function handleAnthropicNonStreamAsSSE(
  response: Response,
  res: ServerResponse,
  mappingTable: MappingTable,
): Promise<void> {
  const responseBody = await response.text();
  const responseData = JSON.parse(responseBody);

  // Restore placeholders in the full response
  const restoredData = restore(responseData, mappingTable);

  // Re-encode as Anthropic SSE events
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
  });

  // Anthropic SSE format: message_start, content_block_start,
  // content_block_delta, content_block_stop, message_delta, message_stop
  const messageStartEvent = {
    type: "message_start",
    message: {
      ...restoredData,
      content: [], // Content delivered via content_block events
    },
  };
  res.write(`event: message_start\ndata: ${JSON.stringify(messageStartEvent)}\n\n`);

  // Emit each content block (text and tool_use)
  const contentBlocks = restoredData.content ?? [];
  for (let i = 0; i < contentBlocks.length; i++) {
    const block = contentBlocks[i];

    if (block.type === "text") {
      res.write(`event: content_block_start\ndata: ${JSON.stringify({
        type: "content_block_start",
        index: i,
        content_block: { type: "text", text: "" },
      })}\n\n`);

      if (block.text) {
        res.write(`event: content_block_delta\ndata: ${JSON.stringify({
          type: "content_block_delta",
          index: i,
          delta: { type: "text_delta", text: block.text },
        })}\n\n`);
      }
    } else if (block.type === "tool_use") {
      res.write(`event: content_block_start\ndata: ${JSON.stringify({
        type: "content_block_start",
        index: i,
        content_block: { type: "tool_use", id: block.id, name: block.name, input: {} },
      })}\n\n`);

      // Emit tool input as a single JSON delta
      if (block.input !== undefined) {
        res.write(`event: content_block_delta\ndata: ${JSON.stringify({
          type: "content_block_delta",
          index: i,
          delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) },
        })}\n\n`);
      }
    } else {
      // Other block types: pass through as-is
      res.write(`event: content_block_start\ndata: ${JSON.stringify({
        type: "content_block_start",
        index: i,
        content_block: block,
      })}\n\n`);
    }

    res.write(`event: content_block_stop\ndata: ${JSON.stringify({
      type: "content_block_stop",
      index: i,
    })}\n\n`);
  }

  // Message delta (stop reason + usage)
  res.write(`event: message_delta\ndata: ${JSON.stringify({
    type: "message_delta",
    delta: { stop_reason: restoredData.stop_reason },
    usage: restoredData.usage,
  })}\n\n`);

  res.write(`event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`);
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
