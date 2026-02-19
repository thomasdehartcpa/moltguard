/**
 * Google Gemini API handler
 *
 * Handles POST /v1/models/:model:generateContent requests in Gemini's format.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { type GatewayConfig, isValidUuidV4 } from "../types.js";
import { sanitize, assertNoLeakedPii } from "../sanitizer.js";
import { restore } from "../restorer.js";
import type { TokenVault } from "../token-vault.js";

/**
 * Handle Gemini API request
 */
export async function handleGeminiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  config: GatewayConfig,
  modelName: string,
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

    // 2. Sanitize the entire request body (contents, tools, metadata, etc.)
    const { mappingTable, categoryCounters } = vault.getSessionState(sessionId);
    const { sanitized: sanitizedRequest } = sanitize(requestData, { mappingTable, categoryCounters });

    // 4. Post-sanitization canary check (defense-in-depth)
    const serializedPayload = JSON.stringify(sanitizedRequest);
    assertNoLeakedPii(serializedPayload);

    // 5. Get backend config
    const backend = config.backends.gemini;
    if (!backend) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Gemini backend not configured" }));
      return;
    }

    // 6. Forward to Gemini API
    const apiUrl = `${backend.baseUrl}/v1/models/${modelName}:generateContent`;
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": backend.apiKey,
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

    // 6. Handle response (Gemini typically doesn't stream in same way)
    const responseBody = await response.text();
    const responseData = JSON.parse(responseBody);

    // Restore placeholders in response
    const restoredData = restore(responseData, mappingTable);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(restoredData));
  } catch (error) {
    console.error("[moltguard-gateway] Gemini handler error:", error);
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
