#!/usr/bin/env node
/**
 * MoltGuard Security Gateway
 *
 * Local HTTP proxy that sanitizes sensitive data before sending to LLM APIs
 * and restores it in responses. Supports Anthropic, OpenAI, and Gemini protocols.
 */

import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { loadConfig, validateConfig } from "./config.js";
import type { GatewayConfig } from "./types.js";
import { handleAnthropicRequest } from "./handlers/anthropic.js";
import { handleOpenAIRequest } from "./handlers/openai.js";
import { handleGeminiRequest } from "./handlers/gemini.js";
import { TokenVault } from "./token-vault.js";

let config: GatewayConfig;
let vault: TokenVault;
let gatewaySessionId: string;

/**
 * Main request handler
 */
async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const { method, url } = req;

  // Log request
  console.log(`[moltguard-gateway] ${method} ${url}`);

  // Only allow POST
  if (method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Method not allowed" }));
    return;
  }

  // Route to appropriate handler
  try {
    if (url === "/v1/messages") {
      // Anthropic Messages API
      await handleAnthropicRequest(req, res, config, vault, gatewaySessionId);
    } else if (url === "/v1/chat/completions" || url === "/chat/completions") {
      // OpenAI Chat Completions API
      await handleOpenAIRequest(req, res, config, vault, gatewaySessionId);
    } else if (url?.match(/^\/v1\/models\/(.+):generateContent$/)) {
      // Gemini API
      const match = url.match(/^\/v1\/models\/(.+):generateContent$/);
      const modelName = match?.[1];
      if (modelName) {
        await handleGeminiRequest(req, res, config, modelName, vault, gatewaySessionId);
      } else {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Model name required" }));
      }
    } else if (url === "/health") {
      // Health check endpoint
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", version: "6.0.0" }));
    } else {
      // Unknown endpoint
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found", url }));
    }
  } catch (error) {
    console.error("[moltguard-gateway] Request handler error:", error);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        error: "Internal server error",
        message: error instanceof Error ? error.message : String(error),
      }),
    );
  }
}

/**
 * Start gateway server
 */
export function startGateway(configPath?: string): void {
  try {
    // Load and validate configuration
    config = loadConfig(configPath);
    validateConfig(config);

    // Initialize token vault for persistent session-scoped tokenization
    vault = new TokenVault();
    // Create a shared session for the gateway's lifetime.  This ensures
    // consistent placeholder mappings across all API calls in a conversation,
    // even when clients don't send an x-moltguard-session header.
    gatewaySessionId = vault.createSession();
    console.log(`[moltguard-gateway] Token vault initialized (session ${gatewaySessionId})`);

    console.log("[moltguard-gateway] Configuration loaded:");
    console.log(`  Port: ${config.port}`);
    console.log(
      `  Backends: ${Object.keys(config.backends).join(", ")}`,
    );

    // Create HTTP server
    const server = createServer(handleRequest);

    // Start listening
    server.listen(config.port, "127.0.0.1", () => {
      console.log(
        `[moltguard-gateway] Server listening on http://127.0.0.1:${config.port}`,
      );
      console.log("[moltguard-gateway] Ready to proxy requests");
      console.log("");
      console.log("Endpoints:");
      console.log(`  POST http://127.0.0.1:${config.port}/v1/messages - Anthropic`);
      console.log(`  POST http://127.0.0.1:${config.port}/v1/chat/completions - OpenAI`);
      console.log(`  POST http://127.0.0.1:${config.port}/v1/models/:model:generateContent - Gemini`);
      console.log(`  GET  http://127.0.0.1:${config.port}/health - Health check`);
    });

    // Handle shutdown
    process.on("SIGINT", () => {
      console.log("\n[moltguard-gateway] Shutting down...");
      vault.destroySession(gatewaySessionId);
      vault.close();
      server.close(() => {
        console.log("[moltguard-gateway] Server stopped");
        process.exit(0);
      });
    });

    process.on("SIGTERM", () => {
      console.log("\n[moltguard-gateway] Shutting down...");
      vault.destroySession(gatewaySessionId);
      vault.close();
      server.close(() => {
        console.log("[moltguard-gateway] Server stopped");
        process.exit(0);
      });
    });
  } catch (error) {
    console.error("[moltguard-gateway] Failed to start:", error);
    process.exit(1);
  }
}

// Start if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const configPath = process.argv[2];
  startGateway(configPath);
}
