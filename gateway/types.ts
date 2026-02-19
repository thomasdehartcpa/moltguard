/**
 * Gateway types
 */

// Mapping from placeholder to original value
export type MappingTable = Map<string, string>;

// Result of sanitization with mapping table
export type SanitizeResult = {
  sanitized: any; // Sanitized content (same structure as input)
  mappingTable: MappingTable; // placeholder -> original value
  redactionCount: number; // Total redactions made
  redactionsByCategory: Record<string, number>; // Per-category redaction counts (for compliance logging)
};

// Gateway configuration
export type GatewayConfig = {
  port: number;
  backends: {
    anthropic?: {
      baseUrl: string;
      apiKey: string;
    };
    openai?: {
      baseUrl: string;
      apiKey: string;
    };
    gemini?: {
      baseUrl: string;
      apiKey: string;
    };
  };
  // Optional: route specific paths to specific backends
  routing?: {
    [path: string]: keyof GatewayConfig["backends"];
  };
};

// Entity match
export type EntityMatch = {
  originalText: string;
  category: string;
  placeholder: string;
};

// UUID v4 validation for session ID headers
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUuidV4(value: string): boolean {
  return UUID_V4_PATTERN.test(value);
}
