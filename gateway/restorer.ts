/**
 * Gateway content restorer
 *
 * Restores sanitized placeholders back to original values using the mapping table.
 * Also strips LLM-fabricated placeholders that mimic the sanitization format but
 * have no corresponding entry in the mapping table.
 */

import type { MappingTable } from "./types.js";

/**
 * Pattern matching placeholder-like tokens the LLM may fabricate.
 * Matches both bracketed `[category_N]` and bare `category_N` forms.
 */
const FABRICATED_PLACEHOLDER_PATTERN =
  /\[?(person|ssn|itin|ein|email|phone|address|partial_address|currency|tax_year|dob|date|bank_account|routing_number|credit_card|bank_card|secret|ip|iban|url)_\d+\]?/g;

/**
 * Pass through LLM-fabricated placeholders unchanged.
 *
 * LLMs (especially DeepSeek) learn the `[category_N]` pattern from sanitized
 * input and fabricate NEW placeholders (e.g. `[person_389]`) for names that
 * were already properly tokenized with different numbers.  These have no
 * mapping table entry, so restoration can't replace them.
 *
 * We pass them through as-is and emit a structured warning so the caller can
 * observe what went unresolved.  We do NOT substitute natural-language
 * fallbacks like "a client" — that produces confident-sounding but wrong output
 * and is worse than showing the raw placeholder.
 *
 * Called AFTER normal restoration so only un-restored placeholders are affected.
 */
function stripFabricatedPlaceholders(text: string, mappingTable: MappingTable): string {
  return text.replace(FABRICATED_PLACEHOLDER_PATTERN, (match) => {
    // If this placeholder is in the mapping table, it should already have been
    // restored — but guard against double-processing by leaving it alone.
    const canonical = match.startsWith("[") ? match : `[${match}]`;
    if (mappingTable.has(canonical)) return match;

    // Warn and pass through unchanged so callers can see what went unresolved.
    console.warn(`[moltguard-gateway] Unresolved LLM-fabricated placeholder passed through: ${match}`);
    return match;
  });
}

/**
 * Restore placeholders in a string.
 *
 * Handles both the canonical bracketed form (`[person_1]`) and the
 * bracket-stripped form (`person_1`) that LLMs frequently produce when
 * they interpret square brackets as markdown/formatting and drop them.
 * The bracketed form is matched first so it takes priority.
 */
function restoreText(text: string, mappingTable: MappingTable): string {
  let restored = text;

  // Sort placeholders by length descending to handle nested cases
  const placeholders = Array.from(mappingTable.keys()).sort(
    (a, b) => b.length - a.length,
  );

  // Pass 1: replace canonical bracketed placeholders — e.g. [person_1]
  for (const placeholder of placeholders) {
    const originalValue = mappingTable.get(placeholder)!;
    restored = restored.split(placeholder).join(originalValue);
  }

  // Pass 2: replace bracket-stripped variants — e.g. person_1
  // LLMs (especially DeepSeek, Llama) routinely strip square brackets.
  // Uses word-boundary regex to prevent partial matches (e.g. person_1 inside person_10).
  for (const placeholder of placeholders) {
    const stripped = placeholder.slice(1, -1); // "[person_1]" → "person_1"
    const originalValue = mappingTable.get(placeholder)!;
    const escaped = stripped.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    restored = restored.replace(new RegExp(`\\b${escaped}\\b`, "g"), originalValue);
  }

  // Pass 3: strip any remaining LLM-fabricated placeholders that have no mapping
  restored = stripFabricatedPlaceholders(restored, mappingTable);

  return restored;
}

/**
 * Recursively restore any value (string, object, array)
 */
function restoreValue(value: any, mappingTable: MappingTable): any {
  // String: restore placeholders
  if (typeof value === "string") {
    return restoreText(value, mappingTable);
  }

  // Array: restore each element
  if (Array.isArray(value)) {
    return value.map((item) => restoreValue(item, mappingTable));
  }

  // Object: restore each property
  if (value !== null && typeof value === "object") {
    const restored: any = {};
    for (const [key, val] of Object.entries(value)) {
      restored[key] = restoreValue(val, mappingTable);
    }
    return restored;
  }

  // Primitives: return as-is
  return value;
}

/**
 * Restore any content (object, array, string) using the mapping table
 */
export function restore(content: any, mappingTable: MappingTable): any {
  if (mappingTable.size === 0) return content;
  return restoreValue(content, mappingTable);
}

/**
 * Restore a JSON string
 * Useful for SSE streaming where each chunk is a JSON string
 */
export function restoreJSON(jsonString: string, mappingTable: MappingTable): string {
  if (mappingTable.size === 0) return jsonString;

  try {
    // Try to parse as JSON first
    const parsed = JSON.parse(jsonString);
    const restored = restore(parsed, mappingTable);
    return JSON.stringify(restored);
  } catch {
    // If not valid JSON, treat as plain text
    return restoreText(jsonString, mappingTable);
  }
}

/**
 * Restore SSE data line (for streaming responses)
 * Format: "data: {...}\n"
 */
export function restoreSSELine(line: string, mappingTable: MappingTable): string {
  if (mappingTable.size === 0) return line;
  if (!line.startsWith("data: ")) return line;

  const dataContent = line.slice(6); // Remove "data: " prefix
  if (dataContent === "[DONE]") return line;

  try {
    const parsed = JSON.parse(dataContent);
    const restored = restore(parsed, mappingTable);
    return `data: ${JSON.stringify(restored)}\n`;
  } catch {
    // Fallback to text restoration
    return `data: ${restoreText(dataContent, mappingTable)}\n`;
  }
}
