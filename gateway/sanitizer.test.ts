/**
 * Gateway sanitizer tests — structural key protection and tool call roundtrips
 */

import { describe, it, expect } from "vitest";
import { sanitize } from "./sanitizer.js";
import { restore } from "./restorer.js";
import { shieldAuthArgs } from "../index.js";

// =============================================================================
// Structural Key Protection
// =============================================================================

describe("structural key protection", () => {
  it("should NOT sanitize tool_call_id values (OpenAI)", () => {
    const input = {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            {
              id: "call_abc123def456xyz",
              type: "function",
              function: {
                name: "get_weather",
                arguments: '{"location":"New York"}',
              },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_abc123def456xyz",
          content: "72°F and sunny",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].tool_calls[0].id).toBe("call_abc123def456xyz");
    expect(sanitized.messages[1].tool_call_id).toBe("call_abc123def456xyz");
    expect(sanitized.messages[0].tool_calls[0].type).toBe("function");
    expect(sanitized.messages[0].role).toBe("assistant");
    expect(sanitized.messages[1].role).toBe("tool");
  });

  it("should NOT sanitize tool_use_id values (Anthropic)", () => {
    const input = {
      messages: [
        {
          role: "assistant",
          content: [
            {
              type: "tool_use",
              id: "toolu_01A09q90qw90lq917835lq9",
              name: "get_weather",
              input: { location: "New York" },
            },
          ],
        },
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "toolu_01A09q90qw90lq917835lq9",
              content: "72°F and sunny",
            },
          ],
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content[0].id).toBe("toolu_01A09q90qw90lq917835lq9");
    expect(sanitized.messages[0].content[0].type).toBe("tool_use");
    expect(sanitized.messages[1].content[0].tool_use_id).toBe("toolu_01A09q90qw90lq917835lq9");
    expect(sanitized.messages[1].content[0].type).toBe("tool_result");
  });

  it("should NOT sanitize model, role, type, or other enum fields", () => {
    const input = {
      model: "gpt-4o-2024-05-13",
      messages: [{ role: "system", content: "You are a helpful assistant." }],
      stream: true,
      temperature: 0.7,
      max_tokens: 1024,
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.model).toBe("gpt-4o-2024-05-13");
    expect(sanitized.messages[0].role).toBe("system");
    expect(sanitized.stream).toBe(true);
    expect(sanitized.temperature).toBe(0.7);
    expect(sanitized.max_tokens).toBe(1024);
  });

  it("should NOT sanitize name fields (function names)", () => {
    const input = {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            {
              id: "call_xyz789",
              type: "function",
              function: {
                name: "search_database",
                arguments: '{"query":"test"}',
              },
            },
          ],
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].tool_calls[0].function.name).toBe("search_database");
  });
});

// =============================================================================
// PII in Content Fields IS Sanitized
// =============================================================================

describe("PII sanitization in content fields", () => {
  it("should sanitize SSNs in content", () => {
    const input = {
      messages: [
        { role: "user", content: "My SSN is 123-45-6789" },
      ],
    };

    const { sanitized, redactionCount } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("123-45-6789");
    expect(redactionCount).toBeGreaterThan(0);
  });

  it("should sanitize emails in content", () => {
    const input = {
      messages: [
        { role: "user", content: "Email me at john.doe@example.com" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("john.doe@example.com");
  });

  it("should sanitize PII in tool result content", () => {
    const input = {
      messages: [
        {
          role: "tool",
          tool_call_id: "call_abc123def456xyz",
          content: "Customer SSN: 987-65-4321, Email: jane@test.com",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    // tool_call_id preserved
    expect(sanitized.messages[0].tool_call_id).toBe("call_abc123def456xyz");
    // PII sanitized
    expect(sanitized.messages[0].content).not.toContain("987-65-4321");
    expect(sanitized.messages[0].content).not.toContain("jane@test.com");
  });

  it("should sanitize PII inside function arguments", () => {
    const input = {
      messages: [
        {
          role: "assistant",
          tool_calls: [
            {
              id: "call_abc123",
              type: "function",
              function: {
                name: "update_customer",
                arguments: JSON.stringify({
                  name: "John Smith",
                  ssn: "111-22-3333",
                  email: "john@corp.com",
                }),
              },
            },
          ],
        },
      ],
    };

    const { sanitized } = sanitize(input);
    const args = sanitized.messages[0].tool_calls[0].function.arguments;

    // arguments is a string field (not in STRUCTURAL_KEYS), so PII inside gets sanitized
    expect(args).not.toContain("111-22-3333");
    expect(args).not.toContain("john@corp.com");
    // structural fields preserved
    expect(sanitized.messages[0].tool_calls[0].id).toBe("call_abc123");
    expect(sanitized.messages[0].tool_calls[0].function.name).toBe("update_customer");
  });

  it("should sanitize PII that happens to look like a tool_call_id in content", () => {
    // Edge case: a content field contains a string that looks like a tool call ID
    // but it's in a content field, so it should still be evaluated for sanitization
    const input = {
      messages: [
        {
          role: "user",
          content: "My secret API key is sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain(
      "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    );
  });
});

// =============================================================================
// OpenAI Roundtrip Tests
// =============================================================================

describe("OpenAI tool call roundtrip", () => {
  it("should roundtrip a full chat completion request with tool_calls", () => {
    const original = {
      model: "gpt-4o",
      messages: [
        {
          role: "system",
          content: "You are a helpful tax assistant.",
        },
        {
          role: "user",
          content: "Look up the record for SSN 234-56-7890, email john.smith@taxfirm.com",
        },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_kR9f2xYz7mN4pQ1wE8vL3s",
              type: "function",
              function: {
                name: "lookup_taxpayer",
                arguments: JSON.stringify({
                  ssn: "234-56-7890",
                  email: "john.smith@taxfirm.com",
                }),
              },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_kR9f2xYz7mN4pQ1wE8vL3s",
          content: JSON.stringify({
            name: "John Smith",
            ssn: "234-56-7890",
            address: "742 Evergreen Terrace, Springfield, IL 62704",
            phone: "(555) 867-5309",
          }),
        },
        {
          role: "assistant",
          content: "I found the taxpayer record for John Smith.",
        },
      ],
      temperature: 0.2,
      max_tokens: 4096,
    };

    const { sanitized, mappingTable } = sanitize(original);

    // Structural integrity: tool_call_id must match between assistant and tool messages
    const assistantCallId = sanitized.messages[2].tool_calls[0].id;
    const toolResponseCallId = sanitized.messages[3].tool_call_id;
    expect(assistantCallId).toBe("call_kR9f2xYz7mN4pQ1wE8vL3s");
    expect(toolResponseCallId).toBe("call_kR9f2xYz7mN4pQ1wE8vL3s");
    expect(assistantCallId).toBe(toolResponseCallId);

    // PII should be sanitized
    expect(JSON.stringify(sanitized)).not.toContain("234-56-7890");
    expect(JSON.stringify(sanitized)).not.toContain("john.smith@taxfirm.com");

    // Model and other structural fields preserved
    expect(sanitized.model).toBe("gpt-4o");
    expect(sanitized.temperature).toBe(0.2);
    expect(sanitized.max_tokens).toBe(4096);

    // Roundtrip: restore should recover original
    const restored = restore(sanitized, mappingTable);
    expect(JSON.stringify(restored)).toBe(JSON.stringify(original));
  });

  it("should roundtrip multiple parallel tool calls", () => {
    const original = {
      model: "gpt-4o",
      messages: [
        {
          role: "user",
          content: "Find records for SSN 111-22-3333 and SSN 444-55-6666",
        },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_aB3dE5fG7hI9jK1lM3nO5p",
              type: "function",
              function: {
                name: "lookup_taxpayer",
                arguments: '{"ssn":"111-22-3333"}',
              },
            },
            {
              id: "call_Q7rS9tU1vW3xY5zA7bC9dE",
              type: "function",
              function: {
                name: "lookup_taxpayer",
                arguments: '{"ssn":"444-55-6666"}',
              },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_aB3dE5fG7hI9jK1lM3nO5p",
          content: '{"name":"Alice Johnson","ssn":"111-22-3333"}',
        },
        {
          role: "tool",
          tool_call_id: "call_Q7rS9tU1vW3xY5zA7bC9dE",
          content: '{"name":"Bob Williams","ssn":"444-55-6666"}',
        },
      ],
    };

    const { sanitized, mappingTable } = sanitize(original);

    // Both tool call IDs preserved and matched
    expect(sanitized.messages[1].tool_calls[0].id).toBe("call_aB3dE5fG7hI9jK1lM3nO5p");
    expect(sanitized.messages[1].tool_calls[1].id).toBe("call_Q7rS9tU1vW3xY5zA7bC9dE");
    expect(sanitized.messages[2].tool_call_id).toBe("call_aB3dE5fG7hI9jK1lM3nO5p");
    expect(sanitized.messages[3].tool_call_id).toBe("call_Q7rS9tU1vW3xY5zA7bC9dE");

    // SSNs sanitized
    expect(JSON.stringify(sanitized)).not.toContain("111-22-3333");
    expect(JSON.stringify(sanitized)).not.toContain("444-55-6666");

    // Roundtrip
    const restored = restore(sanitized, mappingTable);
    expect(JSON.stringify(restored)).toBe(JSON.stringify(original));
  });
});

// =============================================================================
// Anthropic Roundtrip Tests
// =============================================================================

describe("Anthropic tool use/tool_result roundtrip", () => {
  it("should roundtrip a full Anthropic messages request with tool_use and tool_result", () => {
    const original = {
      model: "claude-sonnet-4-5-20250929",
      max_tokens: 1024,
      messages: [
        {
          role: "user",
          content: "Look up the customer with email alice@example.com and SSN 321-54-9876",
        },
        {
          role: "assistant",
          content: [
            {
              type: "text",
              text: "I'll look that up for you.",
            },
            {
              type: "tool_use",
              id: "toolu_01XFDUDYJgAACzvnptvVSPRH",
              name: "lookup_customer",
              input: {
                email: "alice@example.com",
                ssn: "321-54-9876",
              },
            },
          ],
        },
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "toolu_01XFDUDYJgAACzvnptvVSPRH",
              content: "Name: Alice Wonderland, Phone: (555) 999-0000, Address: 100 Main St, Anytown, CA 90210",
            },
          ],
        },
        {
          role: "assistant",
          content: [
            {
              type: "text",
              text: "I found Alice Wonderland's record.",
            },
          ],
        },
      ],
    };

    const { sanitized, mappingTable } = sanitize(original);

    // Tool use IDs preserved
    const toolUseId = sanitized.messages[1].content[1].id;
    const toolResultId = sanitized.messages[2].content[0].tool_use_id;
    expect(toolUseId).toBe("toolu_01XFDUDYJgAACzvnptvVSPRH");
    expect(toolResultId).toBe("toolu_01XFDUDYJgAACzvnptvVSPRH");
    expect(toolUseId).toBe(toolResultId);

    // type and name preserved
    expect(sanitized.messages[1].content[1].type).toBe("tool_use");
    expect(sanitized.messages[1].content[1].name).toBe("lookup_customer");
    expect(sanitized.messages[2].content[0].type).toBe("tool_result");

    // PII sanitized
    const sanitizedJson = JSON.stringify(sanitized);
    expect(sanitizedJson).not.toContain("alice@example.com");
    expect(sanitizedJson).not.toContain("321-54-9876");
    expect(sanitizedJson).not.toContain("(555) 999-0000");

    // Model preserved
    expect(sanitized.model).toBe("claude-sonnet-4-5-20250929");

    // Roundtrip
    const restored = restore(sanitized, mappingTable);
    expect(JSON.stringify(restored)).toBe(JSON.stringify(original));
  });

  it("should roundtrip Anthropic tool_use with nested content blocks", () => {
    const original = {
      model: "claude-sonnet-4-5-20250929",
      max_tokens: 2048,
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "My card number is 4111-1111-1111-1111" },
          ],
        },
        {
          role: "assistant",
          content: [
            {
              type: "tool_use",
              id: "toolu_vQ8r3kLmN9pXwY2zJ5hT1sA",
              name: "process_payment",
              input: { card: "4111-1111-1111-1111", amount: 99.99 },
            },
          ],
        },
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "toolu_vQ8r3kLmN9pXwY2zJ5hT1sA",
              content: [
                { type: "text", text: "Payment processed for card ending 1111" },
              ],
            },
          ],
        },
      ],
    };

    const { sanitized, mappingTable } = sanitize(original);

    // IDs preserved
    expect(sanitized.messages[1].content[0].id).toBe("toolu_vQ8r3kLmN9pXwY2zJ5hT1sA");
    expect(sanitized.messages[2].content[0].tool_use_id).toBe("toolu_vQ8r3kLmN9pXwY2zJ5hT1sA");

    // Credit card sanitized
    expect(JSON.stringify(sanitized)).not.toContain("4111-1111-1111-1111");

    // Roundtrip
    const restored = restore(sanitized, mappingTable);
    expect(JSON.stringify(restored)).toBe(JSON.stringify(original));
  });
});

// =============================================================================
// Edge Cases
// =============================================================================

describe("edge cases", () => {
  it("should sanitize a secret in content even if it resembles a tool_call_id format", () => {
    // A user pastes an API key that happens to start with "call_"
    const input = {
      messages: [
        {
          role: "user",
          content: "My API key is sk-call_abc123def456ghi789jkl012mno345",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain(
      "sk-call_abc123def456ghi789jkl012mno345",
    );
  });

  it("should preserve system_fingerprint in response-like objects", () => {
    const input = {
      id: "chatcmpl-9ZxR5vKmEhYjQ3nW1pLs7tFg",
      object: "chat.completion",
      created: 1718000000,
      model: "gpt-4o-2024-05-13",
      system_fingerprint: "fp_abc123def456",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: "Hello! SSN 999-88-7777 found." },
          finish_reason: "stop",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.id).toBe("chatcmpl-9ZxR5vKmEhYjQ3nW1pLs7tFg");
    expect(sanitized.object).toBe("chat.completion");
    expect(sanitized.system_fingerprint).toBe("fp_abc123def456");
    expect(sanitized.model).toBe("gpt-4o-2024-05-13");
    expect(sanitized.choices[0].finish_reason).toBe("stop");
    // PII in content still sanitized
    expect(sanitized.choices[0].message.content).not.toContain("999-88-7777");
  });

  it("should handle empty messages array", () => {
    const input = { model: "gpt-4o", messages: [] };
    const { sanitized } = sanitize(input);
    expect(sanitized.messages).toEqual([]);
  });

  it("should handle null content in assistant messages", () => {
    const input = {
      messages: [
        { role: "assistant", content: null, tool_calls: [{ id: "call_abc", type: "function", function: { name: "f", arguments: "{}" } }] },
      ],
    };
    const { sanitized } = sanitize(input);
    expect(sanitized.messages[0].content).toBeNull();
    expect(sanitized.messages[0].tool_calls[0].id).toBe("call_abc");
  });
});

// =============================================================================
// Section 7216 Compliance: Bank Account Without Banking Keywords
// =============================================================================

describe("bank account numbers near financial/tax context", () => {
  it("should detect standalone account number near 'deposit'", () => {
    const input = {
      messages: [
        { role: "user", content: "Please direct deposit to 7283940182" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("7283940182");
  });

  it("should detect standalone account number near 'refund'", () => {
    const input = {
      messages: [
        { role: "user", content: "Send refund to account 038291048271" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("038291048271");
  });

  it("should detect account number near tax form reference", () => {
    const input = {
      messages: [
        { role: "user", content: "Per my 1040, deposit into 9182736450" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("9182736450");
  });

  it("should NOT flag plain 8+ digit numbers without financial context", () => {
    const input = {
      messages: [
        { role: "user", content: "Order number 7283940182 has shipped" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).toContain("7283940182");
  });
});

// =============================================================================
// Section 7216 Compliance: Address Without Street Type Suffix
// =============================================================================

describe("addresses without street type suffix", () => {
  it("should detect address without street suffix: '742 Maple, Springfield IL 62704'", () => {
    const input = {
      messages: [
        { role: "user", content: "Mail to 742 Maple, Springfield IL 62704" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("742 Maple, Springfield IL 62704");
  });

  it("should detect address with multi-word street: '100 Oak Park, Denver CO 80202'", () => {
    const input = {
      messages: [
        { role: "user", content: "Send to 100 Oak Park, Denver CO 80202" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("100 Oak Park, Denver CO 80202");
  });

  it("should detect address with ZIP+4", () => {
    const input = {
      messages: [
        { role: "user", content: "Address: 55 Elm, Austin TX 73301-0001" },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("55 Elm, Austin TX 73301-0001");
  });

  it("should NOT match across newlines", () => {
    const input = {
      messages: [
        { role: "user", content: "742 Maple\nSpringfield IL 62704" },
      ],
    };

    const { sanitized } = sanitize(input);

    // Should NOT be caught as a single address (newline breaks the pattern)
    expect(sanitized.messages[0].content).toContain("742 Maple");
  });
});

// =============================================================================
// Section 7216 Compliance: Lowercase Person Names
// =============================================================================

describe("lowercase person name detection", () => {
  it("should detect all-lowercase name 'john smith'", () => {
    const input = {
      messages: [
        { role: "user", content: "The taxpayer is john smith and he filed late." },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("john smith");
  });

  it("should detect lowercase name 'maria garcia'", () => {
    const input = {
      messages: [
        { role: "user", content: "Please look up maria garcia in our records." },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("maria garcia");
  });

  it("should still detect title-case names", () => {
    const input = {
      messages: [
        { role: "user", content: "The taxpayer is John Smith and he filed late." },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("John Smith");
  });
});

// =============================================================================
// Defense-in-Depth: API Identifiers in Content Strings
// =============================================================================

describe("defense-in-depth: API identifiers in content strings", () => {
  it("should NOT sanitize tool_call_ids that appear inside content text", () => {
    // A tool result contains a reference to a tool_call_id in its text
    const input = {
      messages: [
        {
          role: "tool",
          tool_call_id: "call_kR9f2xYz7mN4pQ1wE8vL3s",
          content: "Executed call_kR9f2xYz7mN4pQ1wE8vL3s successfully. SSN found: 123-45-6789.",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    // tool_call_id field preserved (STRUCTURAL_KEYS)
    expect(sanitized.messages[0].tool_call_id).toBe("call_kR9f2xYz7mN4pQ1wE8vL3s");
    // tool_call_id in content NOT sanitized as a secret (defense-in-depth)
    expect(sanitized.messages[0].content).toContain("call_kR9f2xYz7mN4pQ1wE8vL3s");
    // Real PII in content IS still sanitized
    expect(sanitized.messages[0].content).not.toContain("123-45-6789");
  });

  it("should NOT sanitize Anthropic tool_use_ids that appear inside content text", () => {
    const input = {
      messages: [
        {
          role: "user",
          content: [
            {
              type: "tool_result",
              tool_use_id: "toolu_01XFDUDYJgAACzvnptvVSPRH",
              content: "Result for toolu_01XFDUDYJgAACzvnptvVSPRH: email is jane@test.com",
            },
          ],
        },
      ],
    };

    const { sanitized } = sanitize(input);

    // tool_use_id field preserved
    expect(sanitized.messages[0].content[0].tool_use_id).toBe("toolu_01XFDUDYJgAACzvnptvVSPRH");
    // tool_use_id in content string NOT sanitized
    expect(sanitized.messages[0].content[0].content).toContain("toolu_01XFDUDYJgAACzvnptvVSPRH");
    // PII still sanitized
    expect(sanitized.messages[0].content[0].content).not.toContain("jane@test.com");
  });

  it("should NOT sanitize chatcmpl IDs that appear in content", () => {
    const input = {
      messages: [
        {
          role: "assistant",
          content: "Previous completion chatcmpl-9ZxR5vKmEhYjQ3nW1pLs7tFg referenced.",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).toContain("chatcmpl-9ZxR5vKmEhYjQ3nW1pLs7tFg");
  });

  it("should still sanitize real secrets that start with sk-", () => {
    const input = {
      messages: [
        {
          role: "user",
          content: "My key is sk-proj-abc123def456ghi789jkl012",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("sk-proj-abc123def456ghi789jkl012");
  });

  it("should preserve tool_call_ids in a long conversation with many redactions", () => {
    // Simulates a real multi-turn conversation with lots of PII
    // that would push the secret counter high (like secret_23)
    const original = {
      model: "deepseek-chat",
      messages: [
        { role: "user", content: "My SSN is 111-22-3333, email user1@test.com, card 4111-1111-1111-1111" },
        { role: "assistant", content: "I'll look that up." },
        { role: "user", content: "Also check SSN 222-33-4444, phone (555) 123-4567, key sk-live-abc123def456ghi789" },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
              type: "function",
              function: {
                name: "check_email",
                arguments: '{"query":"inbox"}',
              },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
          content: "Found 3 emails from alice@corp.com about SSN 333-44-5555. Reference: call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
        },
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_1_9e8d7c6b-5a4f-3e2d-1c0b-a9f8e7d6c5b4",
              type: "function",
              function: {
                name: "send_reply",
                arguments: '{"to":"alice@corp.com","body":"Re: SSN 333-44-5555"}',
              },
            },
          ],
        },
        {
          role: "tool",
          tool_call_id: "call_1_9e8d7c6b-5a4f-3e2d-1c0b-a9f8e7d6c5b4",
          content: "Email sent to alice@corp.com",
        },
      ],
    };

    const { sanitized, mappingTable } = sanitize(original);

    // ALL tool_call_ids must be preserved
    expect(sanitized.messages[3].tool_calls[0].id).toBe("call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c");
    expect(sanitized.messages[4].tool_call_id).toBe("call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c");
    expect(sanitized.messages[5].tool_calls[0].id).toBe("call_1_9e8d7c6b-5a4f-3e2d-1c0b-a9f8e7d6c5b4");
    expect(sanitized.messages[6].tool_call_id).toBe("call_1_9e8d7c6b-5a4f-3e2d-1c0b-a9f8e7d6c5b4");

    // Tool call ID in content string also preserved (defense-in-depth)
    expect(sanitized.messages[4].content).toContain("call_0_8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c");

    // PII is sanitized
    const sanitizedJson = JSON.stringify(sanitized);
    expect(sanitizedJson).not.toContain("111-22-3333");
    expect(sanitizedJson).not.toContain("222-33-4444");
    expect(sanitizedJson).not.toContain("333-44-5555");
    expect(sanitizedJson).not.toContain("user1@test.com");
    expect(sanitizedJson).not.toContain("alice@corp.com");
    expect(sanitizedJson).not.toContain("4111-1111-1111-1111");
    expect(sanitizedJson).not.toContain("sk-live-abc123def456ghi789");

    // Roundtrip
    const restored = restore(sanitized, mappingTable);
    expect(JSON.stringify(restored)).toBe(JSON.stringify(original));
  });
});

// =============================================================================
// Fabricated Placeholder Handling
// =============================================================================

describe("fabricated placeholder handling", () => {
  it("should pass fabricated placeholders through unchanged instead of substituting natural-language text", () => {
    const input = {
      messages: [
        { role: "user", content: "Tell me about John Smith and Karen Wilson." },
      ],
    };

    const { sanitized, mappingTable } = sanitize(input);

    // Verify names were sanitized
    expect(sanitized.messages[0].content).not.toContain("John Smith");
    expect(sanitized.messages[0].content).not.toContain("Karen Wilson");

    // Simulate a DeepSeek response that uses valid + fabricated placeholders
    const maxPerson = Math.max(
      ...Array.from(mappingTable.keys())
        .filter((k) => k.startsWith("[person_"))
        .map((k) => parseInt(k.match(/\d+/)![0], 10)),
    );
    const fabricatedN = maxPerson + 1;
    const mockResponse = {
      choices: [
        {
          message: {
            content: `[person_1] and [person_${fabricatedN}] both need help.`,
          },
        },
      ],
    };

    const restored = restore(mockResponse, mappingTable);

    // Valid placeholder should be restored to the original value
    const restoredContent = restored.choices[0].message.content;
    expect(restoredContent).not.toContain("[person_1]");

    // Fabricated placeholder must be passed through as-is — NOT substituted
    // with "a client" or any other natural-language fallback, which would
    // produce confident-sounding but wrong output.
    expect(restoredContent).toContain(`[person_${fabricatedN}]`);
    expect(restoredContent).not.toContain("a client");
    // Verify surrounding text is intact (not an empty gap)
    expect(restoredContent).toMatch(/\[person_\d+\] both need help/);
  });
});

// =============================================================================
// Email Header & Salutation Name Detection
// =============================================================================

describe("email header name detection", () => {
  it("should detect names in 'From: Name <email>' format", () => {
    const input = {
      messages: [
        {
          role: "user",
          content: "From: Karen Wilson <karen.wilson@example.com>\nSubject: Tax questions",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("Karen Wilson");
  });

  it("should detect names adjacent to angle-bracketed emails", () => {
    const input = {
      messages: [
        {
          role: "user",
          content: "The sender was Mike Johnson <mike.j@corp.com> and he asked about taxes.",
        },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("Mike Johnson");
  });
});

describe("salutation-context name detection", () => {
  it("should detect single name after 'Hi'", () => {
    const input = {
      messages: [
        { role: "user", content: "Hi Karen,\nI wanted to follow up on the tax return." },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("Karen");
  });

  it("should detect single name after 'Dear'", () => {
    const input = {
      messages: [
        { role: "user", content: "Dear Mike,\nPlease find the amended contract attached." },
      ],
    };

    const { sanitized } = sanitize(input);

    expect(sanitized.messages[0].content).not.toContain("Mike");
  });

  it("should roundtrip salutation-detected names correctly", () => {
    const input = {
      messages: [
        { role: "user", content: "Hello Nikolai,\nPlease send the documents." },
      ],
    };

    const { sanitized, mappingTable } = sanitize(input);

    // Name should be sanitized
    expect(sanitized.messages[0].content).not.toContain("Nikolai");

    // Should restore correctly
    const restored = restore(sanitized, mappingTable);
    expect(restored.messages[0].content).toContain("Nikolai");
  });
});

// =============================================================================
// Counter/Mapping Consistency
// =============================================================================

describe("counter/mapping consistency", () => {
  it("should have redactionsByCategory counts matching actual mappings", () => {
    const input = {
      messages: [
        {
          role: "user",
          content: "John Smith lives at 123 John Smith Drive, Springfield IL 62701. " +
            "His SSN is 123-45-6789.",
        },
      ],
    };

    const { redactionsByCategory, redactionCount, mappingTable } = sanitize(input);

    // Total from per-category counts should equal mappingTable.size
    const totalFromCategories = Object.values(redactionsByCategory).reduce(
      (sum, n) => sum + n,
      0,
    );
    expect(totalFromCategories).toBe(redactionCount);
    expect(redactionCount).toBe(mappingTable.size);
  });
});

// =============================================================================
// Auth Argument Shielding Integration (shield → sanitize → restore)
// =============================================================================

describe("auth argument shielding with sanitizer", () => {
  it("should preserve --account email while sanitizing --to email", () => {
    const command = 'gog gmail send --to recipient@example.com --account owner@corp.com --subject "Hi" --body "Hello"';
    const { shielded, restore: restoreAuth } = shieldAuthArgs(command);

    // Sanitize the shielded command
    const { sanitized, mappingTable } = sanitize(shielded);
    // Restore auth args in the sanitized output
    const result = restoreAuth(sanitized as string);

    // --account email should be preserved
    expect(result).toContain("owner@corp.com");
    // --to email should be sanitized (replaced with placeholder)
    expect(result).not.toContain("recipient@example.com");
  });

  it("should preserve --account email in a gog gmail search command", () => {
    const command = 'gog gmail messages search "newer_than:1d" --max 30 --account thomas@dehartcpa.com';
    const { shielded, restore: restoreAuth } = shieldAuthArgs(command);

    const { sanitized } = sanitize(shielded);
    const result = restoreAuth(sanitized as string);

    expect(result).toContain("thomas@dehartcpa.com");
    expect(result).toContain("--account thomas@dehartcpa.com");
  });

  it("should sanitize all emails when no auth flags are present", () => {
    const command = 'gog gmail send --to alice@example.com --cc bob@example.com --body "meeting notes"';
    const { shielded, restore: restoreAuth } = shieldAuthArgs(command);

    const { sanitized } = sanitize(shielded);
    const result = restoreAuth(sanitized as string);

    expect(result).not.toContain("alice@example.com");
    expect(result).not.toContain("bob@example.com");
  });

  it("should handle both --account and --client in the same command", () => {
    const command = 'gog gmail search --client my-app --account user@example.com --max 10';
    const { shielded, restore: restoreAuth } = shieldAuthArgs(command);

    const { sanitized } = sanitize(shielded);
    const result = restoreAuth(sanitized as string);

    expect(result).toContain("user@example.com");
    expect(result).toContain("my-app");
  });

  it("should roundtrip a Bash params object through shield + sanitize + restore", () => {
    const params = {
      command: 'gog gmail send --to recipient@corp.com --account owner@corp.com --body "SSN 123-45-6789"',
    };

    // Shield auth args
    const { shielded, restore: restoreAuth } = shieldAuthArgs(params.command);
    const shieldedParams = { command: shielded };

    // Sanitize
    const { sanitized: sanitizedParams } = sanitize(shieldedParams);

    // Restore auth args
    (sanitizedParams as any).command = restoreAuth((sanitizedParams as any).command);
    const result = (sanitizedParams as any).command as string;

    // Auth email preserved
    expect(result).toContain("owner@corp.com");
    // Outbound PII sanitized
    expect(result).not.toContain("recipient@corp.com");
    expect(result).not.toContain("123-45-6789");
  });
});
