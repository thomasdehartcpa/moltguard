/**
 * Section 7216 Compliance Test Suite for MoltGuard Sanitizer
 *
 * Tests that taxpayer PII is properly redacted before reaching LLM APIs.
 * IRC Section 7216 requires protection of: names, SSNs, ITINs, EINs,
 * addresses, income amounts, tax years, phone numbers, and email addresses.
 */

import { sanitize } from "./dist/gateway/sanitizer.js";

let passed = 0;
let failed = 0;
const failures = [];

function test(name, input, expectations) {
  const result = sanitize(input);
  const sanitized =
    typeof result.sanitized === "string"
      ? result.sanitized
      : JSON.stringify(result.sanitized);

  let ok = true;

  // Check that original PII values are NOT present in the sanitized output
  for (const pii of expectations.mustRedact || []) {
    if (sanitized.includes(pii)) {
      ok = false;
      failures.push({ name, issue: `PII leaked: "${pii}"`, sanitized });
    }
  }

  // Check that expected placeholder categories appear
  for (const cat of expectations.expectCategories || []) {
    const placeholder = `__${cat}_`;
    if (!sanitized.includes(placeholder)) {
      ok = false;
      failures.push({
        name,
        issue: `Missing category placeholder: ${cat}`,
        sanitized,
      });
    }
  }

  // Check that non-PII content is preserved
  for (const keep of expectations.mustKeep || []) {
    if (!sanitized.includes(keep)) {
      ok = false;
      failures.push({ name, issue: `Non-PII text lost: "${keep}"`, sanitized });
    }
  }

  if (ok) {
    console.log(`  PASS  ${name}`);
    passed++;
  } else {
    console.log(`  FAIL  ${name}`);
    failed++;
  }

  return result;
}

// ============================================================================
console.log("\n=== Section 7216 Compliance Tests ===\n");

// --- SSN ---
console.log("--- SSN Redaction ---");
test("SSN in plain text", "The taxpayer SSN is 123-45-6789.", {
  mustRedact: ["123-45-6789"],
  expectCategories: ["ssn"],
  mustKeep: ["taxpayer"],
});

test("Multiple SSNs", "Primary: 111-22-3333, Spouse: 444-55-6666", {
  mustRedact: ["111-22-3333", "444-55-6666"],
  expectCategories: ["ssn"],
});

// --- ITIN ---
console.log("\n--- ITIN Redaction ---");
test("ITIN detection (starts with 9)", "ITIN: 912-34-5678", {
  mustRedact: ["912-34-5678"],
  expectCategories: ["itin"],
});

test("ITIN vs SSN distinction", "SSN 123-45-6789 and ITIN 999-88-7777", {
  mustRedact: ["123-45-6789", "999-88-7777"],
  expectCategories: ["ssn", "itin"],
});

// --- EIN ---
console.log("\n--- EIN Redaction ---");
test("EIN detection", "Employer EIN: 12-3456789", {
  mustRedact: ["12-3456789"],
  expectCategories: ["ein"],
});

test("Multiple EINs", "Business A: 98-7654321, Business B: 11-2233445", {
  mustRedact: ["98-7654321", "11-2233445"],
  expectCategories: ["ein"],
});

// --- Person Names (NLP) ---
console.log("\n--- Person Name Redaction ---");
test("Full person name", "The taxpayer is John Smith and he filed on time.", {
  mustRedact: ["John Smith"],
  expectCategories: ["person"],
});

test(
  "Multiple names",
  "Jane Doe and Robert Johnson are joint filers on the 1040.",
  {
    mustRedact: ["Jane Doe", "Robert Johnson"],
    expectCategories: ["person"],
  },
);

test(
  "Name with middle initial",
  "Prepared for Michael J Anderson by our firm.",
  {
    mustRedact: ["Michael"],
    expectCategories: ["person"],
  },
);

// --- Addresses ---
console.log("\n--- Address Redaction ---");
test(
  "Full US address",
  "Taxpayer lives at 123 Main Street, Anytown, TX 75001",
  {
    mustRedact: ["123 Main Street, Anytown, TX 75001"],
    expectCategories: ["address"],
  },
);

test(
  "Address with apt/suite",
  "Mailing: 456 Oak Avenue, Suite 200, Portland, OR 97201",
  {
    mustRedact: ["456 Oak Avenue"],
    expectCategories: ["address"],
  },
);

// --- Currency / Income Amounts ---
console.log("\n--- Currency/Income Redaction ---");
test("Wages amount", "W-2 wages: $85,432.00 from employer.", {
  mustRedact: ["$85,432.00"],
  expectCategories: ["currency"],
});

test("Multiple amounts", "AGI was $125,000.00, deductions $24,500.00", {
  mustRedact: ["$125,000.00", "$24,500.00"],
  expectCategories: ["currency"],
});

test("Small amounts", "Filing fee: $35.00", {
  mustRedact: ["$35.00"],
  expectCategories: ["currency"],
});

// --- Tax Year (Context-Aware) ---
console.log("\n--- Tax Year Context-Aware Redaction ---");
test(
  "Tax year near keyword",
  "The client is filing their tax year 2024 return.",
  {
    mustRedact: ["2024"],
    expectCategories: ["tax_year"],
  },
);

test("TY abbreviation", "TY 2023 Form 1040 is due.", {
  mustRedact: ["2023"],
  expectCategories: ["tax_year"],
});

test("Year without tax context preserved", "The building was built in 1985.", {
  mustKeep: ["1985"],
});

// --- Phone Numbers ---
console.log("\n--- Phone Redaction ---");
test("US phone", "Contact: (555) 123-4567", {
  mustRedact: ["(555) 123-4567"],
  expectCategories: ["phone"],
});

test("Phone with country code", "Call +1 555-987-6543 for questions.", {
  mustRedact: ["+1 555-987-6543"],
  expectCategories: ["phone"],
});

// --- Email ---
console.log("\n--- Email Redaction ---");
test("Email address", "Send to taxpayer@example.com for review.", {
  mustRedact: ["taxpayer@example.com"],
  expectCategories: ["email"],
});

// --- Combined Realistic Scenario ---
console.log("\n--- Realistic Tax Preparation Scenario ---");
const realisticPrompt = `Please review this tax return summary:

Taxpayer: Maria Garcia
SSN: 234-56-7890
Spouse: Carlos Garcia
Spouse SSN: 345-67-8901
Address: 789 Elm Drive, Austin, TX 78701
Phone: (512) 555-0199
Email: maria.garcia@email.com

Tax Year 2024 - Form 1040 Joint Return

Employer: Acme Corp (EIN: 74-1234567)
W-2 Wages: $92,340.00
Interest Income (1099-INT): $1,250.00
Total Income: $93,590.00

Standard Deduction: $29,200.00
AGI: $64,390.00
Tax Liability: $7,280.00
Estimated payments: $6,000.00
Balance Due: $1,280.00`;

const realisticResult = test("Full tax return summary", realisticPrompt, {
  mustRedact: [
    "Maria Garcia",
    "234-56-7890",
    "Carlos Garcia",
    "345-67-8901",
    "789 Elm Drive, Austin, TX 78701",
    "(512) 555-0199",
    "maria.garcia@email.com",
    "74-1234567",
    "$92,340.00",
    "$1,250.00",
    "$93,590.00",
    "$29,200.00",
    "$64,390.00",
    "$7,280.00",
    "$6,000.00",
    "$1,280.00",
  ],
  expectCategories: [
    "person",
    "ssn",
    "address",
    "phone",
    "email",
    "ein",
    "currency",
    "tax_year",
  ],
  mustKeep: ["Form 1040", "Joint Return", "Standard Deduction"],
});

// --- Anthropic Messages Format Test ---
console.log("\n--- Anthropic Messages Array Format ---");
const messagesPayload = [
  {
    role: "user",
    content: [
      {
        type: "text",
        text: "Help me with a tax question. My name is Sarah Williams, SSN 567-89-0123. My W-2 shows $72,000.00 in wages for tax year 2024.",
      },
    ],
  },
];

test("Anthropic messages array structure", messagesPayload, {
  mustRedact: ["Sarah Williams", "567-89-0123", "$72,000.00"],
  expectCategories: ["person", "ssn", "currency", "tax_year"],
});

// ============================================================================
console.log("\n=== Results ===");
console.log(`Passed: ${passed}/${passed + failed}`);
console.log(`Failed: ${failed}/${passed + failed}`);

if (failures.length > 0) {
  console.log("\n=== Failure Details ===");
  for (const f of failures) {
    console.log(`\n[${f.name}]`);
    console.log(`  Issue: ${f.issue}`);
    console.log(`  Sanitized output: ${f.sanitized.slice(0, 300)}...`);
  }
}

// Print sanitized output for the realistic scenario for manual inspection
console.log("\n=== Realistic Scenario Sanitized Output (for manual review) ===");
console.log(realisticResult.sanitized);
console.log("\n=== Mapping Table ===");
for (const [placeholder, original] of realisticResult.mappingTable) {
  console.log(`  ${placeholder} -> ${original}`);
}
console.log(`\nRedactions by category:`, realisticResult.redactionsByCategory);

process.exit(failed > 0 ? 1 : 0);
