/**
 * IRC Section 7216 compliance verification test
 *
 * Tests that all taxpayer PII categories are properly redacted
 * before content reaches any external API.
 */

import { sanitize } from "./gateway/sanitizer.js";

const SAMPLE_TAXPAYER_TEXT = `
Client: John Smith
SSN: 123-45-6789
ITIN: 912-34-5678
EIN: 12-3456789
Email: john.smith@taxclient.com
Phone: (555) 867-5309
Address: 742 Evergreen Terrace, Springfield, IL 62704

Tax Year 2024 Filing Summary:
Form 1040 — Adjusted Gross Income: $125,450.00
W-2 Wages: $98,200.50
Schedule C Net Profit: $27,249.50
Estimated Tax Payments: $5,000.00
Refund Due: $1,234.56

Employer: Acme Corp, EIN 98-7654321
Jane Doe (spouse), SSN 987-65-4321
`;

console.log("=== IRC Section 7216 Compliance Test ===\n");

const result = sanitize(SAMPLE_TAXPAYER_TEXT);

console.log("--- SANITIZED OUTPUT (what the LLM would see) ---");
console.log(result.sanitized);
console.log("\n--- REDACTION SUMMARY ---");
console.log(`Total redactions: ${result.redactionCount}`);
console.log("By category:", JSON.stringify(result.redactionsByCategory, null, 2));

// Verify no raw PII leaks through
const rawValues = [
  { label: "SSN", value: "123-45-6789" },
  { label: "ITIN", value: "912-34-5678" },
  { label: "EIN (1)", value: "12-3456789" },
  { label: "EIN (2)", value: "98-7654321" },
  { label: "Email", value: "john.smith@taxclient.com" },
  { label: "Phone", value: "(555) 867-5309" },
  { label: "Currency $125,450.00", value: "$125,450.00" },
  { label: "Currency $98,200.50", value: "$98,200.50" },
  { label: "Currency $27,249.50", value: "$27,249.50" },
  { label: "Currency $5,000.00", value: "$5,000.00" },
  { label: "Currency $1,234.56", value: "$1,234.56" },
  { label: "SSN (spouse)", value: "987-65-4321" },
];

console.log("\n--- LEAK CHECK ---");
let leaks = 0;
for (const { label, value } of rawValues) {
  const leaked = (result.sanitized as string).includes(value);
  console.log(`  ${leaked ? "FAIL ✗" : "PASS ✓"} ${label}: ${leaked ? "LEAKED" : "redacted"}`);
  if (leaked) leaks++;
}

// Check tax year redaction (context-aware)
const taxYearLeaked = /\b2024\b/.test(result.sanitized as string);
console.log(`  ${taxYearLeaked ? "FAIL ✗" : "PASS ✓"} Tax Year 2024: ${taxYearLeaked ? "LEAKED" : "redacted"}`);
if (taxYearLeaked) leaks++;

// Check person names (NLP-based)
const personNames = ["John Smith", "Jane Doe"];
for (const name of personNames) {
  const leaked = (result.sanitized as string).includes(name);
  console.log(`  ${leaked ? "FAIL ✗" : "PASS ✓"} Person "${name}": ${leaked ? "LEAKED" : "redacted"}`);
  if (leaked) leaks++;
}

// Check address
const addressLeaked = (result.sanitized as string).includes("742 Evergreen");
console.log(`  ${addressLeaked ? "FAIL ✗" : "PASS ✓"} Address: ${addressLeaked ? "LEAKED" : "redacted"}`);
if (addressLeaked) leaks++;

console.log(`\n=== RESULT: ${leaks === 0 ? "ALL CHECKS PASSED" : `${leaks} LEAK(S) DETECTED`} ===`);
process.exit(leaks > 0 ? 1 : 0);
