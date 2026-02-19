/**
 * Simple test for the gateway sanitizer
 */

import { sanitize } from "./sanitizer.js";
import { restore } from "./restorer.js";

let passed = 0;
let failed = 0;

function runTest(name: string, input: any, expectedCategories: string[]) {
  console.log(`\n=== ${name} ===`);

  const result = sanitize(input);
  const sanitizedStr = JSON.stringify(result.sanitized);
  const restoredData = restore(result.sanitized, result.mappingTable);
  const roundTrip = JSON.stringify(input) === JSON.stringify(restoredData);

  // Show redactions
  if (result.redactionCount > 0) {
    result.mappingTable.forEach((original, placeholder) => {
      console.log(`  ${placeholder} → ${original}`);
    });
  } else {
    console.log("  (no redactions)");
  }

  // Check expected categories were detected
  const detectedCategories = Object.keys(result.redactionsByCategory);
  const missing = expectedCategories.filter((c) => !detectedCategories.includes(c));
  const categoryPass = missing.length === 0;

  if (!categoryPass) {
    console.log(`  FAIL: Missing categories: ${missing.join(", ")}`);
    console.log(`  Detected: ${detectedCategories.join(", ")}`);
    failed++;
  } else if (!roundTrip) {
    console.log(`  FAIL: Round-trip mismatch`);
    failed++;
  } else {
    console.log(`  PASS (${result.redactionCount} redactions, round-trip OK)`);
    passed++;
  }

  // Check no original values leaked into sanitized output
  result.mappingTable.forEach((original, placeholder) => {
    if (sanitizedStr.includes(original)) {
      console.log(`  LEAK: "${original}" still present in sanitized output!`);
    }
  });
}

// ---------------------------------------------------------------------------
// Original tests
// ---------------------------------------------------------------------------

runTest("Bank Card", [
  { role: "user", content: "我的银行卡号是 6222021234567890，请帮我订酒店" },
], ["credit_card"]);

runTest("Multiple Data Types", [
  { role: "user", content: "我的邮箱是 user@example.com，卡号 6222021234567890，手机 +86-138-1234-5678" },
  { role: "assistant", content: [{ type: "text", text: "好的，我收到了您的信息" }] },
  { role: "user", content: [{ type: "tool_result", tool_use_id: "123", content: "API key: sk-1234567890abcdef" }] },
], ["email", "credit_card", "phone", "secret"]);

// ---------------------------------------------------------------------------
// New gap tests
// ---------------------------------------------------------------------------

// 1. All-caps person names (tax form format)
runTest("All-Caps Names", [
  { role: "user", content: "Taxpayer: JOHN SMITH\nSpouse: MARY ANNE JONES\nPreparer: THOMAS DEHART" },
], ["person"]);

// 2. Standalone dates (no DOB keyword needed)
runTest("Standalone Dates", [
  { role: "user", content: "Filed on 04/15/1985. Payment due 12-31-2024. Received 2024-03-15." },
], ["date"]);

// 3. DOB with keyword (existing — should still work)
runTest("DOB with keyword", [
  { role: "user", content: "DOB: 07/04/1990. Date of birth is 1985-11-22." },
], ["dob"]);

// 4. Routing numbers near bank keywords
runTest("Routing Number", [
  { role: "user", content: "Direct deposit routing number: 021000021, account 12345678901" },
], ["routing_number", "bank_account"]);

// 5. Context-aware currency (no $ prefix)
runTest("Currency Without Dollar Sign", [
  { role: "user", content: "Wages 50,000. Total income 120000.00. Net salary 75,432.10." },
], ["currency"]);

// 6. Currency WITH $ prefix (existing — should still work)
runTest("Currency With Dollar Sign", [
  { role: "user", content: "Refund amount: $3,456.78. Balance due: $12,345.00." },
], ["currency"]);

// 7. Partial addresses (no city/state/zip)
runTest("Partial Address", [
  { role: "user", content: "Client lives at 123 Main Street. Office is at 456 Oak Ave." },
], ["partial_address"]);

// 8. Full addresses (existing — should still work)
runTest("Full Address", [
  { role: "user", content: "Address: 742 Evergreen Terrace, Springfield, IL 62704" },
], ["address"]);

// 9. SSN / EIN (existing — should still work)
runTest("SSN and EIN", [
  { role: "user", content: "SSN: 123-45-6789. Employer EIN: 12-3456789." },
], ["ssn", "ein"]);

// 10. Mixed tax document scenario
runTest("Full Tax Document Scenario", [
  { role: "user", content: [
    "Form 1040 - Individual Income Tax Return",
    "",
    "Taxpayer: JOHN WILLIAM SMITH",
    "SSN: 234-56-7890",
    "DOB: 03/15/1978",
    "Address: 456 Oak Dr",
    "Email: john.smith@email.com",
    "Phone: (555) 123-4567",
    "",
    "Filing Status: Married Filing Joint",
    "Spouse: JANE MARIE SMITH",
    "Spouse SSN: 345-67-8901",
    "",
    "Wages: 85,000",
    "Interest income 2,450.00",
    "Total income: $87,450.00",
    "Adjusted gross income 82,100",
    "",
    "Direct deposit routing: 021000021",
    "Account: 98765432100",
    "",
    "Date filed: 04/15/2024",
    "Tax year 2023",
  ].join("\n") },
], ["person", "ssn", "email", "phone", "currency", "date", "routing_number", "bank_account"]);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log("\n\n=== Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);
if (failed > 0) {
  process.exit(1);
}
