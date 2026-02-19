/**
 * FULL Section 7216 Compliance Test Suite for MoltGuard Sanitizer
 *
 * Validates all three categories of protected information:
 *   1. Direct Identifiers (names, SSN/EIN/ITIN, contact details)
 *   2. Derived Financial Information (AGI, entity classification, assets)
 *   3. Intent-Linked Administrative Data (worksheets, IRS correspondence, employment)
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

  for (const pii of expectations.mustRedact || []) {
    if (sanitized.includes(pii)) {
      ok = false;
      failures.push({ name, issue: `PII leaked: "${pii}"`, sanitized });
    }
  }

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

  for (const keep of expectations.mustKeep || []) {
    if (!sanitized.includes(keep)) {
      ok = false;
      failures.push({ name, issue: `Non-PII text lost: "${keep}"`, sanitized });
    }
  }

  if (ok) {
    console.log(`  ✅ PASS  ${name}`);
    passed++;
  } else {
    console.log(`  ❌ FAIL  ${name}`);
    failed++;
  }

  return { result, sanitized };
}

// ============================================================================
console.log("\n" + "=".repeat(72));
console.log("  SECTION 7216 FULL COMPLIANCE TEST SUITE");
console.log("=".repeat(72));

// ============================================================================
// CATEGORY 1: DIRECT IDENTIFIERS ("The Big Three")
// ============================================================================
console.log("\n" + "─".repeat(72));
console.log("  CATEGORY 1: Direct Identifiers");
console.log("─".repeat(72));

// --- 1a. Full Legal Names ---
console.log("\n  1a. Full Legal Names (including spouses, dependents, partners)");

test("Taxpayer full name", "The taxpayer is John Michael Smith.", {
  mustRedact: ["John Michael Smith"],
  expectCategories: ["person"],
});

test("Spouse name", "Spouse: Jennifer Anne Smith, filing jointly.", {
  mustRedact: ["Jennifer Anne Smith"],
  expectCategories: ["person"],
});

test("Dependent names", "Dependents listed: Emily Rose Smith (age 12), James Thomas Smith (age 8).", {
  mustRedact: ["Emily Rose Smith", "James Thomas Smith"],
  expectCategories: ["person"],
});

test("Business partner names", "K-1 partners: David Chen and Lisa Martinez each own 50%.", {
  mustRedact: ["David Chen", "Lisa Martinez"],
  expectCategories: ["person"],
});

test("Three-word name", "Prepared for Maria Elena Rodriguez by our office.", {
  mustRedact: ["Maria Elena Rodriguez"],
  expectCategories: ["person"],
});

// --- 1b. Identifying Numbers ---
console.log("\n  1b. Identifying Numbers (SSN, EIN, ITIN)");

test("SSN with dashes", "SSN: 123-45-6789", {
  mustRedact: ["123-45-6789"],
  expectCategories: ["ssn"],
});

test("SSN without dashes", "SSN: 123456789", {
  mustRedact: ["123456789"],
  expectCategories: ["ssn"],
});

test("SSN with spaces", "SSN: 123 45 6789", {
  mustRedact: ["123 45 6789"],
  expectCategories: ["ssn"],
});

test("Spouse SSN", "Primary SSN: 111-22-3333, Spouse SSN: 444-55-6666", {
  mustRedact: ["111-22-3333", "444-55-6666"],
  expectCategories: ["ssn"],
});

test("ITIN (starts with 9)", "ITIN: 912-34-5678", {
  mustRedact: ["912-34-5678"],
  expectCategories: ["itin"],
});

test("ITIN (900-range)", "Non-resident ITIN: 900-70-1234", {
  mustRedact: ["900-70-1234"],
  expectCategories: ["itin"],
});

test("ITIN without dashes", "ITIN: 912345678", {
  mustRedact: ["912345678"],
  expectCategories: ["itin"],
});

test("EIN standard format", "Business EIN: 12-3456789", {
  mustRedact: ["12-3456789"],
  expectCategories: ["ein"],
});

test("Multiple EINs", "Parent EIN: 98-7654321, Subsidiary EIN: 11-2233445", {
  mustRedact: ["98-7654321", "11-2233445"],
  expectCategories: ["ein"],
});

test("SSN vs ITIN distinction", "SSN 234-56-7890 and ITIN 999-88-7777 on same return", {
  mustRedact: ["234-56-7890", "999-88-7777"],
  expectCategories: ["ssn", "itin"],
});

// --- 1c. Contact Details ---
console.log("\n  1c. Contact Details (addresses, phones, emails)");

test("Full US address", "Home: 123 Main Street, Springfield, IL 62701", {
  mustRedact: ["123 Main Street"],
  expectCategories: ["address"],
});

test("Address with suite", "Office: 456 Oak Avenue, Suite 200, Portland, OR 97201", {
  mustRedact: ["456 Oak Avenue"],
  expectCategories: ["address"],
});

test("PO Box address", "Mail to P.O. Box 1234, Dallas, TX 75201", {
  mustRedact: ["P.O. Box 1234, Dallas, TX 75201"],
  expectCategories: ["address"],
});

test("US phone (parenthesized)", "Contact: (512) 555-0199", {
  mustRedact: ["(512) 555-0199"],
  expectCategories: ["phone"],
});

test("US phone (dashes)", "Phone: 512-555-0199", {
  mustRedact: ["512-555-0199"],
  expectCategories: ["phone"],
});

test("Phone with country code", "International: +1 555-987-6543", {
  mustRedact: ["+1 555-987-6543"],
  expectCategories: ["phone"],
});

test("Email address", "Email: taxpayer@example.com", {
  mustRedact: ["taxpayer@example.com"],
  expectCategories: ["email"],
});

test("Email with plus addressing", "Contact: john.doe+tax@gmail.com for correspondence.", {
  mustRedact: ["john.doe+tax@gmail.com"],
  expectCategories: ["email"],
});

// ============================================================================
// CATEGORY 2: DERIVED FINANCIAL INFORMATION
// ============================================================================
console.log("\n" + "─".repeat(72));
console.log("  CATEGORY 2: Derived Financial Information");
console.log("─".repeat(72));

// --- 2a. Tax Line Items ---
console.log("\n  2a. Tax Line Items (AGI, liability, refunds, credits)");

test("Adjusted Gross Income", "AGI: $125,000.00 for the tax year 2024 return.", {
  mustRedact: ["$125,000.00"],
  expectCategories: ["currency"],
});

test("Total tax liability", "Total federal tax liability is $18,432.00.", {
  mustRedact: ["$18,432.00"],
  expectCategories: ["currency"],
});

test("Refund amount", "Refund expected: $3,247.00 via direct deposit.", {
  mustRedact: ["$3,247.00"],
  expectCategories: ["currency"],
});

test("Earned Income Credit", "Earned Income Credit (EIC): $2,100.00 claimed on line 27.", {
  mustRedact: ["$2,100.00"],
  expectCategories: ["currency"],
});

test("Child Tax Credit", "Child Tax Credit: $4,000.00 for two qualifying dependents.", {
  mustRedact: ["$4,000.00"],
  expectCategories: ["currency"],
});

test("Multiple line items", "Line 11 AGI: $85,000.00, Line 24 total tax: $9,200.00, Line 34 refund: $1,800.00", {
  mustRedact: ["$85,000.00", "$9,200.00", "$1,800.00"],
  expectCategories: ["currency"],
});

test("Small dollar amounts", "Filing fee: $35.00, late penalty: $125.00", {
  mustRedact: ["$35.00", "$125.00"],
  expectCategories: ["currency"],
});

// --- 2b. Entity Classification ---
console.log("\n  2b. Entity Classification (filing status, entity type)");

// These are contextual identifiers — we check that the amounts near them are redacted
// The classification terms themselves (Single, S-Corp, etc.) are descriptive and may remain
test("Single filer with AGI", "Single filer, AGI $52,000.00, standard deduction applied.", {
  mustRedact: ["$52,000.00"],
  expectCategories: ["currency"],
  mustKeep: ["standard deduction"],
});

test("S-Corp K-1 distribution", "S-Corp K-1 shows ordinary business income of $145,000.00.", {
  mustRedact: ["$145,000.00"],
  expectCategories: ["currency"],
});

test("Schedule C self-employment", "Schedule C net profit: $67,800.00 from sole proprietorship.", {
  mustRedact: ["$67,800.00"],
  expectCategories: ["currency"],
});

test("High net worth amounts", "Total assets reported: $2,450,000.00 on Form 8938.", {
  mustRedact: ["$2,450,000.00"],
  expectCategories: ["currency"],
});

// --- 2c. Investment/Asset Details ---
console.log("\n  2c. Investment/Asset Details (holdings, crypto, bank balances)");

test("Stock holding value", "Brokerage account shows $340,000.00 in securities.", {
  mustRedact: ["$340,000.00"],
  expectCategories: ["currency"],
});

test("Capital gains", "Long-term capital gains from AAPL: $12,500.00.", {
  mustRedact: ["$12,500.00"],
  expectCategories: ["currency"],
});

test("Bank balance", "Checking account balance: $45,678.00 at end of year.", {
  mustRedact: ["$45,678.00"],
  expectCategories: ["currency"],
});

test("Crypto wallet address (Ethereum)", "Ethereum wallet 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38 reported.", {
  // High-entropy hex string should be caught by entropy detector or as a secret
  mustRedact: ["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD38"],
});

test("Rental income", "Rental property income: $24,000.00 annually from 3 units.", {
  mustRedact: ["$24,000.00"],
  expectCategories: ["currency"],
});

// ============================================================================
// CATEGORY 3: INTENT-LINKED ADMINISTRATIVE DATA
// ============================================================================
console.log("\n" + "─".repeat(72));
console.log("  CATEGORY 3: Intent-Linked Administrative Data");
console.log("─".repeat(72));

// --- 3a. Worksheets & Calculations ---
console.log("\n  3a. Worksheets & Calculations");

test("Deduction worksheet amounts", "Client's deduction worksheet: mortgage interest $14,200.00, SALT $10,000.00, charitable $5,500.00.", {
  mustRedact: ["$14,200.00", "$10,000.00", "$5,500.00"],
  expectCategories: ["currency"],
});

test("Depreciation schedule", "MACRS depreciation on equipment: $8,750.00 for tax year 2024.", {
  mustRedact: ["$8,750.00"],
  expectCategories: ["currency"],
});

test("Estimated tax payment worksheet", "Q1: $3,000.00, Q2: $3,000.00, Q3: $3,500.00, Q4: $3,500.00", {
  mustRedact: ["$3,000.00", "$3,500.00"],
  expectCategories: ["currency"],
});

// --- 3b. IRS Correspondence ---
console.log("\n  3b. IRS Correspondence (notice dates, numbers, inquiries)");

test("IRS notice with SSN context", "IRS Notice CP2000 regarding SSN 234-56-7890, proposing additional tax of $4,200.00.", {
  mustRedact: ["234-56-7890", "$4,200.00"],
  expectCategories: ["ssn", "currency"],
});

test("Audit correspondence amounts", "IRS examination proposes disallowance of $15,000.00 in business expenses.", {
  mustRedact: ["$15,000.00"],
  expectCategories: ["currency"],
});

test("Notice with taxpayer name", "Notice sent to Robert Johnson at 789 Oak Lane, Denver, CO 80201 regarding tax year 2023.", {
  mustRedact: ["Robert Johnson", "789 Oak Lane, Denver, CO 80201"],
  expectCategories: ["person", "address"],
});

// --- 3c. Employment Data ---
console.log("\n  3c. Employment Data (employer names, salary, job titles)");

test("W-2 wages", "W-2 from Acme Corp: wages $92,340.00, federal withholding $12,500.00.", {
  mustRedact: ["$92,340.00", "$12,500.00"],
  expectCategories: ["currency"],
});

test("Multiple employer W-2s", "W-2 #1: $45,000.00 wages, W-2 #2: $32,000.00 wages.", {
  mustRedact: ["$45,000.00", "$32,000.00"],
  expectCategories: ["currency"],
});

test("1099-NEC contractor income", "1099-NEC nonemployee compensation: $28,500.00 from consulting.", {
  mustRedact: ["$28,500.00"],
  expectCategories: ["currency"],
});

// ============================================================================
// COMPREHENSIVE REALISTIC SCENARIOS
// ============================================================================
console.log("\n" + "─".repeat(72));
console.log("  COMPREHENSIVE REALISTIC SCENARIOS");
console.log("─".repeat(72));

// Scenario 1: Complete tax return
const fullReturn = `Tax Return Summary - Joint Filing

Taxpayer: Maria Elena Garcia
SSN: 234-56-7890
DOB: 03/15/1985
Spouse: Carlos Antonio Garcia
Spouse SSN: 345-67-8901
Address: 789 Elm Drive, Austin, TX 78701
Phone: (512) 555-0199
Email: maria.garcia@email.com

Tax Year 2024 - Form 1040 Joint Return

Employment:
  Employer: Acme Corporation (EIN: 74-1234567)
  W-2 Wages: $92,340.00
  Federal Withholding: $12,500.00

Other Income:
  Interest Income (1099-INT): $1,250.00
  Dividend Income (1099-DIV): $3,200.00
  Capital Gains (Schedule D): $8,750.00

Total Income: $105,540.00
Adjustments: $2,500.00
AGI: $103,040.00

Deductions:
  Mortgage Interest: $14,200.00
  State/Local Taxes: $10,000.00
  Charitable Contributions: $5,500.00
  Total Itemized: $29,700.00

Taxable Income: $73,340.00
Tax Liability: $10,280.00
Credits Applied: $4,000.00
Net Tax: $6,280.00
Payments/Withholding: $12,500.00
Refund: $6,220.00`;

const { result: fullResult, sanitized: fullSanitized } = test(
  "Complete joint tax return",
  fullReturn,
  {
    mustRedact: [
      "Maria Elena Garcia",
      "234-56-7890",
      "Carlos Antonio Garcia",
      "345-67-8901",
      "789 Elm Drive, Austin, TX 78701",
      "(512) 555-0199",
      "maria.garcia@email.com",
      "74-1234567",
      "$92,340.00",
      "$12,500.00",
      "$1,250.00",
      "$3,200.00",
      "$8,750.00",
      "$105,540.00",
      "$2,500.00",
      "$103,040.00",
      "$14,200.00",
      "$10,000.00",
      "$5,500.00",
      "$29,700.00",
      "$73,340.00",
      "$10,280.00",
      "$4,000.00",
      "$6,280.00",
      "$6,220.00",
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
    mustKeep: [
      "Form 1040",
      "Joint Return",
      "Schedule D",
      "Itemized",
      "Employment",
    ],
  },
);

// Scenario 2: S-Corp K-1
const scorpK1 = `K-1 (Form 1065) - S Corporation Distribution

Shareholder: Thomas Richardson
SSN: 456-78-9012
Entity: Richardson Consulting LLC
EIN: 55-1234567
Address: 321 Business Park Drive, Charlotte, NC 28201

Ordinary Business Income: $145,000.00
Guaranteed Payments: $60,000.00
Section 179 Deduction: $25,000.00
Shareholder Distributions: $80,000.00
Basis at Year End: $120,000.00`;

test("S-Corp K-1 scenario", scorpK1, {
  mustRedact: [
    "Thomas Richardson",
    "456-78-9012",
    "55-1234567",
    "321 Business Park Drive, Charlotte, NC 28201",
    "$145,000.00",
    "$60,000.00",
    "$25,000.00",
    "$80,000.00",
    "$120,000.00",
  ],
  expectCategories: ["person", "ssn", "ein", "address", "currency"],
  mustKeep: ["K-1", "Form 1065", "S Corporation"],
});

// Scenario 3: IRS Audit Correspondence
const auditCorrespondence = `IRS Examination Report

Taxpayer: Robert Andrew Johnson
SSN: 567-89-0123
Address: 456 Pine Street, Seattle, WA 98101
Phone: (206) 555-1234
Email: r.johnson@email.com

Notice Number: CP2000
Tax Year Under Examination: 2023

Proposed Changes:
  Unreported 1099-K Income: $45,000.00
  Additional Self-Employment Tax: $6,885.00
  Accuracy Penalty (20%): $1,377.00
  Total Proposed Assessment: $53,262.00

Taxpayer Response Due: Within 30 days of notice date.`;

test("IRS audit correspondence scenario", auditCorrespondence, {
  mustRedact: [
    "Robert Andrew Johnson",
    "567-89-0123",
    "456 Pine Street, Seattle, WA 98101",
    "(206) 555-1234",
    "r.johnson@email.com",
    "$45,000.00",
    "$6,885.00",
    "$1,377.00",
    "$53,262.00",
  ],
  expectCategories: ["person", "ssn", "address", "phone", "email", "currency"],
  mustKeep: ["CP2000", "Examination Report"],
});

// Scenario 4: Anthropic Messages API format
const messagesPayload = [
  {
    role: "user",
    content: [
      {
        type: "text",
        text: `Help me analyze this client's tax situation:

Client: Sarah Williams, SSN 567-89-0123
Address: 100 Maple Lane, Boston, MA 02101
Phone: (617) 555-9876
Email: s.williams@firm.com

W-2 wages: $72,000.00 from Tech Corp (EIN: 22-3344556)
1099-INT interest: $890.00
Schedule C net profit: $15,000.00

She's a single filer for tax year 2024. What credits might she qualify for?`,
      },
    ],
  },
];

test("Anthropic Messages API payload", messagesPayload, {
  mustRedact: [
    "Sarah Williams",
    "567-89-0123",
    "100 Maple Lane, Boston, MA 02101",
    "(617) 555-9876",
    "s.williams@firm.com",
    "$72,000.00",
    "22-3344556",
    "$890.00",
    "$15,000.00",
  ],
  expectCategories: ["person", "ssn", "address", "phone", "email", "currency", "ein", "tax_year"],
});

// ============================================================================
// GATEWAY LIVE TEST (if running)
// ============================================================================
console.log("\n" + "─".repeat(72));
console.log("  GATEWAY LIVE PROXY TEST (port 8900)");
console.log("─".repeat(72));

async function testGatewayLive() {
  const testPayload = {
    model: "claude-sonnet-4-5-20250929",
    max_tokens: 10,
    messages: [
      {
        role: "user",
        content: `My client John Doe, SSN 111-22-3333, earned $95,000.00 in tax year 2024. His address is 100 Oak Street, Dallas, TX 75201. Phone: (214) 555-0100. Email: john.doe@example.com.`,
      },
    ],
  };

  try {
    const resp = await fetch("http://127.0.0.1:8900/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "test-key-for-sanitization-check",
      },
      body: JSON.stringify(testPayload),
    });

    // We don't care about the API response (it will fail with bad key).
    // We care about the gateway logs showing redactions happened.
    console.log(`\n  Gateway responded with status: ${resp.status}`);
    if (resp.status === 401 || resp.status === 400) {
      console.log("  ✅ PASS  Gateway is proxying (auth error expected with test key)");
      passed++;
    } else if (resp.status === 200) {
      console.log("  ✅ PASS  Gateway proxied request successfully");
      passed++;
    } else {
      const body = await resp.text();
      console.log(`  ⚠️  Unexpected status ${resp.status}: ${body.slice(0, 200)}`);
    }
  } catch (err) {
    console.log(`  ⚠️  Gateway not reachable: ${err.message}`);
    console.log("  SKIP  Gateway live test (service may not be running)");
  }
}

await testGatewayLive();

// ============================================================================
// RESULTS
// ============================================================================
console.log("\n" + "=".repeat(72));
console.log("  RESULTS");
console.log("=".repeat(72));
console.log(`\n  Total:  ${passed + failed}`);
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
console.log(`  Rate:   ${((passed / (passed + failed)) * 100).toFixed(1)}%`);

if (failures.length > 0) {
  console.log("\n" + "=".repeat(72));
  console.log("  FAILURE DETAILS");
  console.log("=".repeat(72));
  for (const f of failures) {
    console.log(`\n  [${f.name}]`);
    console.log(`    Issue: ${f.issue}`);
    console.log(`    Output: ${f.sanitized.slice(0, 300)}...`);
  }
}

// Print complete return sanitization for manual review
console.log("\n" + "=".repeat(72));
console.log("  SANITIZED OUTPUT — Complete Joint Return (manual review)");
console.log("=".repeat(72));
console.log(fullSanitized);

console.log("\n" + "=".repeat(72));
console.log("  REDACTION MAP — Complete Joint Return");
console.log("=".repeat(72));
for (const [placeholder, original] of fullResult.mappingTable) {
  console.log(`  ${placeholder.padEnd(22)} → ${original}`);
}
console.log(`\n  Categories: ${JSON.stringify(fullResult.redactionsByCategory)}`);

process.exit(failed > 0 ? 1 : 0);
