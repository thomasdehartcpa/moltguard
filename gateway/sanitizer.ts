/**
 * Gateway content sanitizer
 *
 * Recursively processes message structures, replaces sensitive data with
 * numbered placeholders, and returns a mapping table for restoration.
 *
 * IRC Section 7216 compliance: includes EIN, ITIN, currency, tax year,
 * person name, and address detection for taxpayer data protection.
 */

import type { SanitizeResult, MappingTable, EntityMatch } from "./types.js";
import winkNLP from "wink-nlp";
import model from "wink-eng-lite-web-model";

// =============================================================================
// NLP Initialization (singleton)
// =============================================================================

const nlp = winkNLP(model);
const its = nlp.its;

// =============================================================================
// Entity Definitions
// =============================================================================

type Entity = {
  category: string;
  categoryKey: string; // Used for numbered placeholders: [email_1], [email_2]
  pattern: RegExp;
};

const ENTITIES: Entity[] = [
  // URLs (must come before email to avoid partial matches)
  {
    category: "URL",
    categoryKey: "url",
    pattern: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
  },
  // Email
  {
    category: "EMAIL",
    categoryKey: "email",
    pattern: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g,
  },
  // Credit Card (4 groups of 4 digits)
  {
    category: "CREDIT_CARD",
    categoryKey: "credit_card",
    pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
  },
  // Bank Card (Chinese format: 16-19 digits)
  {
    category: "BANK_CARD",
    categoryKey: "bank_card",
    pattern: /\b\d{16,19}\b/g,
  },
  // US Currency amounts (requires $ prefix)
  {
    category: "CURRENCY",
    categoryKey: "currency",
    pattern: /\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?/g,
  },
  // ITIN (Individual Taxpayer ID — starts with 9, same format as SSN)
  // Must come BEFORE SSN so ITINs are labeled distinctly
  // Supports dashes, spaces, or no separators: 912-34-5678, 912 34 5678, 912345678
  {
    category: "ITIN",
    categoryKey: "itin",
    pattern: /\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  // SSN (###-##-#### with optional dashes/spaces/no separators)
  {
    category: "SSN",
    categoryKey: "ssn",
    pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  },
  // EIN (Employer Identification Number: ##-#######)
  {
    category: "EIN",
    categoryKey: "ein",
    pattern: /\b\d{2}-\d{7}\b/g,
  },
  // IBAN
  {
    category: "IBAN",
    categoryKey: "iban",
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b/g,
  },
  // IP Address
  {
    category: "IP_ADDRESS",
    categoryKey: "ip",
    pattern: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
  },
  // Phone numbers (US/intl formats, parenthesized area codes, +86-xxx-xxxx-xxxx)
  {
    category: "PHONE",
    categoryKey: "phone",
    pattern: /(?:[+]?[0-9]{1,3}[-\s.]?)?\(?[0-9]{3}\)?[-\s.][0-9]{3,4}[-\s.][0-9]{4,6}\b/g,
  },
  // US street addresses (number + street + type + city/state/zip)
  {
    category: "ADDRESS",
    categoryKey: "address",
    pattern: /(?<![.$\d])\d{1,5}\s+[A-Za-z0-9\s.]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Trail|Trl|Pike|Highway|Hwy|Square|Sq)\.?(?:[,\s]+(?:Suite|Ste|Apt|Unit|#)\s*\w+)?,?\s+[A-Za-z\s.]+,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?/g,
  },
  // PO Box addresses (PO Box + number + city/state/zip)
  {
    category: "ADDRESS",
    categoryKey: "address",
    pattern: /P\.?O\.?\s*Box\s+\d+,?\s+[A-Za-z\s.]+,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?/gi,
  },
  // Partial street addresses (without city/state/zip)
  // Uses [^\S\n] for spaces to prevent matching across newlines
  {
    category: "PARTIAL_ADDRESS",
    categoryKey: "partial_address",
    pattern: /(?<![.$\d])\d{1,5}[^\S\n]+[A-Za-z0-9][A-Za-z0-9\t .]*?(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Trail|Trl|Pike|Highway|Hwy|Square|Sq)\.?\b/gi,
  },
  // Addresses without street type suffix: "<number> <words>, <City> <ST> <ZIP>"
  // Anchored by the City/State/ZIP portion; prevents matching across newlines
  {
    category: "ADDRESS",
    categoryKey: "address",
    pattern: /(?<![.$\d])\d{1,5}[^\S\n]+[A-Za-z][A-Za-z0-9\t .]*?,[^\S\n]+[A-Za-z][A-Za-z\s.]*?[^\S\n]+[A-Z]{2}[^\S\n]+\d{5}(?:-\d{4})?/g,
  },
];

/**
 * Pattern matching known LLM API identifiers (tool call IDs, message IDs, etc.)
 * These are high-entropy strings that MUST NOT be treated as secrets.
 * Matches: call_*, toolu_*, chatcmpl-*, msg_*, resp_*, run_*, step_*, asst_*,
 *          and UUID-formatted strings.
 */
const API_IDENTIFIER_PATTERN =
  /^(?:call_|toolu_|chatcmpl-|msg_|resp_|run_|step_|asst_|file-|org-|snip_|tool_|block_|embd_|modr_|ft-|batch_)/;

// Known secret prefixes
const SECRET_PREFIXES = [
  "sk-",
  "sk_",
  "pk_",
  "ghp_",
  "AKIA",
  "xox",
  "SG.",
  "hf_",
  "api-",
  "token-",
  "secret-",
];

const BEARER_PATTERN = /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/g;

const SECRET_PREFIX_PATTERN = new RegExp(
  `(?:${SECRET_PREFIXES.map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})[A-Za-z0-9\\-_.~+/]{8,}=*`,
  "g",
);

// =============================================================================
// Tax Year Context-Aware Detection
// =============================================================================

const TAX_KEYWORDS = /\b(?:tax\s+year|TY|filing|return|W-2|W2|1040|1099|Schedule|Form|fiscal\s+year|FY)\b/gi;
const YEAR_PATTERN = /\b(19|20)\d{2}\b/g;
const TAX_YEAR_CONTEXT_WINDOW = 60; // characters

function collectTaxYearMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];

  // Find all tax keyword positions
  TAX_KEYWORDS.lastIndex = 0;
  const keywordPositions: number[] = [];
  let km: RegExpExecArray | null;
  while ((km = TAX_KEYWORDS.exec(content)) !== null) {
    keywordPositions.push(km.index);
  }
  if (keywordPositions.length === 0) return matches;

  // Find years near tax keywords
  YEAR_PATTERN.lastIndex = 0;
  let ym: RegExpExecArray | null;
  while ((ym = YEAR_PATTERN.exec(content)) !== null) {
    const yearPos = ym.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - yearPos) <= TAX_YEAR_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      matches.push({
        originalText: ym[0],
        category: "tax_year",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Date of Birth Context-Aware Detection
// =============================================================================

const DOB_KEYWORDS = /\b(?:DOB|date\s+of\s+birth|birthdate|birth\s+date|birthday|born)\b/gi;
const DATE_PATTERN = /\b(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})\b/g;
const ISO_DATE_PATTERN = /\b(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})\b/g;
const DOB_CONTEXT_WINDOW = 60; // characters

function collectDobMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];

  // Find all DOB keyword positions
  DOB_KEYWORDS.lastIndex = 0;
  const keywordPositions: number[] = [];
  let km: RegExpExecArray | null;
  while ((km = DOB_KEYWORDS.exec(content)) !== null) {
    keywordPositions.push(km.index);
  }
  if (keywordPositions.length === 0) return matches;

  // Find dates near DOB keywords (MM/DD/YYYY or MM-DD-YYYY)
  DATE_PATTERN.lastIndex = 0;
  let dm: RegExpExecArray | null;
  while ((dm = DATE_PATTERN.exec(content)) !== null) {
    const datePos = dm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - datePos) <= DOB_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      matches.push({
        originalText: dm[0],
        category: "dob",
        placeholder: "",
      });
    }
  }

  // Find dates near DOB keywords (YYYY-MM-DD / ISO format)
  ISO_DATE_PATTERN.lastIndex = 0;
  while ((dm = ISO_DATE_PATTERN.exec(content)) !== null) {
    const datePos = dm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - datePos) <= DOB_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      matches.push({
        originalText: dm[0],
        category: "dob",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Standalone Date Detection (all dates, not just DOB-proximate)
// =============================================================================

const STANDALONE_DATE_MM = /\b(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})\b/g;
const STANDALONE_DATE_ISO = /\b(\d{4})[\/\-](\d{1,2})[\/\-](\d{1,2})\b/g;

function isValidDate(month: number, day: number, year: number): boolean {
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;
  if (year < 1900 || year > 2100) return false;
  return true;
}

function collectDateMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];
  const seen = new Set<string>();

  // MM/DD/YYYY or MM-DD-YYYY
  STANDALONE_DATE_MM.lastIndex = 0;
  let dm: RegExpExecArray | null;
  while ((dm = STANDALONE_DATE_MM.exec(content)) !== null) {
    const month = parseInt(dm[1], 10);
    const day = parseInt(dm[2], 10);
    const year = parseInt(dm[3], 10);
    // Skip dates inside file paths (preceded by / or \ , or followed by . for extension)
    const charBeforeMM = dm.index > 0 ? content[dm.index - 1] : "";
    const endPosMM = dm.index + dm[0].length;
    const charAfterMM = endPosMM < content.length ? content[endPosMM] : "";
    if (charBeforeMM === "/" || charBeforeMM === "\\" || charAfterMM === ".") continue;
    if (isValidDate(month, day, year) && !seen.has(dm[0])) {
      seen.add(dm[0]);
      matches.push({
        originalText: dm[0],
        category: "date",
        placeholder: "",
      });
    }
  }

  // YYYY-MM-DD / YYYY/MM/DD (ISO format)
  STANDALONE_DATE_ISO.lastIndex = 0;
  while ((dm = STANDALONE_DATE_ISO.exec(content)) !== null) {
    const year = parseInt(dm[1], 10);
    const month = parseInt(dm[2], 10);
    const day = parseInt(dm[3], 10);
    // Skip dates inside file paths (preceded by / or \ , or followed by . for extension)
    const charBeforeISO = dm.index > 0 ? content[dm.index - 1] : "";
    const endPosISO = dm.index + dm[0].length;
    const charAfterISO = endPosISO < content.length ? content[endPosISO] : "";
    if (charBeforeISO === "/" || charBeforeISO === "\\" || charAfterISO === ".") continue;
    if (isValidDate(month, day, year) && !seen.has(dm[0])) {
      seen.add(dm[0]);
      matches.push({
        originalText: dm[0],
        category: "date",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Context-Aware Currency Detection (without $ prefix)
// =============================================================================

const FINANCIAL_KEYWORDS = /\b(?:wages?|income|salary|payment|refund|balance|amount|total|gross|net|compensation|earned|adjusted|taxable|liability|deduction|withholding|dividend|distribution|contribution|proceeds|revenue|cost|expense|fee|rent|royalt(?:y|ies)|alimony|stipend|bonus|commission|pension|annuity|benefit)\b/gi;
const BARE_CURRENCY_PATTERN = /\b(\d{1,3}(?:,\d{3})+(?:\.\d{2})?)\b/g;
const LARGE_NUMBER_PATTERN = /\b(\d{5,}(?:\.\d{2})?)\b/g;
const FINANCIAL_CONTEXT_WINDOW = 200; // characters

function collectFinancialAmountMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];
  const seen = new Set<string>();

  // Find all financial keyword positions
  FINANCIAL_KEYWORDS.lastIndex = 0;
  const keywordPositions: number[] = [];
  let km: RegExpExecArray | null;
  while ((km = FINANCIAL_KEYWORDS.exec(content)) !== null) {
    keywordPositions.push(km.index);
  }
  if (keywordPositions.length === 0) return matches;

  // Find comma-formatted numbers near financial keywords (e.g., 50,000 or 1,234,567.89)
  BARE_CURRENCY_PATTERN.lastIndex = 0;
  let nm: RegExpExecArray | null;
  while ((nm = BARE_CURRENCY_PATTERN.exec(content)) !== null) {
    const numPos = nm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - numPos) <= FINANCIAL_CONTEXT_WINDOW,
    );
    if (nearKeyword && !seen.has(nm[0])) {
      seen.add(nm[0]);
      matches.push({
        originalText: nm[0],
        category: "currency",
        placeholder: "",
      });
    }
  }

  // Find large plain numbers near financial keywords (e.g., 120000.00)
  LARGE_NUMBER_PATTERN.lastIndex = 0;
  while ((nm = LARGE_NUMBER_PATTERN.exec(content)) !== null) {
    const numPos = nm.index;
    if (seen.has(nm[0])) continue;
    // Skip if it looks like a year (4 digits, 1900-2100 range)
    const val = parseInt(nm[0], 10);
    if (nm[0].length === 4 && val >= 1900 && val <= 2100) continue;
    // Skip if it looks like an SSN/EIN/phone (already caught by other patterns)
    if (/^\d{9}$/.test(nm[0]) || /^\d{3}\d{2}\d{4}$/.test(nm[0])) continue;

    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - numPos) <= FINANCIAL_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      seen.add(nm[0]);
      matches.push({
        originalText: nm[0],
        category: "currency",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Context-Aware Bank Account & Routing Number Detection
// =============================================================================

const BANK_KEYWORDS = /\b(?:account|routing|ABA|checking|savings|bank\s*(?:account|number)|acct|direct\s+deposit)\b/gi;
const ROUTING_NUMBER_PATTERN = /\b(\d{9})\b/g;
const ACCOUNT_NUMBER_PATTERN = /\b(\d{8,17})\b/g;
const BANK_CONTEXT_WINDOW = 120; // characters

// Valid ABA routing number first two digits
const ABA_VALID_PREFIXES = new Set([
  "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12",
  "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32",
  "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72",
  "80",
]);

function isValidRoutingNumber(num: string): boolean {
  if (num.length !== 9) return false;
  const prefix = num.substring(0, 2);
  if (!ABA_VALID_PREFIXES.has(prefix)) return false;
  // ABA checksum validation: 3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9) mod 10 == 0
  const d = num.split("").map(Number);
  const checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
  return checksum % 10 === 0;
}

function collectBankMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];
  const seen = new Set<string>();

  // Find all bank keyword positions
  BANK_KEYWORDS.lastIndex = 0;
  const keywordPositions: number[] = [];
  let km: RegExpExecArray | null;
  while ((km = BANK_KEYWORDS.exec(content)) !== null) {
    keywordPositions.push(km.index);
  }
  if (keywordPositions.length === 0) return matches;

  // Routing numbers near bank keywords with ABA validation
  ROUTING_NUMBER_PATTERN.lastIndex = 0;
  let nm: RegExpExecArray | null;
  while ((nm = ROUTING_NUMBER_PATTERN.exec(content)) !== null) {
    if (seen.has(nm[0])) continue;
    if (!isValidRoutingNumber(nm[1])) continue;
    const numPos = nm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - numPos) <= BANK_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      seen.add(nm[0]);
      matches.push({
        originalText: nm[0],
        category: "routing_number",
        placeholder: "",
      });
    }
  }

  // Account numbers near bank keywords
  ACCOUNT_NUMBER_PATTERN.lastIndex = 0;
  while ((nm = ACCOUNT_NUMBER_PATTERN.exec(content)) !== null) {
    if (seen.has(nm[0])) continue;
    // Skip 9-digit numbers near routing keywords (valid or not — they're routing
    // numbers being discussed, not account numbers)
    if (nm[0].length === 9) continue;
    const numPos = nm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - numPos) <= BANK_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      seen.add(nm[0]);
      matches.push({
        originalText: nm[0],
        category: "bank_account",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Standalone Bank Account Detection (financial/tax context, no banking keywords)
// =============================================================================

const FINANCIAL_TAX_KEYWORDS = /\b(?:deposit|direct\s+deposit|refund|1040|8888|W-2|W2|1099|payment|transfer|wire|ACH|EFT|tax\s+return|withholding|payroll)\b/gi;
const STANDALONE_ACCOUNT_PATTERN = /\b(\d{8,12})\b/g;
const FINANCIAL_TAX_CONTEXT_WINDOW = 200; // characters

function collectStandaloneBankMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];
  const seen = new Set<string>();

  // Find all financial/tax keyword positions
  FINANCIAL_TAX_KEYWORDS.lastIndex = 0;
  const keywordPositions: number[] = [];
  let km: RegExpExecArray | null;
  while ((km = FINANCIAL_TAX_KEYWORDS.exec(content)) !== null) {
    keywordPositions.push(km.index);
  }
  if (keywordPositions.length === 0) return matches;

  // Find 8-12 digit numbers near financial/tax keywords
  STANDALONE_ACCOUNT_PATTERN.lastIndex = 0;
  let nm: RegExpExecArray | null;
  while ((nm = STANDALONE_ACCOUNT_PATTERN.exec(content)) !== null) {
    if (seen.has(nm[0])) continue;
    // Skip numbers that look like years (4 digits)
    if (nm[0].length === 4) continue;
    // Skip 9-digit numbers that pass ABA routing validation (caught by collectBankMatches)
    if (nm[0].length === 9 && isValidRoutingNumber(nm[0])) continue;
    const numPos = nm.index;
    const nearKeyword = keywordPositions.some(
      (kp) => Math.abs(kp - numPos) <= FINANCIAL_TAX_CONTEXT_WINDOW,
    );
    if (nearKeyword) {
      seen.add(nm[0]);
      matches.push({
        originalText: nm[0],
        category: "bank_account",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Shannon Entropy
// =============================================================================

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// =============================================================================
// NLP-Based Person Detection
// =============================================================================

// Common non-name title-case words to exclude from person name heuristic
const NAME_EXCLUSIONS = new Set([
  "Tax", "Year", "Form", "Schedule", "Filing", "Summary", "Client",
  "Employer", "Address", "Phone", "Email", "Income", "Wages", "Net",
  "Profit", "Estimated", "Payments", "Refund", "Due", "Adjusted",
  "Gross", "Total", "Federal", "State", "Local", "Return", "The",
  "Street", "St", "Avenue", "Ave", "Road", "Rd", "Drive", "Dr",
  "Lane", "Ln", "Court", "Ct", "Boulevard", "Blvd", "Way", "Place",
  "Terrace", "Circle", "Parkway", "Trail", "Pike", "Highway", "Square",
  "Corp", "Inc", "LLC", "LLP", "January", "February", "March",
  "April", "May", "June", "July", "August", "September", "October",
  "November", "December", "Monday", "Tuesday", "Wednesday", "Thursday",
  "Friday", "Saturday", "Sunday", "Acme", "Springfield",
  // Tax-specific terms (Section 7216 false-positive prevention)
  "Standard", "Deduction", "Interest", "Liability", "Balance",
  "Qualified", "Dividend", "Capital", "Gain", "Loss", "Taxable",
  "Withholding", "Credit", "Dependent", "Exemption", "Premium",
  "Contribution", "Distribution", "Retirement", "Social", "Security",
  "Medicare", "Itemized", "Modified", "Ordinary", "Passive", "Earned",
  "Unearned", "Nontaxable", "Allowance", "Depreciation", "Amortization",
  "Charitable", "Business", "Rental", "Royalty", "Partnership",
  // Single-letter form identifiers (W-2, K-1, etc.)
  "W", "K", "A", "B", "C", "D", "E", "F",
  // Additional tax document terms
  "Statement", "Wage", "Compensation", "Certificate",
  "Joint", "Single", "Separate", "Individual", "Annual",
  // Entity/org and IRS correspondence terms (false-positive prevention)
  "Corporation", "Examination", "Report", "Mortgage", "Contributions",
  "Gains", "Other", "Credits", "Applied", "Taxes", "Shareholder",
  "Guaranteed", "Notice", "Number", "Proposed", "Changes", "Assessment",
  "Accuracy", "Penalty",
  // Filing status and additional false-positive terms
  "Filing", "Status", "Married", "Head", "Household", "Surviving",
  "Widow", "Widower", "Preparer", "Dependent", "Spouse",
  "Direct", "Deposit", "Routing", "Account", "Checking", "Savings",
  // Government agencies and common all-caps terms in tax documents
  "IRS", "SSA", "CPA", "USA", "FBI", "CIA", "DOJ", "SEC", "DOL",
  "Amended", "Original", "Current", "Final", "Revised", "Corrected",
  "Prior", "Subsequent", "Pending", "Approved", "Denied", "Rejected",
  "Notice", "Letter", "Response", "Request", "Appeal",
]);

// Tax form label pattern — NLP sometimes identifies these as PERSON entities
const TAX_FORM_LABEL_PATTERN = /^(Form|Schedule|Statement|Wage|Tax)\b/i;

// Heuristic: two or more consecutive capitalized words that aren't common non-name words
// Uses [^\S\n]+ instead of \s+ to prevent matching across newlines
// Each word allows internal uppercase transitions for Mc/Mac/De/Le-prefixed surnames
// (e.g. "McGarry", "McDonald", "MacArthur", "DeLuca", "LeBlanc")
const TITLE_CASE_NAME_PATTERN = /\b([A-Z][a-z]+(?:[A-Z][a-z]+)*(?:[^\S\n]+[A-Z][a-z]*(?:[A-Z][a-z]+)*)+)\b/g;

// All-caps name pattern: two or more consecutive all-uppercase words (2+ chars each)
// Common on tax forms where names appear as "JOHN SMITH"
const ALL_CAPS_NAME_PATTERN = /\b([A-Z]{2,}(?:[^\S\n]+[A-Z]{2,})+)\b/g;

// Lowercase name pattern: exactly two consecutive all-lowercase words (2+ chars each)
const LOWERCASE_NAME_PATTERN = /\b([a-z]{2,})[^\S\n]+([a-z]{2,})\b/g;

// Common first names (lowercase) for anchoring lowercase name detection
const COMMON_FIRST_NAMES = new Set([
  "james", "john", "robert", "michael", "david", "william", "richard", "joseph",
  "thomas", "charles", "christopher", "daniel", "matthew", "anthony", "mark",
  "donald", "steven", "paul", "andrew", "joshua", "kenneth", "kevin", "brian",
  "george", "timothy", "ronald", "edward", "jason", "jeffrey", "ryan", "jacob",
  "gary", "nicholas", "eric", "jonathan", "stephen", "larry", "justin", "scott",
  "brandon", "benjamin", "samuel", "raymond", "gregory", "frank", "alexander",
  "patrick", "jack", "dennis", "jerry", "tyler", "aaron", "jose", "adam",
  "nathan", "henry", "peter", "zachary", "douglas", "harold", "kyle", "noah",
  "mary", "patricia", "jennifer", "linda", "barbara", "elizabeth", "susan",
  "jessica", "sarah", "karen", "lisa", "nancy", "betty", "margaret", "sandra",
  "ashley", "dorothy", "kimberly", "emily", "donna", "michelle", "carol",
  "amanda", "melissa", "deborah", "stephanie", "rebecca", "sharon", "laura",
  "cynthia", "kathleen", "amy", "angela", "shirley", "anna", "brenda", "pamela",
  "emma", "nicole", "helen", "samantha", "katherine", "christine", "debra",
  "rachel", "carolyn", "janet", "catherine", "maria", "heather", "diane",
  "ruth", "julie", "olivia", "joyce", "virginia", "victoria", "kelly", "lauren",
  "christina", "joan", "evelyn", "judith", "megan", "andrea", "cheryl", "hannah",
  "jacqueline", "martha", "gloria", "teresa", "ann", "sara", "madison", "frances",
  "kathryn", "janice", "jean", "abigail", "alice", "judy", "sophia", "grace",
  "denise", "amber", "doris", "marilyn", "danielle", "beverly", "isabella",
  "theresa", "diana", "natalie", "brittany", "charlotte", "marie", "kayla", "alexis",
]);

// Uppercase version of exclusions for all-caps matching
const NAME_EXCLUSIONS_UPPER = new Set(
  [...NAME_EXCLUSIONS].map((w) => w.toUpperCase()),
);

// Additional structural/technical terms commonly found in system prompts,
// documentation, and configuration that should NOT be treated as person names.
// These supplement NAME_EXCLUSIONS for headings and technical vocabulary that
// the heuristic capitalization patterns would otherwise false-positive on.
const STRUCTURAL_TERM_EXCLUSIONS = new Set([
  // Document/prompt structure
  "Context", "Overview", "Summary", "Details", "Notes", "Example",
  "Examples", "Usage", "Description", "Reference", "Guide", "Rules",
  "Constraints", "Requirements", "Configuration", "Settings", "Options",
  "Parameters", "Properties", "Types", "Schema", "Payload", "Modes",
  "Implementation", "Documentation", "Architecture", "Design", "Pattern",
  "Patterns", "Structure", "Format", "Formatting", "Style", "Styles",
  // LLM/AI system terms
  "System", "Message", "Messages", "Prompt", "Response", "Responses",
  "Model", "Models", "Agent", "Agents", "Session", "Sessions",
  "Tool", "Tools", "Function", "Functions", "Plugin", "Plugins",
  "Gateway", "Cache", "Caching", "Search", "Query", "Queries",
  "Identity", "Role", "Roles", "Permission", "Permissions",
  // Severity/status terms
  "Critical", "Important", "Warning", "Error", "Info", "Debug",
  "Active", "Inactive", "Enabled", "Disabled", "Default", "Custom",
  "Initialize", "Initialization", "Setup", "Config", "Manage",
  // CRUD/lifecycle verbs
  "Create", "Update", "Delete", "Read", "Write", "Execute",
  "Start", "Stop", "Pause", "Resume", "Reset", "Refresh",
  // Scheduling/job terms
  "Schedule", "Scheduled", "Wake", "Sleep", "Job", "Jobs",
  "Task", "Tasks", "Queue", "Worker", "Workers", "Process",
  "Heartbeat", "Heartbeats", "Periodic", "Interval", "Timer",
  "Daily", "Weekly", "Monthly", "Nightly", "Hourly",
  // Metrics/limits
  "Budget", "Limit", "Limits", "Rate", "Quota", "Threshold",
  "Count", "Counter", "Metric", "Metrics", "Stats", "Statistics",
  // Network/security terms
  "URL", "HTTPS", "HTTP", "API", "REST", "OAuth", "Token",
  "Private", "Public", "Virtual", "Network", "Networks",
  "Operational", "Policies", "Policy", "Incident", "Threat",
  "Awareness", "Safeguard", "Conduct", "Compliance",
  // UI terms
  "Upload", "Download", "Submit", "Notification", "Notifications",
  "View", "Views", "Dashboard", "Panel", "Menu", "Button",
  "Calendar", "Colors", "Tags", "Replies", "Follow", "Aliases",
  // General nouns common in headings
  "Foundation", "Recall", "Learnings", "Benefits", "Focus",
  "Areas", "Agreement", "Operating", "Scope", "Mode",
  "Workspace", "Files", "Project", "Inbound", "Outbound",
  "Coding", "Updates", "Override", "Subject",
  "Proactive", "Separate", "Self",
  // Product/brand names commonly misidentified as person names
  "Google", "Brave", "Claude", "Codex", "Gemini", "Llama",
  "Anthropic", "OpenAI", "DeepSeek", "Ollama", "Telegram",
  // Technical/action terms seen in false positives
  "Transport", "Frontend", "Backend", "Receipt", "Filing",
  "Organizing", "Requires", "Collective", "Serial", "Number",
  "Professionals", "Steps", "Form", "Forms",
]);

const STRUCTURAL_TERM_EXCLUSIONS_UPPER = new Set(
  [...STRUCTURAL_TERM_EXCLUSIONS].map((w) => w.toUpperCase()),
);

// Title-cased version of common first names for anchoring name detection
// in multi-word (3+) title-case candidates
const TITLE_CASE_FIRST_NAMES = new Set(
  [...COMMON_FIRST_NAMES].map((n) => n.charAt(0).toUpperCase() + n.slice(1)),
);

/**
 * Check if a match at the given position appears on a "structural" line --
 * one that starts with markdown formatting (headings, list items, bold text,
 * emphasis, etc.).  Structural lines contain headings and labels, not prose
 * with person names.
 */
function isOnStructuralLine(content: string, matchIndex: number): boolean {
  const lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
  const linePrefix = content.substring(lineStart, matchIndex).trimStart();

  // Markdown headings: # ## ### etc.
  if (/^#{1,6}\s/.test(linePrefix)) return true;
  // Bold markers: **text**
  if (/^\*\*/.test(linePrefix)) return true;
  // List items: - item or * item
  if (/^[-*]\s/.test(linePrefix)) return true;
  // Numbered list items: 1. item, 2. item
  if (/^\d+\.\s/.test(linePrefix)) return true;
  // Emphasis/italic: _text_
  if (/^_[A-Za-z]/.test(linePrefix)) return true;

  return false;
}

function collectNlpMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];
  const seen = new Set<string>();

  // NLP-based detection
  const doc = nlp.readDoc(content);
  const entities = doc.entities();

  entities.each((entity: any) => {
    const type = entity.out(its.type) as string;
    const value = entity.out() as string;

    if (type === "PERSON" && value.trim().length > 1) {
      // Trim to first line only to prevent cross-line over-capture
      const trimmed = value.split("\n")[0].trim();
      if (trimmed.length <= 1) return;
      // Skip NLP PERSON matches that are actually tax form identifiers
      if (TAX_FORM_LABEL_PATTERN.test(trimmed)) return;

      // Skip NLP PERSON matches on structural lines (headings, bold, lists)
      const entityIndex = content.indexOf(trimmed);
      if (entityIndex >= 0 && isOnStructuralLine(content, entityIndex)) return;

      // Skip NLP PERSON matches where ALL words are structural/excluded terms
      // (catches product names like "Google Workspace", labels like "Next Steps")
      const entityWords = trimmed.split(/\s+/);
      if (entityWords.length >= 2) {
        const allExcluded = entityWords.every((w) => {
          const wTitle = w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
          return NAME_EXCLUSIONS.has(w) || NAME_EXCLUSIONS.has(wTitle) ||
            STRUCTURAL_TERM_EXCLUSIONS.has(w) || STRUCTURAL_TERM_EXCLUSIONS.has(wTitle) ||
            NAME_EXCLUSIONS_UPPER.has(w.toUpperCase()) ||
            STRUCTURAL_TERM_EXCLUSIONS_UPPER.has(w.toUpperCase());
        });
        if (allExcluded) return;
      }

      seen.add(trimmed);
      matches.push({
        originalText: trimmed,
        category: "person",
        placeholder: "",
      });
    }
  });

  // Fallback: detect lowercase person names like "john smith"
  // Uses a common first-names dictionary to anchor detection
  LOWERCASE_NAME_PATTERN.lastIndex = 0;
  let lcm: RegExpExecArray | null;
  while ((lcm = LOWERCASE_NAME_PATTERN.exec(content)) !== null) {
    const candidate = lcm[0];
    if (seen.has(candidate)) continue;
    const firstName = lcm[1];
    const lastName = lcm[2];
    // First word must be a common first name
    if (!COMMON_FIRST_NAMES.has(firstName)) continue;
    // Title-case and check exclusions
    const tcFirst = firstName.charAt(0).toUpperCase() + firstName.slice(1);
    const tcLast = lastName.charAt(0).toUpperCase() + lastName.slice(1);
    if (NAME_EXCLUSIONS.has(tcFirst) || NAME_EXCLUSIONS.has(tcLast)) continue;
    seen.add(candidate);
    matches.push({
      originalText: candidate,
      category: "person",
      placeholder: "",
    });
  }

  // Fallback: title-case name heuristic for names NLP missed
  TITLE_CASE_NAME_PATTERN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TITLE_CASE_NAME_PATTERN.exec(content)) !== null) {
    const candidate = m[1];
    if (seen.has(candidate)) continue;

    // Skip matches on structural lines (markdown headings, list items, etc.)
    if (isOnStructuralLine(content, m.index)) continue;

    const words = candidate.split(/\s+/);
    const nonExcluded = words.filter(
      (w) => !NAME_EXCLUSIONS.has(w) && !STRUCTURAL_TERM_EXCLUSIONS.has(w),
    );

    if (
      words.length === 2 &&
      (nonExcluded.length === 2 || words.some((w) => TITLE_CASE_FIRST_NAMES.has(w))) &&
      nonExcluded.length >= 1
    ) {
      // 2-word matches: accept if BOTH words are non-excluded (strong name
      // signal — catches uncommon first names like "Erin Worthy") OR if at
      // least one word is a known first name (catches "Karen Settings").
      // Rejects patterns where only 1 word is non-excluded and it's not a
      // known first name (e.g. "Google Workspace", "Brave Search").
      seen.add(candidate);
      matches.push({
        originalText: candidate,
        category: "person",
        placeholder: "",
      });
    } else if (
      words.length >= 3 &&
      nonExcluded.length >= words.length - 1 &&
      words.some((w) => TITLE_CASE_FIRST_NAMES.has(w))
    ) {
      // 3+ word matches: require at least one known first name to avoid
      // false positives on section headings like "Screen Time Safeguard"
      seen.add(candidate);
      matches.push({
        originalText: candidate,
        category: "person",
        placeholder: "",
      });
    }
  }

  // Fallback: all-caps name heuristic (common on tax forms: "JOHN SMITH")
  ALL_CAPS_NAME_PATTERN.lastIndex = 0;
  while ((m = ALL_CAPS_NAME_PATTERN.exec(content)) !== null) {
    const candidate = m[1];
    if (seen.has(candidate)) continue;

    // Skip matches on structural lines (markdown headings, bold text, etc.)
    if (isOnStructuralLine(content, m.index)) continue;

    const words = candidate.split(/\s+/);
    // Limit to 2-3 words — real names on forms are "JOHN SMITH" or "MARY JANE DOE"
    if (words.length > 3) continue;

    const nonExcluded = words.filter(
      (w) => !NAME_EXCLUSIONS_UPPER.has(w) && !STRUCTURAL_TERM_EXCLUSIONS_UPPER.has(w),
    );
    // Require at least one known first name to avoid false positives on
    // government form labels ("CORRESPONDENCE INFORMATION", "PAYMENT SECTION")
    const hasKnownFirstName = words.some(
      (w) => COMMON_FIRST_NAMES.has(w.toLowerCase()),
    );
    if (words.length >= 2 && nonExcluded.length >= words.length - 1 && hasKnownFirstName) {
      seen.add(candidate);
      matches.push({
        originalText: candidate,
        category: "person",
        placeholder: "",
      });
    }
  }

  // Fallback: email header name extraction — "From: Karen Wilson <karen@example.com>"
  const EMAIL_HEADER_NAME_PATTERN =
    /(?:From|To|Cc|Bcc|Reply-To|Sender)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*<[^>]+>/g;
  EMAIL_HEADER_NAME_PATTERN.lastIndex = 0;
  while ((m = EMAIL_HEADER_NAME_PATTERN.exec(content)) !== null) {
    const candidate = m[1].trim();
    if (seen.has(candidate)) continue;
    if (candidate.split(/\s+/).every((w) => NAME_EXCLUSIONS.has(w))) continue;
    seen.add(candidate);
    matches.push({
      originalText: candidate,
      category: "person",
      placeholder: "",
    });
  }

  // Fallback: name adjacent to angle-bracketed email — "Karen Wilson <karen@example.com>"
  const NAME_BEFORE_EMAIL_PATTERN =
    /([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*<[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}>/g;
  NAME_BEFORE_EMAIL_PATTERN.lastIndex = 0;
  while ((m = NAME_BEFORE_EMAIL_PATTERN.exec(content)) !== null) {
    const candidate = m[1].trim();
    if (seen.has(candidate)) continue;
    if (candidate.split(/\s+/).every((w) => NAME_EXCLUSIONS.has(w))) continue;
    seen.add(candidate);
    matches.push({
      originalText: candidate,
      category: "person",
      placeholder: "",
    });
  }

  // Fallback: salutation-context single name — "Hi Karen," or "Dear Mike"
  const SALUTATION_NAME_PATTERN =
    /(?:^|[.\n])\s*(?:Hi|Hey|Hello|Dear|Thanks|Thank you),?\s+([A-Z][a-z]{2,})\b/gm;
  SALUTATION_NAME_PATTERN.lastIndex = 0;
  while ((m = SALUTATION_NAME_PATTERN.exec(content)) !== null) {
    const candidate = m[1];
    if (seen.has(candidate)) continue;
    if (NAME_EXCLUSIONS.has(candidate)) continue;
    seen.add(candidate);
    matches.push({
      originalText: candidate,
      category: "person",
      placeholder: "",
    });
  }

  return matches;
}

// =============================================================================
// Match Collection
// =============================================================================

function collectMatches(content: string): EntityMatch[] {
  const matches: EntityMatch[] = [];

  // Context-aware bank account & routing number detection (BEFORE regex entities
  // so routing numbers aren't consumed as SSNs by the generic 9-digit SSN pattern)
  const bankMatches = collectBankMatches(content);
  matches.push(...bankMatches);

  // Standalone bank account detection (8-12 digit numbers near financial/tax keywords)
  const standaloneBankMatches = collectStandaloneBankMatches(content);
  matches.push(...standaloneBankMatches);

  // Regex-based entities
  for (const entity of ENTITIES) {
    entity.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = entity.pattern.exec(content)) !== null) {
      matches.push({
        originalText: m[0],
        category: entity.categoryKey,
        placeholder: "", // Will be set later with numbering
      });
    }
  }

  // Context-aware tax year detection
  const taxYearMatches = collectTaxYearMatches(content);
  matches.push(...taxYearMatches);

  // Context-aware date of birth detection
  const dobMatches = collectDobMatches(content);
  matches.push(...dobMatches);

  // Standalone date detection (all dates, not just DOB-proximate)
  const dateMatches = collectDateMatches(content);
  matches.push(...dateMatches);

  // Context-aware currency detection (amounts without $ prefix near financial keywords)
  const financialMatches = collectFinancialAmountMatches(content);
  matches.push(...financialMatches);

  // NLP-based person name detection
  const nlpMatches = collectNlpMatches(content);
  matches.push(...nlpMatches);

  // Secret prefixes
  SECRET_PREFIX_PATTERN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SECRET_PREFIX_PATTERN.exec(content)) !== null) {
    if (API_IDENTIFIER_PATTERN.test(m[0])) continue; // Skip API identifiers
    matches.push({
      originalText: m[0],
      category: "secret",
      placeholder: "",
    });
  }

  // Bearer tokens
  BEARER_PATTERN.lastIndex = 0;
  while ((m = BEARER_PATTERN.exec(content)) !== null) {
    matches.push({
      originalText: m[0],
      category: "secret",
      placeholder: "",
    });
  }

  // High-entropy tokens
  const tokenPattern = /\b[A-Za-z0-9\-_.~+/]{20,}={0,3}\b/g;
  tokenPattern.lastIndex = 0;
  while ((m = tokenPattern.exec(content)) !== null) {
    const token = m[0];
    if (matches.some((existing) => existing.originalText === token)) continue;
    if (/^[a-z]+$/.test(token)) continue;
    if (API_IDENTIFIER_PATTERN.test(token)) continue; // Skip API identifiers
    if (shannonEntropy(token) >= 4.0) {
      matches.push({
        originalText: token,
        category: "secret",
        placeholder: "",
      });
    }
  }

  return matches;
}

// =============================================================================
// Text Sanitization
// =============================================================================

function sanitizeText(
  text: string,
  mappingTable: MappingTable,
  categoryCounters: Map<string, number>,
): string {
  const matches = collectMatches(text);
  if (matches.length === 0) return text;

  // Deduplicate by original text
  const unique = new Map<string, EntityMatch>();
  for (const match of matches) {
    if (!unique.has(match.originalText)) {
      unique.set(match.originalText, match);
    }
  }

  // Sort by length descending
  const sorted = [...unique.values()].sort(
    (a, b) => b.originalText.length - a.originalText.length,
  );

  // Replace and build mapping table
  let sanitized = text;
  for (const match of sorted) {
    // Only increment counter and create mapping when the match text is
    // actually present.  A shorter match may have been consumed by a longer
    // one (e.g. "Karen" inside "123 Karen Wilson Drive"), in which case
    // split() returns a single part and no replacement is needed.
    const parts = sanitized.split(match.originalText);
    if (parts.length > 1) {
      const counter = (categoryCounters.get(match.category) ?? 0) + 1;
      categoryCounters.set(match.category, counter);
      const placeholder = `[${match.category}_${counter}]`;
      sanitized = parts.join(placeholder);
      mappingTable.set(placeholder, match.originalText);
    }
  }

  return sanitized;
}

// =============================================================================
// Recursive Sanitization
// =============================================================================

/**
 * Structural keys whose values should NEVER be sanitized.
 * These are protocol-level identifiers (tool_call_id, role, model, etc.)
 * that can look like high-entropy secrets but are required to remain intact
 * for the LLM API contract to work.
 */
const STRUCTURAL_KEYS = new Set([
  // OpenAI protocol — identifiers and enum-valued fields
  "tool_call_id", "id", "model", "role", "type", "finish_reason",
  "name", "object", "created", "index", "logprobs",
  "system_fingerprint", "refusal",
  // Anthropic protocol — identifiers and enum-valued fields
  "tool_use_id", "stop_reason", "stop_sequence",
  "media_type", "source_type",
  // Gemini protocol — identifiers and enum-valued fields
  "finishReason", "safetyCategory", "harmCategory", "harmProbability",
  // Common request parameters (numeric/boolean but protect anyway)
  "stream", "max_tokens", "temperature", "top_p",
  "top_k", "frequency_penalty", "presence_penalty", "seed", "n",
  // Token usage fields (numeric, but key names should not be sanitized)
  "prompt_tokens", "completion_tokens", "total_tokens",
  "input_tokens", "output_tokens",
]);

/**
 * Recursively sanitize any value (string, object, array)
 */
function sanitizeValue(
  value: any,
  mappingTable: MappingTable,
  categoryCounters: Map<string, number>,
): any {
  // String: sanitize directly
  if (typeof value === "string") {
    return sanitizeText(value, mappingTable, categoryCounters);
  }

  // Array: sanitize each element
  if (Array.isArray(value)) {
    return value.map((item) =>
      sanitizeValue(item, mappingTable, categoryCounters),
    );
  }

  // Object: sanitize each property, skipping structural keys
  if (value !== null && typeof value === "object") {
    const sanitized: any = {};
    for (const [key, val] of Object.entries(value)) {
      if (STRUCTURAL_KEYS.has(key)) {
        sanitized[key] = val; // Pass through unchanged
      } else {
        sanitized[key] = sanitizeValue(val, mappingTable, categoryCounters);
      }
    }
    return sanitized;
  }

  // Primitives: return as-is
  return value;
}

// =============================================================================
// Public API
// =============================================================================

/**
 * Shared sanitization state for cross-call consistency.
 * When passed, the same PII value always gets the same placeholder
 * number across multiple sanitize() calls within a session.
 */
export type SanitizationState = {
  mappingTable: MappingTable;
  categoryCounters: Map<string, number>;
};

/**
 * Sanitize any content (messages array, object, string)
 * Returns sanitized content and mapping table for restoration.
 *
 * Optionally accepts shared state so that multiple calls (e.g., across
 * tool invocations) produce consistent placeholder numbering and a
 * single accumulated mapping table.
 */
export function sanitize(content: any, sharedState?: SanitizationState): SanitizeResult {
  const mappingTable: MappingTable = sharedState?.mappingTable ?? new Map();
  const categoryCounters = sharedState?.categoryCounters ?? new Map<string, number>();

  const sanitized = sanitizeValue(content, mappingTable, categoryCounters);

  // Build per-category redaction counts from the counters
  const redactionsByCategory: Record<string, number> = {};
  for (const [category, count] of categoryCounters) {
    redactionsByCategory[category] = count;
  }

  return {
    sanitized,
    mappingTable,
    redactionCount: mappingTable.size,
    redactionsByCategory,
  };
}

/**
 * Sanitize messages array (common case for LLM APIs)
 */
export function sanitizeMessages(messages: any[]): SanitizeResult {
  return sanitize(messages);
}

// =============================================================================
// Post-Sanitization Canary Check (defense-in-depth)
// =============================================================================

const LEAKED_SSN_PATTERN = /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/;
const LEAKED_EIN_PATTERN = /\b\d{2}-\d{7}\b/;

/**
 * Scan a serialized payload for residual PII patterns that should have been
 * removed by sanitize(). Throws if any SSN-like or EIN-like patterns remain.
 * Call this AFTER sanitize() but BEFORE forwarding to the LLM API.
 */
export function assertNoLeakedPii(payload: string): void {
  if (LEAKED_SSN_PATTERN.test(payload) || LEAKED_EIN_PATTERN.test(payload)) {
    console.error("[moltguard-gateway] Sanitization integrity check failed — leaked PII pattern detected in outbound payload");
    throw new Error("Sanitization integrity check failed");
  }
}
