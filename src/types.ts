// Public types for business-check.

export type Severity = "high" | "medium" | "low";
export type Verdict = "high_risk" | "caution" | "looks_ok" | "unknown";

export type FlagCategory =
  | "identity"   // who is behind the site, how old it is
  | "contact"    // phone, email, address
  | "payments"   // how they want to be paid
  | "content"    // what the site says and how it says it
  | "technical"  // email setup, security certificate, blocklists
  | "policies";  // privacy, refund, shipping, terms

export interface Flag {
  /** Stable machine-readable id, e.g. "domain_very_new". */
  id: string;
  category: FlagCategory;
  severity: Severity;
  /** Short plain-English title, e.g. "Website is brand new". */
  title: string;
  /** One or two plain-English sentences explaining what was found and why it matters. */
  detail: string;
  /** Risk points this flag adds (0 for good signs). */
  points: number;
}

export interface Lookup {
  name: string;
  url: string;
  why: string;
}

export interface BusinessFacts {
  domain: string;
  siteName?: string;
  reachable: boolean;
  finalUrl?: string;
  fetchError?: string;
  pagesScanned: string[];
  registration?: {
    registeredOn?: string;
    expiresOn?: string;
    ageDays?: number;
    registrar?: string;
    ownerHidden?: boolean;
  };
  firstSeenOnline?: string;      // earliest Wayback Machine snapshot (YYYY-MM-DD)
  hosting?: { ips: string[]; network?: string; country?: string };
  email?: { canReceiveEmail: boolean; spf: boolean; dmarc: boolean };
  ssl?: { valid: boolean; issuer?: string; expiresOn?: string; error?: string };
  contact?: { phones: string[]; emails: string[]; freeEmails: string[]; hasAddress: boolean; addressSample?: string };
  policies?: { privacy: boolean; terms: boolean; refund: boolean; shipping: boolean; about: boolean; contactPage: boolean };
  payments?: { cards: string[]; risky: string[] };
  social?: string[];
  claimedSinceYear?: number;
  platform?: string;
  blocklist?: { checked: boolean; matches: string[] };
}

export interface BusinessCheckResult {
  input: string;
  checkedAt: string;
  verdict: Verdict;
  /** 0 (no risk found) to 100 (very risky). */
  score: number;
  headline: string;
  redFlags: Flag[];
  goodSigns: Flag[];
  facts: BusinessFacts;
  /** Free places a person can double-check this business themselves. */
  lookups: Lookup[];
}

/** Everything that touches the network can be swapped out (for tests, or to run in other environments). */
export interface CheckOptions {
  fetch?: typeof fetch;
  /** Resolve a hostname to IP addresses. Must reject private/internal addresses. */
  resolveHost?: (hostname: string) => Promise<string[]>;
  resolveMx?: (domain: string) => Promise<{ exchange: string; priority: number }[]>;
  resolveTxt?: (domain: string) => Promise<string[][]>;
  getCertificate?: (hostname: string) => Promise<BusinessFacts["ssl"]>;
  /** Optional Google Safe Browsing API key. */
  safeBrowsingKey?: string;
  /** Per-request timeout in ms (default 8000). */
  timeoutMs?: number;
  /** Max extra pages (contact/about/refund) to read besides the homepage (default 3). */
  maxExtraPages?: number;
  /** Override "now" (for tests). */
  now?: Date;
  userAgent?: string;
}
