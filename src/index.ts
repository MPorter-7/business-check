// business-check — is this business real?
// Paste a business's website and get plain-English red flags and good signs,
// using only free public information.
//
//   import { checkBusiness } from "business-check";
//   const result = await checkBusiness("example-shop.com");
//   console.log(result.verdict, result.redFlags.map(f => f.title));

import dns from "node:dns";
import type { BusinessCheckResult, BusinessFacts, CheckOptions, Lookup } from "./types.js";
import { analyzePage, mergeSignals, type PageSignals } from "./content.js";
import { scoreBusiness, isFreeEmail } from "./scoring.js";
import {
  DEFAULT_UA, normalizeInput, registrableDomain, resolvePublicHost, fetchPage, lookupRegistration,
  lookupFirstSeen, lookupHostingNetwork, lookupEmailSetup, getCertificate, checkSafeBrowsing,
} from "./net.js";

export * from "./types.js";
export { analyzePage, lookalikeBrand } from "./content.js";
export { scoreBusiness } from "./scoring.js";
export { registrableDomain, normalizeInput } from "./net.js";

const EXTRA_PAGE_PATTERNS: [string, RegExp][] = [
  ["contact", /contact/i],
  ["about", /about|our-story|who-we-are/i],
  ["refund", /refund|return|shipping|policy|policies|terms/i],
];

/** Pick the contact / about / refund pages from the homepage's own links. */
export function pickExtraPages(signals: PageSignals, homeUrl: URL, max: number): URL[] {
  const site = registrableDomain(homeUrl.hostname);
  const picked: URL[] = [];
  const seen = new Set<string>([homeUrl.toString().replace(/\/$/, "")]);
  for (const [, re] of EXTRA_PAGE_PATTERNS) {
    const link = signals.links.find((l) => {
      if (!re.test(l.href) && !re.test(l.text)) return false;
      try {
        const u = new URL(l.href, homeUrl);
        return (u.protocol === "https:" || u.protocol === "http:") && registrableDomain(u.hostname) === site && !seen.has(u.toString().replace(/\/$/, ""));
      } catch { return false; }
    });
    if (link) {
      const u = new URL(link.href, homeUrl);
      u.hash = "";
      seen.add(u.toString().replace(/\/$/, ""));
      picked.push(u);
    }
    if (picked.length >= max) break;
  }
  return picked;
}

export function lookupsFor(domain: string): Lookup[] {
  const q = encodeURIComponent(domain);
  return [
    { name: "Trustpilot reviews", url: `https://www.trustpilot.com/review/${domain}`, why: "See what real customers say." },
    { name: "Better Business Bureau", url: `https://www.bbb.org/search?find_text=${q}`, why: "Check complaints and whether it's a registered business." },
    { name: "Search Reddit", url: `https://www.reddit.com/search/?q=${q}`, why: "People often post about scam stores here." },
    { name: "Search Google for \"scam\"", url: `https://www.google.com/search?q=${encodeURIComponent(`"${domain}" scam OR reviews`)}`, why: "Look for warnings from other shoppers." },
    { name: "Internet Archive history", url: `https://web.archive.org/web/*/${domain}`, why: "See what the site looked like in the past." },
    { name: "Official domain records (ICANN)", url: `https://lookup.icann.org/en/lookup?name=${q}`, why: "Who registered the web address and when." },
  ];
}

export async function checkBusiness(input: string, options: CheckOptions = {}): Promise<BusinessCheckResult> {
  const f = options.fetch ?? fetch;
  const resolveHost = options.resolveHost ?? resolvePublicHost;
  const resolveMx = options.resolveMx ?? ((d: string) => dns.promises.resolveMx(d));
  const resolveTxt = options.resolveTxt ?? ((d: string) => dns.promises.resolveTxt(d));
  const certOf = options.getCertificate ?? getCertificate;
  const timeoutMs = options.timeoutMs ?? 8000;
  const now = options.now ?? new Date();
  const userAgent = options.userAgent ?? DEFAULT_UA;

  const url = normalizeInput(input);
  const domain = registrableDomain(url.hostname);
  const facts: BusinessFacts = { domain, reachable: false, pagesScanned: [] };

  // Public records (in parallel with loading the site)
  const recordsPromise = Promise.all([
    lookupRegistration(domain, f, timeoutMs, now),
    lookupFirstSeen(domain, f, timeoutMs),
    lookupEmailSetup(domain, resolveMx, resolveTxt, 5000),
    checkSafeBrowsing(url.toString(), options.safeBrowsingKey, f, timeoutMs),
  ]);

  let signals: PageSignals | undefined;
  try {
    const home = await fetchPage(url, { fetch: f, resolveHost, timeoutMs, userAgent });
    facts.reachable = home.status < 500;
    facts.finalUrl = home.finalUrl.toString();
    facts.pagesScanned.push(facts.finalUrl);
    facts.hosting = { ips: home.ips.slice(0, 4) };
    const homeSignals = analyzePage(home.html);
    const pages = [homeSignals];

    const extra = pickExtraPages(homeSignals, home.finalUrl, options.maxExtraPages ?? 3);
    const extraResults = await Promise.all(extra.map((u) =>
      fetchPage(u, { fetch: f, resolveHost, timeoutMs, userAgent }).then((r) => ({ u: r.finalUrl, html: r.html, ok: r.status < 400 })).catch(() => null)
    ));
    for (const r of extraResults) {
      if (r?.ok && r.html) { pages.push(analyzePage(r.html)); facts.pagesScanned.push(r.u.toString()); }
    }
    signals = mergeSignals(pages);

    const [hostInfo, ssl] = await Promise.all([
      home.ips[0] ? lookupHostingNetwork(home.ips[0], f, timeoutMs) : Promise.resolve({}),
      home.finalUrl.protocol === "https:" ? certOf(home.finalUrl.hostname) : Promise.resolve({ valid: false, error: "the site doesn't use a secure (https) connection" }),
    ]);
    facts.hosting = { ...facts.hosting, ...hostInfo };
    facts.ssl = ssl;
  } catch (e: any) {
    facts.fetchError = e?.message || String(e);
    if (/private network/i.test(facts.fetchError || "")) throw e;
  }

  const [registration, firstSeen, email, blocklist] = await recordsPromise;
  facts.registration = registration;
  facts.firstSeenOnline = firstSeen;
  facts.email = email;
  facts.blocklist = blocklist;

  if (signals) {
    facts.siteName = signals.siteName;
    facts.contact = {
      phones: signals.phones,
      emails: signals.emails,
      freeEmails: signals.emails.filter(isFreeEmail),
      hasAddress: !!signals.addressSample,
      addressSample: signals.addressSample,
    };
    facts.policies = signals.policies;
    facts.payments = { cards: signals.cardPayments, risky: signals.riskyPayments };
    facts.social = signals.social;
    facts.claimedSinceYear = signals.claimedSinceYear;
    facts.platform = signals.platform;
  }

  const scored = scoreBusiness(facts, signals, now);
  return {
    input,
    checkedAt: now.toISOString(),
    verdict: scored.verdict,
    score: scored.score,
    headline: scored.headline,
    redFlags: scored.redFlags,
    goodSigns: scored.goodSigns,
    facts,
    lookups: lookupsFor(domain),
  };
}
