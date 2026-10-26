// Run with:  npx tsx --test packages/business-check/test/*.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkBusiness, analyzePage, lookalikeBrand, registrableDomain } from "../src/index.js";
import { resetRdapCache } from "../src/net.js";
import { beforeEach } from "node:test";
beforeEach(() => resetRdapCache());

const NOW = new Date("2026-10-25T12:00:00Z");
const daysAgo = (d: number) => new Date(NOW.getTime() - d * 86_400_000).toISOString();

// ---------- two fake websites ----------

const SCAM_HOME = `<html><head><title>Luxe Outlet | Official Store</title></head><body>
<h1>CLOSING DOWN SALE — EVERYTHING MUST GO! Up to 90% OFF</h1>
<p>Serving customers since 1998. Limited time only, hurry, only 3 left in stock!</p>
<p>Lorem ipsum dolor sit amet. Contact: luxeoutlet.help@gmail.com</p>
<p>We accept payment via Zelle and Cash App for faster shipping.</p>
<a href="/contact">Contact</a></body></html>`;
const SCAM_CONTACT = `<html><body><p>Email us at luxeoutlet.help@gmail.com. Your Company Name</p></body></html>`;

const REAL_HOME = `<html><head><meta property="og:site_name" content="Knoxville Hardware Co"><title>Knoxville Hardware</title></head><body>
<p>Family owned since 1987. Visit us at 214 Main Street, Knoxville, PA 16928. Call (570) 555-0142.</p>
<p>We accept Visa, Mastercard and PayPal.</p>
<a href="/about-us">About us</a> <a href="/contact">Contact</a> <a href="/returns">Returns &amp; Refunds</a>
<a href="/privacy-policy">Privacy Policy</a> <a href="/terms">Terms of Service</a>
<a href="mailto:info@knoxvillehardware.com">info@knoxvillehardware.com</a>
<a href="https://www.facebook.com/knoxvillehardware">Facebook</a></body></html>`;

type Site = { pages: Record<string, string>; registered: string; expires: string; firstSeen?: string; mx: boolean; spf: boolean; dmarc: boolean; certValid: boolean };
const SITES: Record<string, Site> = {
  "luxe-outlet-sale.shop": { pages: { "/": SCAM_HOME, "/contact": SCAM_CONTACT }, registered: daysAgo(12), expires: daysAgo(12 - 365), mx: false, spf: false, dmarc: false, certValid: true },
  "knoxvillehardware.com": { pages: { "/": REAL_HOME, "/about-us": "<p>About</p>", "/contact": "<p>Contact</p>", "/returns": "<p>30 day returns</p>" }, registered: daysAgo(365 * 12), expires: daysAgo(-365), firstSeen: "20140302000000", mx: true, spf: true, dmarc: true, certValid: true },
};

function fakeDeps() {
  const fetchCalls: string[] = [];
  const fakeFetch = (async (input: any) => {
    const url = new URL(String(input));
    fetchCalls.push(url.toString());
    const json = (o: unknown) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
    if (url.hostname === "data.iana.org") return json({ services: [[["com", "net"], ["https://rdap.registry-one.test/v1/"]], [["shop"], ["https://rdap.registry-two.test/"]]] });
    if (url.hostname.startsWith("rdap.registry-") && url.pathname.includes("/domain/")) {
      const s = SITES[decodeURIComponent(url.pathname.split("/").pop()!)];
      if (!s) return new Response("", { status: 404 });
      return json({ events: [{ eventAction: "registration", eventDate: s.registered }, { eventAction: "expiration", eventDate: s.expires }],
        entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]] }, { roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]] }] });
    }
    if (url.hostname === "rdap.arin.net") return json({ name: "EXAMPLE-NET", country: "US", entities: [] });
    if (url.hostname === "web.archive.org") {
      const d = url.searchParams.get("url")!;
      const s = SITES[d];
      return json(s?.firstSeen ? [["timestamp"], [s.firstSeen]] : []);
    }
    const s = SITES[url.hostname.replace(/^www\./, "")];
    const html = s?.pages[url.pathname];
    if (html === undefined) return new Response("not found", { status: 404, headers: { "content-type": "text/html" } });
    return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
  }) as typeof fetch;
  return {
    fetchCalls,
    options: {
      fetch: fakeFetch,
      now: NOW,
      resolveHost: async (h: string) => { if (h === "internal.test") throw new Error("That address points to a private network and can't be checked."); return ["93.184.216.34"]; },
      resolveMx: async (d: string) => (SITES[d]?.mx ? [{ exchange: "mx.example.net", priority: 10 }] : []),
      resolveTxt: async (d: string) => {
        const dmarc = d.startsWith("_dmarc.");
        const s = SITES[d.replace(/^_dmarc\./, "")];
        if (!s) return [];
        return dmarc ? (s.dmarc ? [["v=DMARC1; p=reject"]] : []) : (s.spf ? [["v=spf1 include:_spf.example.net ~all"]] : []);
      },
      getCertificate: async (h: string) => ({ valid: SITES[h.replace(/^www\./, "")]?.certValid ?? false, issuer: "Let's Encrypt", expiresOn: "2027-01-01" }),
    },
  };
}

// ---------- tests ----------

test("flags an obvious scam store as high risk with clear reasons", async () => {
  const { options } = fakeDeps();
  const r = await checkBusiness("luxe-outlet-sale.shop", options);
  const ids = r.redFlags.map((f) => f.id);
  assert.equal(r.verdict, "high_risk");
  for (const id of ["domain_very_new", "history_mismatch", "risky_payments", "template_text", "huge_discounts", "free_email", "missing_policies"]) {
    assert.ok(ids.includes(id), `expected red flag ${id}, got ${ids.join(", ")}`);
  }
  assert.ok(r.score >= 80, `score ${r.score}`);
  assert.equal(r.redFlags[0].severity, "high", "most serious flags come first");
  assert.ok(r.facts.pagesScanned.some((p) => p.endsWith("/contact")), "reads the contact page too");
});

test("treats an established local business as looking OK", async () => {
  const { options } = fakeDeps();
  const r = await checkBusiness("https://knoxvillehardware.com", options);
  assert.equal(r.verdict, "looks_ok", JSON.stringify(r.redFlags, null, 1));
  const good = r.goodSigns.map((g) => g.id);
  for (const id of ["domain_established", "archived_history", "has_address", "has_phone", "card_payments", "has_policies", "email_setup", "social_links"]) {
    assert.ok(good.includes(id), `expected good sign ${id}, got ${good.join(", ")}`);
  }
  assert.equal(r.facts.siteName, "Knoxville Hardware Co");
  assert.equal(r.facts.registration?.registrar, "Example Registrar, Inc.");
  assert.equal(r.facts.firstSeenOnline, "2014-03-02");
});

test("refuses to scan private network addresses", async () => {
  const { options } = fakeDeps();
  await assert.rejects(() => checkBusiness("http://internal.test/admin", options), /private network/);
});

test("still reports public records when the website is down", async () => {
  const { options } = fakeDeps();
  const r = await checkBusiness("knoxvillehardware.com", { ...options, fetch: (async (u: any) => {
    const url = new URL(String(u));
    if (url.hostname === "knoxvillehardware.com") throw new Error("connection refused");
    return options.fetch(u);
  }) as typeof fetch });
  assert.equal(r.facts.reachable, false);
  assert.ok(r.facts.registration?.ageDays && r.facts.registration.ageDays > 4000);
  assert.notEqual(r.verdict, "high_risk");
});

test("spots look-alike brand domains without false alarms", () => {
  assert.equal(lookalikeBrand("paypal-secure-login.com"), "paypal");
  assert.equal(lookalikeBrand("amazon-refunds.net"), "amazon");
  assert.equal(lookalikeBrand("ups-redelivery.info"), "ups");
  assert.equal(lookalikeBrand("paypal.com"), undefined);
  assert.equal(lookalikeBrand("startups.com"), undefined, "\"ups\" inside a word is not a hit");
  assert.equal(lookalikeBrand("knoxvillehardware.com"), undefined);
});

test("reads contact details and payments from a page", () => {
  const s = analyzePage(REAL_HOME);
  assert.deepEqual(s.phones, ["(570) 555-0142"]);
  assert.ok(s.emails.includes("info@knoxvillehardware.com"));
  assert.match(s.addressSample || "", /214 Main Street/);
  assert.deepEqual(s.cardPayments.sort(), ["Mastercard", "PayPal", "Visa"]);
  assert.equal(s.claimedSinceYear, 1987);
  assert.deepEqual(s.social, ["Facebook"]);
});

test("flags a look-alike address even when the site is offline", async () => {
  const { options } = fakeDeps();
  const r = await checkBusiness("paypal-account-verify-help.com", { ...options, resolveHost: async () => { throw new Error("That website doesn't exist or isn't online right now."); } });
  assert.equal(r.facts.reachable, false);
  assert.equal(r.redFlags[0].id, "brand_lookalike");
  assert.notEqual(r.verdict, "unknown");
  assert.match(r.headline, /isn't loading right now/);
});

test("handles odd input", () => {
  assert.equal(registrableDomain("shop.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("www.Example.com"), "example.com");
});
