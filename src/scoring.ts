// Turns the facts about a business website into plain-English red flags and good signs.
// Every rule is simple and explainable — no black box. Points add up to a 0–100 risk score.

import type { BusinessFacts, Flag, Verdict } from "./types.js";
import { FREE_EMAIL_DOMAINS, lookalikeBrand, type PageSignals } from "./content.js";

/** ["a","b","c"] -> "a, b or c" */
const orList = (xs: string[]) => xs.length <= 1 ? (xs[0] || "") : `${xs.slice(0, -1).join(", ")} or ${xs[xs.length - 1]}`;

const years = (days: number) => Math.floor(days / 365);
const monthsText = (days: number) => {
  if (days < 31) return `${days} day${days === 1 ? "" : "s"}`;
  const m = Math.round(days / 30.4);
  return `${m} month${m === 1 ? "" : "s"}`;
};

export function scoreBusiness(facts: BusinessFacts, signals: PageSignals | undefined, now: Date): { redFlags: Flag[]; goodSigns: Flag[]; score: number; verdict: Verdict; headline: string } {
  const red: Flag[] = [];
  const good: Flag[] = [];
  const flag = (f: Omit<Flag, "points"> & { points: number }) => red.push(f);
  const ok = (f: Omit<Flag, "points" | "severity">) => good.push({ ...f, severity: "low", points: 0 });

  // ---------------- Identity: how old is it, who is behind it
  const brand = lookalikeBrand(facts.domain);
  if (brand) {
    flag({ id: "brand_lookalike", category: "identity", severity: "high", points: 45,
      title: `Looks like a copy of ${brand.toUpperCase()}`,
      detail: `The web address contains "${brand}" but it is not one of ${brand.toUpperCase()}'s real websites. Scammers use look-alike addresses to seem official.` });
  }

  if (facts.blocklist?.matches.length) {
    flag({ id: "blocklisted", category: "technical", severity: "high", points: 80,
      title: "Listed as dangerous by Google",
      detail: `Google Safe Browsing has flagged this site (${facts.blocklist.matches.join(", ").toLowerCase().replace(/_/g, " ")}). Do not enter any information on it.` });
  }

  const age = facts.registration?.ageDays;
  if (typeof age === "number") {
    if (age < 30) flag({ id: "domain_very_new", category: "identity", severity: "high", points: 40,
      title: "Website is brand new",
      detail: `This web address was registered only ${monthsText(age)} ago. Most scam shops are less than a few months old, while real businesses usually have sites that are years old.` });
    else if (age < 180) flag({ id: "domain_new", category: "identity", severity: "medium", points: 22,
      title: "Website is very new",
      detail: `This web address was registered ${monthsText(age)} ago. New isn't automatically bad, but be extra careful with brand-new stores.` });
    else if (age < 365) flag({ id: "domain_young", category: "identity", severity: "low", points: 8,
      title: "Website is less than a year old",
      detail: `This web address was registered ${monthsText(age)} ago.` });
    else ok({ id: "domain_established", category: "identity",
      title: `Website has existed for ${years(age)} year${years(age) === 1 ? "" : "s"}`,
      detail: `The web address was registered in ${facts.registration?.registeredOn?.slice(0, 4)}. Scam sites rarely last this long.` });
  }

  // Claimed history vs. reality ("Since 1998" on a site made last month)
  if (signals?.claimedSinceYear && typeof age === "number") {
    const claimedYears = now.getUTCFullYear() - signals.claimedSinceYear;
    const firstSeenYear = facts.firstSeenOnline ? Number(facts.firstSeenOnline.slice(0, 4)) : undefined;
    const onlineYears = Math.max(age / 365, firstSeenYear ? now.getUTCFullYear() - firstSeenYear : 0);
    if (claimedYears >= 3 && onlineYears < 1) {
      flag({ id: "history_mismatch", category: "identity", severity: "high", points: 30,
        title: `Claims to be in business since ${signals.claimedSinceYear}`,
        detail: `The site says it has been around since ${signals.claimedSinceYear}, but its web address is only ${monthsText(age)} old${facts.firstSeenOnline ? ` and it first appeared online in ${facts.firstSeenOnline.slice(0, 7)}` : ""}. Fake stores often invent a long history.` });
    }
  }

  if (facts.firstSeenOnline) {
    const firstYear = Number(facts.firstSeenOnline.slice(0, 4));
    const yrs = now.getUTCFullYear() - firstYear;
    if (yrs >= 3) ok({ id: "archived_history", category: "identity",
      title: `Online since at least ${firstYear}`,
      detail: `The Internet Archive has copies of this site going back to ${facts.firstSeenOnline.slice(0, 7)}.` });
  }

  if (facts.registration?.ageDays !== undefined && facts.registration.ageDays < 365 && facts.registration.expiresOn && facts.registration.registeredOn) {
    const termDays = (Date.parse(facts.registration.expiresOn) - Date.parse(facts.registration.registeredOn)) / 86_400_000;
    if (termDays > 0 && termDays <= 400) flag({ id: "short_registration", category: "identity", severity: "low", points: 5,
      title: "Web address only paid for one year",
      detail: "New sites registered for just a single year are common among throwaway scam stores. On its own this means little." });
  }

  // ---------------- Contact details
  const contact = facts.contact;
  if (facts.reachable && contact) {
    const site = facts.domain.toLowerCase();
    if (!contact.phones.length && !contact.emails.length && !contact.hasAddress) {
      flag({ id: "no_contact", category: "contact", severity: "high", points: 25,
        title: "No way to contact them",
        detail: "We couldn't find a phone number, email address or street address. Real businesses make it easy to reach them." });
    } else {
      if (!contact.hasAddress) flag({ id: "no_address", category: "contact", severity: "low", points: 6,
        title: "No business address listed",
        detail: "We couldn't find a street address. Many scam stores hide where they are." });
      else ok({ id: "has_address", category: "contact", title: "Lists a business address", detail: contact.addressSample ? `Found: "${contact.addressSample}". You can look it up on a map to see if it's a real storefront or office.` : "A street address is listed on the site." });
      if (!contact.phones.length) flag({ id: "no_phone", category: "contact", severity: "low", points: 6,
        title: "No phone number listed", detail: "There's no phone number to call. Not always a problem, but real businesses usually have one." });
      else ok({ id: "has_phone", category: "contact", title: "Lists a phone number", detail: `Found: ${contact.phones.slice(0, 2).join(", ")}. Try calling it before you buy.` });
    }
    if (contact.freeEmails.length) {
      const onlyFree = contact.emails.every((e) => contact.freeEmails.includes(e));
      flag({ id: "free_email", category: "contact", severity: onlyFree ? "medium" : "low", points: onlyFree ? 15 : 5,
        title: "Uses a free personal email address",
        detail: `The contact email is ${contact.freeEmails[0]}. Established businesses normally use an email at their own web address (like @${site}).` });
    }
  }

  // ---------------- Payments
  if (facts.payments?.risky.length) {
    flag({ id: "risky_payments", category: "payments", severity: "high", points: 30,
      title: `Asks for payment by ${orList(facts.payments.risky)}`,
      detail: "These payment methods are almost impossible to reverse if something goes wrong. Legitimate stores let you pay by card or PayPal, which come with buyer protection." });
  }
  if (facts.payments?.cards.length) ok({ id: "card_payments", category: "payments",
    title: "Accepts protected payment methods",
    detail: `Mentions ${facts.payments.cards.slice(0, 4).join(", ")}. Paying by credit card or PayPal lets you dispute the charge if you're scammed.` });

  // ---------------- What the site says
  if (signals) {
    if (signals.templateText.length) flag({ id: "template_text", category: "content", severity: "high", points: 25,
      title: "Contains unfinished template text",
      detail: `We found ${signals.templateText.join(", ")}. Scam sites are often thrown together from templates and never finished.` });
    if (signals.bigDiscounts.length) flag({ id: "huge_discounts", category: "content", severity: "medium", points: 15,
      title: `Huge discounts (up to ${signals.bigDiscounts[0]}% off)`,
      detail: "Prices that seem too good to be true usually are. Fake stores lure people in with impossible deals." });
    if (signals.pressurePhrases.length >= 2) flag({ id: "pressure", category: "content", severity: "low", points: 8,
      title: "Uses pressure tactics",
      detail: `Phrases like "${signals.pressurePhrases.slice(0, 3).join('", "')}" are meant to rush you into buying before you think.` });
    if (signals.social.length) ok({ id: "social_links", category: "content",
      title: "Links to social media", detail: `Links to ${signals.social.join(", ")}. Check that those pages are active and have real followers and comments.` });
  }

  // ---------------- Policies
  const p = facts.policies;
  if (facts.reachable && p) {
    const missing = [!p.privacy && "a privacy policy", !p.refund && "a refund policy", !p.terms && "terms of service"].filter(Boolean) as string[];
    if (missing.length >= 2) flag({ id: "missing_policies", category: "policies", severity: "medium", points: 12,
      title: "Missing basic policies",
      detail: `We couldn't find ${orList(missing)}. Real stores are required to explain how they handle your data and returns.` });
    else if (missing.length === 0) ok({ id: "has_policies", category: "policies", title: "Has privacy, refund and terms pages", detail: "Read the refund policy before buying — scam sites sometimes hide impossible return rules there." });
  }

  // ---------------- Technical
  if (facts.ssl && facts.reachable) {
    if (!facts.ssl.valid) flag({ id: "bad_ssl", category: "technical", severity: "high", points: 30,
      title: "Security certificate problem",
      detail: `The site's security certificate isn't valid (${facts.ssl.error || "not trusted"}). Never enter card details on a site like this.` });
  }
  if (facts.email) {
    if (!facts.email.canReceiveEmail) flag({ id: "no_email_setup", category: "technical", severity: "low", points: 6,
      title: "Can't receive email at its own address",
      detail: `Nothing is set up to receive email at @${facts.domain}. Real businesses almost always use their own domain for email.` });
    else if (facts.email.spf && facts.email.dmarc) ok({ id: "email_setup", category: "technical",
      title: "Business email is properly set up", detail: "Its email has anti-spoofing protection (SPF and DMARC), which takes some effort — a mildly good sign." });
  }
  if (facts.registration?.ownerHidden === false) ok({ id: "owner_public", category: "identity",
    title: "Owner's name is public", detail: "The domain registration shows who owns it instead of hiding behind a privacy service." });

  // ---------------- Score + verdict
  const score = Math.min(100, red.reduce((s, f) => s + f.points, 0));
  const highs = red.filter((f) => f.severity === "high").length;
  let verdict: Verdict;
  if (!facts.reachable && typeof age !== "number" && highs === 0) verdict = "unknown";
  else if (score >= 50 || highs >= 2) verdict = "high_risk";
  else if (score >= 20 || highs === 1) verdict = "caution";
  else verdict = "looks_ok";

  const headline =
    verdict === "high_risk" ? `${facts.siteName || facts.domain} shows ${highs >= 2 ? "several serious warning signs" : "a serious warning sign"}.` :
    verdict === "caution" ? `${facts.siteName || facts.domain} has some warning signs. Double-check before you pay.` :
    verdict === "looks_ok" ? `We didn't find major red flags for ${facts.siteName || facts.domain}.` :
    `We couldn't reach ${facts.domain}, so we couldn't check it properly.`;
  const offlineNote = !facts.reachable && verdict !== "unknown" ? ` The website itself isn't loading right now, so this is based on its address and public records only.` : "";

  // Most serious first
  const order = { high: 0, medium: 1, low: 2 } as const;
  red.sort((a, b) => order[a.severity] - order[b.severity] || b.points - a.points);
  return { redFlags: red, goodSigns: good, score, verdict, headline: headline + offlineNote };
}

export function isFreeEmail(email: string): boolean {
  const d = email.split("@")[1]?.toLowerCase() || "";
  return FREE_EMAIL_DOMAINS.includes(d);
}
