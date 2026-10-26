// Reads a business website's HTML and pulls out the things that separate real
// businesses from fake ones: contact details, policies, how they take payment,
// pressure tactics, leftover template text, and claims about how old they are.
// Pure functions — no network access — so they are easy to test.

export interface PageSignals {
  siteName?: string;
  text: string;
  links: { href: string; text: string }[];
  phones: string[];
  emails: string[];
  addressSample?: string;
  policies: { privacy: boolean; terms: boolean; refund: boolean; shipping: boolean; about: boolean; contactPage: boolean };
  cardPayments: string[];
  riskyPayments: string[];
  pressurePhrases: string[];
  bigDiscounts: number[];
  templateText: string[];
  claimedSinceYear?: number;
  social: string[];
  platform?: string;
}

export const FREE_EMAIL_DOMAINS = [
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com", "live.com", "msn.com",
  "aol.com", "icloud.com", "me.com", "protonmail.com", "proton.me", "gmx.com", "gmx.net", "mail.com", "yandex.com",
  "zoho.com", "qq.com", "163.com",
];

const decodeEntities = (s: string) =>
  s.replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));

export function htmlToText(html: string): string {
  return decodeEntities(
    html
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(br|p|div|li|h[1-6]|tr|section|footer|header)\b[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " ")
  ).replace(/[ \t]+/g, " ").replace(/\n\s*/g, "\n").trim();
}

export function extractLinks(html: string): { href: string; text: string }[] {
  const out: { href: string; text: string }[] = [];
  for (const m of html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"'#][^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    out.push({ href: decodeEntities(m[1].trim()), text: htmlToText(m[2]).slice(0, 80) });
    if (out.length >= 600) break;
  }
  return out;
}

const uniq = <T,>(xs: T[]) => [...new Set(xs)];

export function analyzePage(html: string): PageSignals {
  const text = htmlToText(html);
  const lower = text.toLowerCase();
  const rawLower = html.toLowerCase();
  const links = extractLinks(html);

  const siteName =
    html.match(/<meta[^>]+property\s*=\s*["']og:site_name["'][^>]*content\s*=\s*["']([^"']+)["']/i)?.[1] ||
    html.match(/<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*property\s*=\s*["']og:site_name["']/i)?.[1] ||
    html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.split(/[|\-–—]/)[0];

  // Phone numbers (North American format + tel: links)
  const phones = uniq([
    ...links.filter((l) => /^tel:/i.test(l.href)).map((l) => l.href.replace(/^tel:/i, "").trim()),
    ...(text.match(/(?:\+?1[\s.-]?)?\(?\b[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g) || []),
  ].map((p) => p.replace(/\s+/g, " ").trim())).slice(0, 10);

  // Email addresses (text + mailto: links), ignoring image file names like logo@2x.png
  const emails = uniq([
    ...links.filter((l) => /^mailto:/i.test(l.href)).map((l) => l.href.replace(/^mailto:/i, "").split("?")[0]),
    ...(text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || []),
  ].map((e) => e.toLowerCase().trim()).filter((e) => !/\.(png|jpe?g|gif|webp|svg)$/.test(e))).slice(0, 10);

  // Street address (US/Canada style), e.g. "1200 Main Street, Suite 4" or "... PA 18966"
  const addressSample =
    text.match(/\b\d{1,6}\s+(?:[A-Za-z0-9.'-]+\s){1,5}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl|Parkway|Pkwy|Highway|Hwy|Circle|Cir|Square|Sq|Terrace|Pike|Route|Rte)\b\.?(?:[^\n]{0,60})?/i)?.[0]?.trim() ||
    text.match(/\b[A-Z][a-zA-Z .'-]{2,30},\s?(?:A[LKZR]|C[AOT]|D[EC]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY])\s\d{5}(?:-\d{4})?\b/)?.[0]?.trim();

  const linkText = links.map((l) => `${l.text} ${l.href}`.toLowerCase()).join("\n");
  const policies = {
    privacy: /privacy/.test(linkText),
    terms: /terms|conditions|tos\b/.test(linkText),
    refund: /refund|return|money.?back|exchange/.test(linkText),
    shipping: /shipping|delivery/.test(linkText),
    about: /about|our.?story|who.?we.?are/.test(linkText),
    contactPage: /contact/.test(linkText),
  };

  const cardPayments = uniq(
    ([
      ["Visa", /\bvisa\b/], ["Mastercard", /mastercard/], ["American Express", /american express|\bamex\b/],
      ["Discover", /\bdiscover card\b|discover\s*(?:network|logo)/], ["PayPal", /paypal/], ["Stripe", /stripe/],
      ["Shop Pay", /shop ?pay/], ["Apple Pay", /apple ?pay/], ["Google Pay", /google ?pay/],
    ] as [string, RegExp][]).filter(([, re]) => re.test(rawLower)).map(([n]) => n)
  );

  // Payment methods that are hard or impossible to get back — scammers' favourites.
  const riskyPayments = uniq(
    ([
      ["Zelle", /\bzelle\b/], ["Cash App", /cash ?app\b/], ["Western Union", /western union/], ["MoneyGram", /moneygram/],
      ["wire transfer", /wire transfer|bank wire/], ["gift cards", /pay(?:ment)?s? (?:with|by|via|using) (?:a )?gift ?cards?|gift cards? (?:as|for) payment/],
      ["cryptocurrency", /(?:pay|payment|accept)\w* (?:with |by |via |in )?(?:bitcoin|btc|crypto|usdt|tether|ethereum)|bitcoin only|crypto only/],
      ["Venmo / PayPal Friends & Family", /friends (?:and|&) family|venmo/],
    ] as [string, RegExp][]).filter(([, re]) => re.test(lower)).map(([n]) => n)
  );

  const pressurePhrases = uniq(
    ([
      "limited time", "act now", "today only", "hurry", "last chance", "going out of business", "everything must go",
      "closing down sale", "while supplies last", "don't miss out", "only a few left", "selling fast",
    ].filter((p) => lower.includes(p)).concat((lower.match(/only \d+ (?:left|remaining) in stock/g) || []).slice(0, 1)))
  );

  const bigDiscounts = uniq(
    [...lower.matchAll(/(\d{2})\s?%\s?off/g)].map((m) => Number(m[1])).filter((n) => n >= 70 && n < 100)
  ).sort((a, b) => b - a);

  const templateText = ([
    ["lorem ipsum", /lorem ipsum/], ["\"Your Company Name\"", /your company name|company name here|your business name/],
    ["placeholder address \"123 Main Street\"", /123 main st(?:reet)?\b/], ["placeholder phone number", /\(?123\)?[\s.-]456[\s.-]7890|555[\s.-]555[\s.-]5555/],
    ["placeholder email", /\b(?:example|youremail|your-email|email)@(?:example|domain|yourdomain|email)\.com\b/],
  ] as [string, RegExp][]).filter(([, re]) => re.test(lower)).map(([n]) => n);

  // "Since 1998", "Established in 2005", "Est. 1987", "Founded in 2001"
  let claimedSinceYear: number | undefined;
  const yearMatch = lower.match(/\b(?:since|established(?: in)?|est\.?|founded(?: in)?|serving (?:customers|you) since)\s+((?:18|19|20)\d{2})\b/);
  if (yearMatch) claimedSinceYear = Number(yearMatch[1]);

  const social = uniq(
    links.map((l) => l.href.toLowerCase()).map((h) =>
      /facebook\.com\/(?!sharer|share|dialog|plugins)/.test(h) ? "Facebook" :
      /instagram\.com\//.test(h) ? "Instagram" :
      /linkedin\.com\/(company|in)\//.test(h) ? "LinkedIn" :
      /(?:twitter|x)\.com\/(?!intent|share)/.test(h) ? "X (Twitter)" :
      /youtube\.com\/(?:@|c\/|channel\/|user\/)/.test(h) ? "YouTube" :
      /tiktok\.com\/@/.test(h) ? "TikTok" : ""
    ).filter(Boolean)
  );

  const platform =
    /cdn\.shopify\.com|shopify\.theme|myshopify\.com/.test(rawLower) ? "Shopify" :
    /static\.wixstatic\.com|wix\.com/.test(rawLower) ? "Wix" :
    /squarespace\.com|static1\.squarespace/.test(rawLower) ? "Squarespace" :
    /wp-content\/|wordpress/.test(rawLower) ? "WordPress" :
    /woocommerce/.test(rawLower) ? "WooCommerce" : undefined;

  return {
    siteName: siteName ? decodeEntities(siteName).trim().slice(0, 80) : undefined,
    text, links, phones, emails, addressSample: addressSample?.slice(0, 120), policies,
    cardPayments, riskyPayments, pressurePhrases, bigDiscounts, templateText, claimedSinceYear, social, platform,
  };
}

/** Merge signals from several pages of the same site (homepage + contact + about…). */
export function mergeSignals(pages: PageSignals[]): PageSignals {
  const [first, ...rest] = pages;
  if (!first) return analyzePage("");
  const all = [first, ...rest];
  const or = (k: keyof PageSignals["policies"]) => all.some((p) => p.policies[k]);
  return {
    siteName: first.siteName,
    text: all.map((p) => p.text).join("\n"),
    links: all.flatMap((p) => p.links),
    phones: uniq(all.flatMap((p) => p.phones)).slice(0, 10),
    emails: uniq(all.flatMap((p) => p.emails)).slice(0, 10),
    addressSample: all.find((p) => p.addressSample)?.addressSample,
    policies: { privacy: or("privacy"), terms: or("terms"), refund: or("refund"), shipping: or("shipping"), about: or("about"), contactPage: or("contactPage") },
    cardPayments: uniq(all.flatMap((p) => p.cardPayments)),
    riskyPayments: uniq(all.flatMap((p) => p.riskyPayments)),
    pressurePhrases: uniq(all.flatMap((p) => p.pressurePhrases)),
    bigDiscounts: uniq(all.flatMap((p) => p.bigDiscounts)).sort((a, b) => b - a),
    templateText: uniq(all.flatMap((p) => p.templateText)),
    claimedSinceYear: all.find((p) => p.claimedSinceYear)?.claimedSinceYear,
    social: uniq(all.flatMap((p) => p.social)),
    platform: first.platform || rest.find((p) => p.platform)?.platform,
  };
}

// Big brands scammers love to copy. If a site's domain contains one of these names
// but isn't one of that brand's real domains, it's very likely a look-alike.
export const BRANDS: Record<string, string[]> = {
  amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazonaws.com", "amazon.jobs"],
  paypal: ["paypal.com", "paypal.me"],
  apple: ["apple.com", "icloud.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
  walmart: ["walmart.com", "walmart.ca"],
  costco: ["costco.com", "costco.ca"],
  target: ["target.com"],
  bestbuy: ["bestbuy.com", "bestbuy.ca"],
  ebay: ["ebay.com", "ebay.co.uk"],
  netflix: ["netflix.com"],
  usps: ["usps.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  dhl: ["dhl.com"],
  irs: ["irs.gov"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  citibank: ["citi.com", "citibank.com"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com", "binance.us"],
  facebook: ["facebook.com", "fb.com", "meta.com"],
  instagram: ["instagram.com"],
  google: ["google.com", "youtube.com"],
  geeksquad: ["geeksquad.com", "bestbuy.com"],
  norton: ["norton.com", "nortonlifelock.com"],
  mcafee: ["mcafee.com"],
  zelle: ["zellepay.com"],
  venmo: ["venmo.com"],
  cashapp: ["cash.app", "squareup.com"],
  ticketmaster: ["ticketmaster.com"],
  homedepot: ["homedepot.com"],
  lowes: ["lowes.com"],
  nike: ["nike.com"],
};

/** Returns the brand a domain appears to imitate, or undefined. */
export function lookalikeBrand(registrableDomain: string): string | undefined {
  const d = registrableDomain.toLowerCase();
  const label = d.replace(/\.[a-z.]+$/, "").replace(/[^a-z0-9]/g, "");
  for (const [brand, real] of Object.entries(BRANDS)) {
    if (real.includes(d)) return undefined;
    // Short names (ups, dhl, irs) must stand alone as a word to avoid false hits like "groups".
    const hit = brand.length <= 4
      ? new RegExp(`(^|[^a-z])${brand}([^a-z]|$)`).test(d.replace(/\.[a-z.]+$/, ""))
      : label.includes(brand);
    if (hit) return brand;
  }
  return undefined;
}
