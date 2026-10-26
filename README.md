# business-check

**Is this business real?** Give it a business's website and it tells you, in plain English, what looks suspicious and what looks trustworthy, using only free public information.

Built by [ThreatShield Alpha](https://threatshieldalpha.net) to help regular people avoid fake online stores, fake service companies and copycat websites. Try it online at **[threatshieldalpha.net/check/business](https://threatshieldalpha.net/check/business)**.

```
$ npx business-check luxe-outlet-sale.shop

luxe-outlet-sale.shop  →  HIGH RISK  (risk 100/100)
Luxe Outlet shows several serious warning signs.

Red flags
  ● Website is brand new
    This web address was registered only 12 days ago. Most scam shops are less than a few months old…
  ● Claims to be in business since 1998
    The site says it has been around since 1998, but its web address is only 12 days old…
  ● Asks for payment by Zelle or Cash App
    These payment methods are almost impossible to reverse if something goes wrong…
  ● Contains unfinished template text
  ● Uses a free personal email address
  ● Huge discounts (up to 90% off)
  …
```

## What it checks

| Area | What it looks at | Source (all free) |
|---|---|---|
| **Age & identity** | When the web address was registered, by which registrar, and whether the owner is hidden. Whether the site claims a long history ("since 1998") it can't have. Look-alike addresses copying big brands (PayPal, Amazon, USPS…). | [RDAP](https://about.rdap.org/) (the modern, official WHOIS) |
| **Track record** | When the site first appeared online. | [Internet Archive](https://web.archive.org/) |
| **Contact details** | Phone number, street address, and whether the email is a free Gmail/Yahoo address instead of the business's own. | The website itself |
| **Payments** | Requests for Zelle, Cash App, wire transfers, gift cards or crypto (money you can't get back) vs. cards and PayPal (buyer protection). | The website itself |
| **What it says** | Leftover template text ("lorem ipsum", "Your Company Name"), 70–90% off "deals", pressure tactics ("hurry, only 3 left"). | The website itself |
| **Policies** | Privacy policy, refund/return policy, terms of service. | The website itself |
| **Technical** | Security certificate, whether the domain can receive email, anti-spoofing email records (SPF/DMARC). Optional Google Safe Browsing blocklist check. | DNS, TLS, [Safe Browsing](https://developers.google.com/safe-browsing) (needs your own free key) |

It reads the homepage plus up to three linked pages (contact, about, refund policy).

Every red flag comes from a simple, readable rule in [`src/scoring.ts`](src/scoring.ts), with no hidden AI scoring, so you can see exactly why something was flagged.

## Install & use

Requires Node.js 20 or newer. There are no runtime dependencies.

```bash
npx business-check example-shop.com          # readable report
npx business-check example-shop.com --json   # full result as JSON
```

In your own code:

```ts
import { checkBusiness } from "business-check";

const result = await checkBusiness("example-shop.com", {
  safeBrowsingKey: process.env.SAFE_BROWSING_API_KEY, // optional
});

result.verdict;     // "high_risk" | "caution" | "looks_ok" | "unknown"
result.score;       // 0 (nothing found) … 100 (very risky)
result.redFlags;    // [{ id, title, detail, severity, category, points }]
result.goodSigns;   // same shape, for things that look trustworthy
result.facts;       // everything that was found (registration, contact details, policies…)
result.lookups;     // links to Trustpilot, BBB, Reddit, ICANN… to double-check by hand
```

Every network call (fetch, DNS, certificate) can be replaced through the options. That's how the tests run offline, and it lets you add caching or run the checker on other platforms.

## Safety

- **No private network access.** Every address and redirect is checked, and anything pointing to a private or internal network is refused, so the tool can't be used to probe a server's own network.
- **Limits.** Pages are read with a size cap (900 KB) and a timeout (8 s by default).
- If you run it as a public web service, put your own rate limit in front of it.

## Honest limits

This tool spots **warning signs**, not proof. A brand-new site can be a real new business, and a careful scammer can avoid every red flag. Use it as a first check, then use the lookup links, search for reviews, and pay with a credit card or PayPal so you can dispute the charge if something goes wrong.

## Develop

```bash
npm install
npm test        # offline tests with fake websites
npm run build   # compiles to dist/
```

Ideas and pull requests are welcome, especially new red-flag rules backed by real scam examples.

## License

MIT © 2026 Matthew Porter ([ThreatShield Alpha](https://threatshieldalpha.net))
