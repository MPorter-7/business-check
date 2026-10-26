#!/usr/bin/env node
// Command line:  npx business-check example-shop.com [--json]

import { checkBusiness } from "./index.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
const target = args.find((a) => !a.startsWith("--"));

if (!target) {
  console.log("Usage: business-check <website> [--json]\n\nExample: business-check example-shop.com");
  process.exit(1);
}

const color = (code: number) => (s: string) => (process.stdout.isTTY && !json ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = color(31), yellow = color(33), green = color(32), bold = color(1), dim = color(2);

checkBusiness(target, { safeBrowsingKey: process.env.SAFE_BROWSING_API_KEY })
  .then((r) => {
    if (json) { console.log(JSON.stringify(r, null, 2)); return; }
    const label = { high_risk: red("HIGH RISK"), caution: yellow("BE CAREFUL"), looks_ok: green("NO MAJOR RED FLAGS"), unknown: dim("COULDN'T CHECK") }[r.verdict];
    console.log(`\n${bold(r.facts.domain)}  →  ${label}  ${dim(`(risk ${r.score}/100)`)}`);
    console.log(r.headline + "\n");
    if (r.redFlags.length) {
      console.log(bold("Red flags"));
      for (const f of r.redFlags) {
        const tag = f.severity === "high" ? red("●") : f.severity === "medium" ? yellow("●") : dim("●");
        console.log(`  ${tag} ${bold(f.title)}\n    ${f.detail}`);
      }
      console.log();
    }
    if (r.goodSigns.length) {
      console.log(bold("Good signs"));
      for (const g of r.goodSigns) console.log(`  ${green("✓")} ${g.title}`);
      console.log();
    }
    console.log(bold("Double-check it yourself"));
    for (const l of r.lookups) console.log(`  ${l.name}: ${dim(l.url)}`);
    console.log();
  })
  .catch((e) => { console.error(red(`Error: ${e?.message || e}`)); process.exit(1); });
