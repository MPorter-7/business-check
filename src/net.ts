// Network lookups. All sources are free and need no API key:
//   - RDAP (rdap.org): who registered the domain, when, and with which registrar
//   - Internet Archive (web.archive.org): when the site first appeared online
//   - DNS: whether the domain can receive email and has anti-spoofing records
//   - TLS: the site's security certificate
// Google Safe Browsing is used only if you supply your own free API key.

import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import type { BusinessFacts } from "./types.js";

export const DEFAULT_UA = "Mozilla/5.0 (compatible; BusinessCheck/1.0; +https://github.com/MPorter-7)";

export function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, rej) => { t = setTimeout(() => rej(new Error(`${label} timed out`)), ms); });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith("::ffff:")) return isPrivateIp(v.slice(7));
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80");
}

/** Default host resolver: refuses private/internal addresses so the tool can't be used to probe a private network. */
export async function resolvePublicHost(hostname: string): Promise<string[]> {
  const host = hostname.replace(/^\[|\]$/g, "");
  let addrs: string[];
  try {
    addrs = net.isIP(host) ? [host] : (await dns.promises.lookup(host, { all: true })).map((a) => a.address);
  } catch (e: any) {
    if (/ENOTFOUND|ENODATA|EAI_NONAME/.test(String(e?.code || e?.message))) throw new Error("That website doesn't exist or isn't online right now.");
    throw e;
  }
  if (!addrs.length) throw new Error("That web address doesn't exist.");
  if (addrs.some(isPrivateIp)) throw new Error("That address points to a private network and can't be checked.");
  return addrs;
}

/** "shop.example.co.uk" -> "example.co.uk" (good enough for common TLDs). */
export function registrableDomain(hostname: string): string {
  const h = hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  if (net.isIP(h)) return h;
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join(".");
  return /^(co|com|org|net|gov|ac|edu|ltd|plc)\.[a-z]{2}$/.test(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

export function normalizeInput(raw: string): URL {
  let s = String(raw || "").trim();
  if (!s) throw new Error("Please enter a website address.");
  if (/^[^\s/]+@[^\s/]+\.[a-z]{2,}$/i.test(s)) s = s.split("@")[1]; // an email address → check its domain
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u: URL;
  try { u = new URL(s); } catch { throw new Error("That doesn't look like a website address."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only website addresses can be checked.");
  if (!u.hostname.includes(".")) throw new Error("That doesn't look like a website address.");
  return u;
}

const MAX_BODY = 900_000;
async function readLimited(res: Response): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    total += value.length;
  }
  try { await reader.cancel(); } catch { /* ignore */ }
  return new TextDecoder("utf-8").decode(Buffer.concat(chunks.map((c) => Buffer.from(c))));
}

/** Fetch a page safely: re-checks every redirect hop against private addresses, limits size and time. */
export async function fetchPage(
  url: URL,
  opts: { fetch: typeof fetch; resolveHost: (h: string) => Promise<string[]>; timeoutMs: number; userAgent: string },
): Promise<{ finalUrl: URL; status: number; html: string; ips: string[] }> {
  let current = url;
  let ips: string[] = [];
  for (let hop = 0; hop <= 5; hop++) {
    ips = await opts.resolveHost(current.hostname);
    const res = await withTimeout(
      opts.fetch(current, { redirect: "manual", headers: { "User-Agent": opts.userAgent, Accept: "text/html,*/*" } }),
      opts.timeoutMs, "Loading the website",
    );
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      try { await res.body?.cancel(); } catch { /* ignore */ }
      const next = new URL(loc, current);
      if (next.protocol !== "http:" && next.protocol !== "https:") break;
      current = next;
      continue;
    }
    const type = res.headers.get("content-type") || "";
    const html = /html|text\/plain/i.test(type) || !type ? await readLimited(res) : (await res.body?.cancel().catch(() => {}), "");
    return { finalUrl: current, status: res.status, html, ips };
  }
  throw new Error("The website redirected too many times.");
}

// IANA publishes which official registry answers RDAP for each ending (.com, .shop, .org…).
let rdapBootstrap: Promise<Record<string, string>> | undefined;
function rdapServers(f: typeof fetch, timeoutMs: number): Promise<Record<string, string>> {
  if (!rdapBootstrap) {
    rdapBootstrap = withTimeout(f("https://data.iana.org/rdap/dns.json"), timeoutMs, "Registry directory")
      .then((r) => (r.ok ? r.json() : { services: [] }))
      .then((d: any) => {
        const map: Record<string, string> = {};
        for (const [tlds, urls] of d.services || []) {
          const url = (urls as string[]).find((u) => u.startsWith("https://")) || (urls as string[])[0];
          for (const t of tlds as string[]) map[t.toLowerCase()] = url.endsWith("/") ? url : url + "/";
        }
        return map;
      })
      .catch(() => { rdapBootstrap = undefined; return {}; });
  }
  return rdapBootstrap;
}

/** For tests: forget the cached registry directory. */
export function resetRdapCache() { rdapBootstrap = undefined; }

export async function lookupRegistration(domain: string, f: typeof fetch, timeoutMs: number, now: Date): Promise<BusinessFacts["registration"] | undefined> {
  try {
    const tld = domain.split(".").pop() || "";
    const servers = await rdapServers(f, timeoutMs);
    const bases = [servers[tld], "https://rdap.org/"].filter(Boolean) as string[];
    let data: any;
    for (const base of bases) {
      try {
        const res = await withTimeout(f(`${base}domain/${encodeURIComponent(domain)}`, { headers: { Accept: "application/rdap+json, application/json" } }), timeoutMs, "Registration lookup");
        if (res.ok) { data = await res.json(); break; }
      } catch { /* try the next source */ }
    }
    if (!data) return undefined;
    const ev = (action: string) => (data.events || []).find((e: any) => e.eventAction === action)?.eventDate as string | undefined;
    const registeredOn = ev("registration");
    const expiresOn = ev("expiration");
    const entities: any[] = data.entities || [];
    const vcardName = (e: any) => (e?.vcardArray?.[1] || []).find((x: any) => x[0] === "fn")?.[3] as string | undefined;
    const registrar = vcardName(entities.find((e) => (e.roles || []).includes("registrar")));
    const registrant = entities.find((e) => (e.roles || []).includes("registrant"));
    const registrantName = vcardName(registrant) || "";
    const ownerHidden = !registrant || /redact|privacy|private|proxy|withheld|not disclosed|domains by proxy|whoisguard|contact privacy/i.test(registrantName) ||
      (registrant.remarks || []).some((r: any) => /redact/i.test(JSON.stringify(r)));
    return {
      registeredOn,
      expiresOn,
      ageDays: registeredOn ? Math.max(0, Math.floor((now.getTime() - Date.parse(registeredOn)) / 86_400_000)) : undefined,
      registrar,
      ownerHidden,
    };
  } catch {
    return undefined;
  }
}

/** Earliest Internet Archive snapshot, as YYYY-MM-DD. */
export async function lookupFirstSeen(domain: string, f: typeof fetch, timeoutMs: number): Promise<string | undefined> {
  try {
    const res = await withTimeout(f(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}&limit=1&output=json&fl=timestamp&filter=statuscode:200`), timeoutMs, "Archive lookup");
    if (!res.ok) return undefined;
    const rows: string[][] = await res.json();
    const ts = rows?.[1]?.[0];
    return ts && /^\d{8}/.test(ts) ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}` : undefined;
  } catch {
    return undefined;
  }
}

export async function lookupHostingNetwork(ip: string, f: typeof fetch, timeoutMs: number): Promise<{ network?: string; country?: string }> {
  try {
    // ARIN's service answers for any IP address (it forwards to the right regional registry).
    const res = await withTimeout(f(`https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`, { headers: { Accept: "application/rdap+json, application/json" } }), timeoutMs, "Hosting lookup");
    if (!res.ok) return {};
    const d: any = await res.json();
    const org = (d.entities || []).map((e: any) => (e?.vcardArray?.[1] || []).find((x: any) => x[0] === "fn")?.[3]).find(Boolean);
    return { network: org || d.name, country: d.country };
  } catch {
    return {};
  }
}

export async function lookupEmailSetup(
  domain: string,
  resolveMx: (d: string) => Promise<{ exchange: string; priority: number }[]>,
  resolveTxt: (d: string) => Promise<string[][]>,
  timeoutMs: number,
): Promise<BusinessFacts["email"]> {
  const safe = <T,>(p: Promise<T>, fallback: T) => withTimeout(p, timeoutMs, "DNS").catch(() => fallback);
  const [mx, txt, dmarc] = await Promise.all([
    safe(resolveMx(domain), [] as { exchange: string; priority: number }[]),
    safe(resolveTxt(domain), [] as string[][]),
    safe(resolveTxt(`_dmarc.${domain}`), [] as string[][]),
  ]);
  const flat = (r: string[][]) => r.map((x) => x.join(""));
  return {
    canReceiveEmail: mx.some((m) => m.exchange && m.exchange !== "."),
    spf: flat(txt).some((t) => /^v=spf1/i.test(t)),
    dmarc: flat(dmarc).some((t) => /^v=dmarc1/i.test(t)),
  };
}

export function getCertificate(hostname: string): Promise<BusinessFacts["ssl"]> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 6000 }, () => {
      const cert = socket.getPeerCertificate();
      resolve({
        valid: socket.authorized,
        issuer: (cert?.issuer as any)?.O || (cert?.issuer as any)?.CN,
        expiresOn: cert?.valid_to ? new Date(cert.valid_to).toISOString().slice(0, 10) : undefined,
        error: socket.authorized ? undefined : String(socket.authorizationError || "not trusted"),
      });
      socket.end();
    });
    socket.on("error", (e) => resolve({ valid: false, error: e.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ valid: false, error: "timed out" }); });
  });
}

export async function checkSafeBrowsing(url: string, key: string | undefined, f: typeof fetch, timeoutMs: number): Promise<BusinessFacts["blocklist"]> {
  if (!key) return { checked: false, matches: [] };
  try {
    const res = await withTimeout(f(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "business-check", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }],
        },
      }),
    }), timeoutMs, "Safe Browsing");
    if (!res.ok) return { checked: false, matches: [] };
    const d: any = await res.json();
    return { checked: true, matches: [...new Set<string>((d.matches || []).map((m: any) => m.threatType))] };
  } catch {
    return { checked: false, matches: [] };
  }
}
