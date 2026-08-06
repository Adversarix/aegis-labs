// Tests for client-recon. Pure functions + fixtures + a CLI subprocess check.
// Run: node client-recon.test.mjs
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { analyze, stableHash, edgeFingerprint, score, claim } from "./lib/index.js";
import { platformMismatch, languageMismatch, impossibleScreen } from "./lib/lies.js";
import { webdriverFlag, softwareRenderer } from "./lib/headless.js";
import { datacenterOrigin, missingBrowserHeaders } from "./lib/edge.js";
import { collectClient } from "./collect/client.js";
import { edgeContext } from "./collect/edge.js";

const DIR = dirname(fileURLToPath(import.meta.url));
const BIN = join(DIR, "bin", "client-recon.js");
const fixture = (name) => JSON.parse(readFileSync(join(DIR, "fixtures", name), "utf8"));

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };
const hasClaim = (claims, id) => claims.some((c) => c.id === id);

// --- engine: score + verdict bands ---
ok("empty claim set is clean", score([]).verdict === "clean" && score([]).score === 0);
ok("a certain high-weight claim forces adversarial", score([
  claim({ id: "x", text: "", confidence: "certain", weight: 9, category: "automation" }),
]).verdict === "adversarial");
ok("hardening claims do not score", score([
  claim({ id: "h", text: "", confidence: "likely", weight: 3, category: "hardening" }),
]).score === 0);
ok("a lone weak guess stays clean", score([
  claim({ id: "g", text: "", confidence: "guess", weight: 4, category: "network" }),
]).verdict === "clean");

// --- engine: stableHash is deterministic + fixed-width ---
ok("stableHash is deterministic", stableHash("aegis") === stableHash("aegis"));
ok("stableHash differs on input", stableHash("aegis") !== stableHash("aegis "));
ok("stableHash is 8 hex chars", /^[0-9a-f]{8}$/.test(stableHash("anything")));

// --- individual detectors ---
ok("platformMismatch flags UA vs navigator.platform", hasClaim(
  platformMismatch({ client: { ua: "Windows NT 10.0", platform: "Linux x86_64" } }),
  "ua.platform-navigator-mismatch"));
ok("platformMismatch silent when consistent", platformMismatch({
  client: { ua: "Windows NT 10.0", platform: "Win32" } }).length === 0);
ok("languageMismatch compares primary subtag", hasClaim(
  languageMismatch({ client: { language: "ru-RU" }, edge: { acceptLanguage: "en-US,en;q=0.9" } }),
  "lang.js-vs-header-mismatch"));
ok("languageMismatch ignores en-US vs en-GB", languageMismatch({
  client: { language: "en-GB" }, edge: { acceptLanguage: "en-US,en;q=0.9" } }).length === 0);
ok("impossibleScreen flags avail>total", hasClaim(
  impossibleScreen({ client: { screenW: 800, availW: 1200 } }), "screen.avail-exceeds-total"));
ok("webdriverFlag flags true", hasClaim(webdriverFlag({ client: { webdriver: true } }), "auto.webdriver-flag"));
ok("webdriverFlag silent on false", webdriverFlag({ client: { webdriver: false } }).length === 0);
ok("softwareRenderer flags SwiftShader", hasClaim(
  softwareRenderer({ client: { webglRenderer: "Google SwiftShader" } }), "auto.software-webgl"));
ok("datacenterOrigin flags AWS", hasClaim(
  datacenterOrigin({ edge: { asOrganization: "Amazon AWS EC2", asn: 14618 } }), "net.datacenter-origin"));
ok("datacenterOrigin silent on consumer ISP", datacenterOrigin({
  edge: { asOrganization: "Comcast Cable Communications" } }).length === 0);
ok("missingBrowserHeaders flags absent accept-language", hasClaim(
  missingBrowserHeaders({ edge: { userAgent: "Chrome/126", headerOrder: ["host", "user-agent", "accept"] } }),
  "net.missing-browser-headers"));

// --- robustness ---
ok("analyze tolerates an empty bundle", analyze({}).verdict === "clean");
ok("analyze tolerates missing halves", analyze({ client: {} }).claims.length === 0);
ok("a throwing detector is contained", (() => {
  const boom = () => { throw new Error("kaboom"); };
  const r = analyze({}, { detectors: [boom] });
  return hasClaim(r.claims, "error.boom") && r.verdict === "clean";
})());

// --- fixtures end to end ---
const honest = analyze(fixture("honest-chrome.json"));
ok("honest chrome is clean", honest.verdict === "clean");
ok("honest chrome has a fingerprint", /^[0-9a-f]{8}$/.test(honest.fingerprint));

const headless = analyze(fixture("headless-puppeteer.json"));
ok("headless puppeteer is adversarial", headless.verdict === "adversarial");
ok("headless flags webdriver", hasClaim(headless.claims, "auto.webdriver-flag"));
ok("headless flags software webgl", hasClaim(headless.claims, "auto.software-webgl"));
ok("headless flags datacenter origin", hasClaim(headless.claims, "net.datacenter-origin"));

const spoofed = analyze(fixture("spoofed-ua.json"));
ok("spoofed UA is at least suspect", spoofed.verdict === "suspect" || spoofed.verdict === "adversarial");
ok("spoofed flags platform mismatch", hasClaim(spoofed.claims, "ua.platform-navigator-mismatch"));
ok("spoofed flags UA js-vs-wire", hasClaim(spoofed.claims, "ua.js-vs-wire-mismatch"));
ok("spoofed flags timezone mismatch", hasClaim(spoofed.claims, "geo.timezone-mismatch"));

// --- claim ordering: certain before guess ---
ok("claims are ordered by confidence then weight", (() => {
  const cs = headless.claims;
  const rank = { certain: 0, likely: 1, guess: 2 };
  for (let i = 1; i < cs.length; i++) if (rank[cs[i - 1].confidence] > rank[cs[i].confidence]) return false;
  return true;
})());

// --- edgeFingerprint needs enough signal ---
ok("edgeFingerprint returns null on thin edge", edgeFingerprint({ tlsVersion: "TLSv1.3" }) === null);
ok("edgeFingerprint is stable across calls", (() => {
  const e = fixture("honest-chrome.json").edge;
  return edgeFingerprint(e) === edgeFingerprint(e);
})());

// --- CLI subprocess: exit code doubles as a gate ---
function cli(args, expectFail) {
  try { return { status: 0, out: execFileSync("node", [BIN, ...args], { encoding: "utf8" }) }; }
  catch (e) { return { status: e.status ?? 1, out: (e.stdout || "") + (e.stderr || "") }; }
}
const cleanRun = cli([join(DIR, "fixtures", "honest-chrome.json")]);
ok("CLI exits 0 on clean bundle", cleanRun.status === 0 && /verdict:\s+clean/.test(cleanRun.out));
const advRun = cli([join(DIR, "fixtures", "headless-puppeteer.json")]);
ok("CLI exits 1 on adversarial bundle", advRun.status === 1 && /verdict:\s+adversarial/.test(advRun.out));
const jsonRun = cli(["--json", join(DIR, "fixtures", "spoofed-ua.json")]);
ok("CLI --json emits parseable output", (() => { try { JSON.parse(jsonRun.out); return true; } catch { return false; } })());

// --- collect/edge: build the edge half from headers + cf context ---
const edgeFromObj = edgeContext({
  headers: {
    "User-Agent": "Mozilla/5.0 Chrome/126",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip",
    "CF-Connecting-IP": "203.0.113.9",
    "sec-ch-ua": '"Chromium";v="126"',
  },
  cf: { country: "US", asn: 7922, asOrganization: "Comcast", tlsVersion: "TLSv1.3", httpProtocol: "HTTP/2" },
});
ok("edgeContext lifts UA from headers", edgeFromObj.userAgent === "Mozilla/5.0 Chrome/126");
ok("edgeContext lifts client IP", edgeFromObj.ip === "203.0.113.9");
ok("edgeContext merges cf fields", edgeFromObj.asOrganization === "Comcast" && edgeFromObj.tlsVersion === "TLSv1.3");
ok("edgeContext records lowercased header order", edgeFromObj.headerOrder.includes("user-agent"));
ok("edgeContext groups client hints", edgeFromObj.clientHints && edgeFromObj.clientHints["sec-ch-ua"] === '"Chromium";v="126"');
ok("edgeContext omits absent fields", !("city" in edgeFromObj));

// A WHATWG Headers instance is accepted the same way as a plain object.
const wh = new Headers({ "user-agent": "curl/8", "x-forwarded-proto": "http/1.1" });
const edgeFromHeaders = edgeContext({ headers: wh });
ok("edgeContext accepts a Headers instance", edgeFromHeaders.userAgent === "curl/8");
ok("edgeContext falls back to x-forwarded-proto", edgeFromHeaders.httpProtocol === "http/1.1");
ok("edgeContext tolerates no input", typeof edgeContext() === "object");

// --- collect/edge -> analyze round trip flags a non-browser client ---
const rt = analyze({ edge: edgeContext({
  headers: { "user-agent": "python-requests/2.31.0", host: "x" },
  cf: { asOrganization: "DigitalOcean LLC", asn: 14061 },
}) });
ok("collected edge round-trips through analyze", rt.claims.some((c) => c.id === "net.datacenter-origin"));

// --- collect/client: runs under an injected (mock) environment ---
const mockEnv = {
  navigator: {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0",
    platform: "Win32", webdriver: false, language: "en-US", languages: ["en-US", "en"],
    maxTouchPoints: 0, hardwareConcurrency: 8, deviceMemory: 8,
    permissions: { query: async () => ({ state: "prompt" }) },
  },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040 },
  window: { outerWidth: 1920, outerHeight: 1030, devicePixelRatio: 1, chrome: {} },
  performance: { now: () => 0 },
  Intl: { DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: "America/New_York" }) }) },
  Notification: { permission: "default" },
};
const collected = await collectClient(mockEnv);
ok("collectClient reads the mock UA", collected.ua.includes("Chrome/126"));
ok("collectClient reads screen + timezone", collected.screenW === 1920 && collected.timezone === "America/New_York");
ok("collectClient reads window.chrome presence", collected.hasChromeObject === true);
ok("collectClient resolves permissions state", collected.permissionsNotification === "prompt");
ok("collectClient omits unobserved WebGL fields", !("webglRenderer" in collected));
// Under a mock, sampled "native" functions (e.g. permissions.query) are ordinary
// JS, so toStringNative is false by construction — that is the detector working,
// not a real client. Real browser globals are native. Normalize it, then the
// collected bundle should read clean end to end.
ok("collectClient flags mock natives as non-native", collected.toStringNative === false);
ok("collected client bundle is clean through analyze",
  analyze({ client: { ...collected, toStringNative: true } }).verdict === "clean");

// A malformed env must not throw — probes degrade to omitted fields.
const collectedEmpty = await collectClient({});
ok("collectClient tolerates an empty environment", typeof collectedEmpty === "object");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
