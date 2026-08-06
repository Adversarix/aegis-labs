// Deception detectors: places where a client's story does not hang together.
// Each function reads the raw bundle and returns Claims. The strongest signals
// are cross-checks between what the browser *says* (client.*, freely spoofable)
// and what the edge *saw* (edge.*, forged only with more effort) — a spoofed
// User-Agent is cheap, but making the TLS stack, header order, and geo-IP all
// agree with the lie is not.
//
// A bundle is the plain object shape documented in ../README.md. Missing fields
// are treated as "unknown" and simply skip their detector — collectors are
// allowed to omit anything.
import { claim } from "./signals.js";

const has = (v) => v !== undefined && v !== null && v !== "";

// OS family keywords as they appear in a User-Agent string. Order matters:
// iOS UAs also contain "like Mac OS X", and Android UAs contain "Linux", so the
// more specific token has to win — check phones before desktop.
const UA_OS = [
  [/iphone|ipad|ios/i, "iOS"],
  [/android/i, "Android"],
  [/cros/i, "ChromeOS"],
  [/windows/i, "Windows"],
  [/macintosh|mac os x/i, "macOS"],
  [/linux/i, "Linux"],
];

function osFromUA(ua) {
  if (!has(ua)) return null;
  // iOS before Linux/Mac: iPhone UAs also contain "like Mac OS X".
  for (const [re, name] of UA_OS) if (re.test(ua)) return name;
  return null;
}

function osFromPlatform(platform) {
  if (!has(platform)) return null;
  const p = platform.toLowerCase();
  if (p.startsWith("win")) return "Windows";
  if (p.startsWith("mac")) return "macOS";
  if (p.includes("linux") || p.includes("x86_64") || p.includes("aarch64")) return "Linux";
  if (p.includes("android")) return "Android";
  if (p.includes("iphone") || p.includes("ipad")) return "iOS";
  return null;
}

/** UA OS family disagrees with navigator.platform / UA-CH platform. */
export function platformMismatch(b) {
  const c = b.client ?? {};
  const uaOs = osFromUA(c.ua);
  const platOs = osFromPlatform(c.platform);
  const chOs = has(c.uaPlatform) ? c.uaPlatform : null;
  const out = [];
  if (uaOs && platOs && uaOs !== platOs) {
    out.push(claim({
      id: "ua.platform-navigator-mismatch",
      text: `User-Agent claims *${uaOs}* but navigator.platform reports *${platOs}*.`,
      confidence: "certain", category: "deception", weight: 8,
      evidence: [`ua=${c.ua}`, `platform=${c.platform}`],
      how: "Compare the OS token in the UA string against navigator.platform.",
    }));
  }
  if (uaOs && chOs && !chOs.toLowerCase().includes(uaOs.toLowerCase()) &&
      !(uaOs === "macOS" && /mac/i.test(chOs))) {
    out.push(claim({
      id: "ua.platform-uach-mismatch",
      text: `User-Agent claims *${uaOs}* but Client Hints report platform *${chOs}*.`,
      confidence: "certain", category: "deception", weight: 8,
      evidence: [`ua=${c.ua}`, `sec-ch-ua-platform=${chOs}`],
      how: "Compare the UA OS token against the UA-CH sec-ch-ua-platform value.",
    }));
  }
  return out;
}

/** UA presented to JS differs from the UA the edge received on the wire. */
export function uaWireMismatch(b) {
  const c = b.client ?? {};
  const e = b.edge ?? {};
  if (!has(c.ua) || !has(e.userAgent)) return [];
  if (c.ua === e.userAgent) return [];
  return [claim({
    id: "ua.js-vs-wire-mismatch",
    text: "The User-Agent seen by JavaScript differs from the one sent on the HTTP request.",
    confidence: "certain", category: "deception", weight: 8,
    evidence: [`client.ua=${c.ua}`, `edge.userAgent=${e.userAgent}`],
    how: "Compare navigator.userAgent against the request User-Agent header.",
  })];
}

/** Mobile claim without the touch surface a phone/tablet would have. */
export function mobileWithoutTouch(b) {
  const c = b.client ?? {};
  const claimsMobile = /mobile|android|iphone|ipad/i.test(c.ua ?? "") || c.uaMobile === true;
  if (!claimsMobile) return [];
  if (typeof c.maxTouchPoints !== "number") return [];
  if (c.maxTouchPoints > 0) return [];
  return [claim({
    id: "ua.mobile-without-touch",
    text: "Client presents as a mobile device but reports *zero* touch points.",
    confidence: "likely", category: "deception", weight: 6,
    evidence: [`ua=${c.ua}`, `maxTouchPoints=${c.maxTouchPoints}`],
    how: "A mobile UA with navigator.maxTouchPoints === 0 is inconsistent hardware.",
  })];
}

/** Browser-reported timezone contradicts the edge geo-IP timezone (VPN/proxy). */
export function timezoneMismatch(b) {
  const c = b.client ?? {};
  const e = b.edge ?? {};
  if (!has(c.timezone) || !has(e.timezone)) return [];
  if (c.timezone === e.timezone) return [];
  return [claim({
    id: "geo.timezone-mismatch",
    text: `Browser timezone *${c.timezone}* does not match the connection's geo-IP timezone *${e.timezone}*.`,
    confidence: "likely", category: "network", weight: 6,
    evidence: [`Intl.timeZone=${c.timezone}`, `edge.timezone=${e.timezone}`],
    how: "Compare Intl.DateTimeFormat().resolvedOptions().timeZone against edge geo-IP.",
  })];
}

/** navigator.language(s) contradict the Accept-Language header. */
export function languageMismatch(b) {
  const c = b.client ?? {};
  const e = b.edge ?? {};
  const jsLang = has(c.language) ? c.language : (Array.isArray(c.languages) ? c.languages[0] : null);
  const hdr = e.acceptLanguage;
  if (!has(jsLang) || !has(hdr)) return [];
  // Compare only the primary subtag (en-US vs en-GB is a soft signal, en vs de is hard).
  const primary = (s) => String(s).toLowerCase().split(",")[0].trim().split("-")[0];
  if (primary(jsLang) === primary(hdr)) return [];
  return [claim({
    id: "lang.js-vs-header-mismatch",
    text: `navigator.language *${jsLang}* disagrees with the Accept-Language header *${hdr}*.`,
    confidence: "likely", category: "deception", weight: 5,
    evidence: [`navigator.language=${jsLang}`, `accept-language=${hdr}`],
    how: "Compare the primary language subtag of navigator.language against Accept-Language.",
  })];
}

/** Screen geometry that cannot physically hold together. */
export function impossibleScreen(b) {
  const c = b.client ?? {};
  const out = [];
  if (typeof c.screenW === "number" && typeof c.availW === "number" &&
      c.screenW > 0 && c.availW > c.screenW) {
    out.push(claim({
      id: "screen.avail-exceeds-total",
      text: "Available screen width exceeds total screen width — geometry is fabricated.",
      confidence: "certain", category: "deception", weight: 7,
      evidence: [`screenW=${c.screenW}`, `availW=${c.availW}`],
      how: "screen.availWidth must be <= screen.width on real hardware.",
    }));
  }
  if ((c.screenW === 0 || c.screenH === 0)) {
    out.push(claim({
      id: "screen.zero-dimension",
      text: "Screen reports a zero dimension — typical of a headless or virtual display.",
      confidence: "likely", category: "automation", weight: 6,
      evidence: [`screenW=${c.screenW}`, `screenH=${c.screenH}`],
      how: "A real display never reports width or height of 0.",
    }));
  }
  return out;
}

/** Native functions whose toString has been patched — a monkey-patch tell. */
export function patchedNatives(b) {
  const c = b.client ?? {};
  if (c.toStringNative === undefined) return [];
  if (c.toStringNative === true) return [];
  return [claim({
    id: "tamper.native-tostring-patched",
    text: "A built-in function no longer reports as native code — the runtime has been *patched*.",
    confidence: "certain", category: "automation", weight: 8,
    evidence: [`toStringNative=${c.toStringNative}`],
    how: "Native funcs stringify to '[native code]'; automation shims replace them.",
  })];
}

/** Coarse or jitter-free performance.now — a hardened/anti-fingerprint browser. */
export function timerCoarsening(b) {
  const c = b.client ?? {};
  if (typeof c.timerResolutionMs !== "number") return [];
  if (c.timerResolutionMs < 1) return [];
  return [claim({
    id: "hardening.timer-coarsened",
    text: `performance.now resolution is coarsened to ~${c.timerResolutionMs}ms — a privacy-hardened browser (Brave/Tor).`,
    confidence: "likely", category: "hardening", weight: 3,
    evidence: [`timerResolutionMs=${c.timerResolutionMs}`],
    how: "Anti-timing browsers round performance.now to blunt fingerprinting/side-channels.",
  })];
}

// Every deception/hardening detector, in one list for the composer.
export const LIE_DETECTORS = [
  platformMismatch,
  uaWireMismatch,
  mobileWithoutTouch,
  timezoneMismatch,
  languageMismatch,
  impossibleScreen,
  patchedNatives,
  timerCoarsening,
];
