// Automation / headless detectors. These target the tells left by headless
// Chromium, Playwright/Puppeteer/Selenium drivers, and the VM/software-render
// environments they usually run in. Individually most are weak — a real browser
// can trip one — so they are scored cumulatively, and only the definitive tells
// (navigator.webdriver, a "HeadlessChrome" token) carry certain/high weight.
import { claim } from "./signals.js";

const has = (v) => v !== undefined && v !== null && v !== "";

/** navigator.webdriver === true — the standardized automation flag. */
export function webdriverFlag(b) {
  const c = b.client ?? {};
  if (c.webdriver !== true) return [];
  return [claim({
    id: "auto.webdriver-flag",
    text: "navigator.webdriver is *true* — the browser is under automation control.",
    confidence: "certain", category: "automation", weight: 9,
    evidence: ["navigator.webdriver=true"],
    how: "The WebDriver spec sets navigator.webdriver on automated sessions.",
  })];
}

/** An explicit headless token in the User-Agent. */
export function headlessToken(b) {
  const ua = (b.client ?? {}).ua ?? "";
  if (!/headless/i.test(ua)) return [];
  return [claim({
    id: "auto.headless-ua-token",
    text: "User-Agent contains a *Headless* token.",
    confidence: "certain", category: "automation", weight: 8,
    evidence: [`ua=${ua}`],
    how: "Headless Chromium advertises 'HeadlessChrome' unless deliberately stripped.",
  })];
}

/** Claims to be Chrome but window.chrome is absent — a common patch gap. */
export function missingChromeObject(b) {
  const c = b.client ?? {};
  const isChrome = /chrome|crios/i.test(c.ua ?? "") && !/edg|opr|brave/i.test(c.ua ?? "");
  if (!isChrome || c.hasChromeObject === undefined) return [];
  if (c.hasChromeObject === true) return [];
  return [claim({
    id: "auto.missing-window-chrome",
    text: "Client presents as Chrome but the window.chrome object is missing.",
    confidence: "likely", category: "automation", weight: 6,
    evidence: [`ua=${c.ua}`, "hasChromeObject=false"],
    how: "Genuine Chrome exposes window.chrome; many headless setups do not.",
  })];
}

/** No languages at all — headless launched without a locale. */
export function emptyLanguages(b) {
  const c = b.client ?? {};
  const empty = (Array.isArray(c.languages) && c.languages.length === 0) ||
    (c.languages !== undefined && !has(c.language) && !Array.isArray(c.languages));
  if (!empty) return [];
  return [claim({
    id: "auto.empty-languages",
    text: "navigator.languages is empty — typical of a headless launch with no locale.",
    confidence: "likely", category: "automation", weight: 5,
    evidence: [`languages=${JSON.stringify(c.languages)}`],
    how: "Interactive browsers always carry at least one configured language.",
  })];
}

/** Software renderer — SwiftShader / llvmpipe / Mesa in a datacenter GPU-less box. */
export function softwareRenderer(b) {
  const c = b.client ?? {};
  const r = `${c.webglVendor ?? ""} ${c.webglRenderer ?? ""}`.toLowerCase();
  if (!has(r.trim())) return [];
  if (!/swiftshader|llvmpipe|mesa offscreen|virgl|microsoft basic render/i.test(r)) return [];
  return [claim({
    id: "auto.software-webgl",
    text: "WebGL is backed by a *software* renderer — common in headless/VM environments.",
    confidence: "likely", category: "automation", weight: 5,
    evidence: [`webglVendor=${c.webglVendor}`, `webglRenderer=${c.webglRenderer}`],
    how: "SwiftShader/llvmpipe indicate no real GPU, as on most cloud/CI hosts.",
  })];
}

/**
 * The classic permissions inconsistency: Notification.permission reads "denied"
 * while permissions.query({name:"notifications"}) reports "prompt". Real Chrome
 * keeps these in sync; headless Chrome historically did not.
 */
export function permissionsInconsistency(b) {
  const c = b.client ?? {};
  if (!has(c.notificationPermission) || !has(c.permissionsNotification)) return [];
  if (!(c.notificationPermission === "denied" && c.permissionsNotification === "prompt")) return [];
  return [claim({
    id: "auto.permissions-mismatch",
    text: "Notification.permission is 'denied' while permissions.query reports 'prompt' — a headless tell.",
    confidence: "likely", category: "automation", weight: 6,
    evidence: [`Notification.permission=${c.notificationPermission}`,
               `permissions.query=${c.permissionsNotification}`],
    how: "These two APIs agree in interactive Chrome; classic headless desynchronizes them.",
  })];
}

/** No browser chrome — outer viewport reports zero, as when nothing is painted. */
export function noWindowChrome(b) {
  const c = b.client ?? {};
  if (typeof c.outerW !== "number" && typeof c.outerH !== "number") return [];
  if (!(c.outerW === 0 || c.outerH === 0)) return [];
  return [claim({
    id: "auto.zero-outer-viewport",
    text: "window.outerWidth/Height is zero — no browser chrome, as in a headless render.",
    confidence: "guess", category: "automation", weight: 4,
    evidence: [`outerW=${c.outerW}`, `outerH=${c.outerH}`],
    how: "Windowed browsers report a non-zero outer viewport including toolbars.",
  })];
}

export const HEADLESS_DETECTORS = [
  webdriverFlag,
  headlessToken,
  missingChromeObject,
  emptyLanguages,
  softwareRenderer,
  permissionsInconsistency,
  noWindowChrome,
];
