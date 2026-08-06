// Browser-side collector. Runs in the page and builds the `client` half of a
// client-recon bundle — the browser's self-report plus a few derived tells
// (software renderer, patched natives, timer resolution) that detectors key on.
//
// Everything is best-effort: any probe that throws or is unsupported is skipped,
// so the collector never breaks the page and simply omits fields the detectors
// then treat as "unknown". Nothing here is trusted downstream — it is exactly
// the attacker-controllable self-report the edge signals are checked against.
//
// Import and call in the browser:
//   import { collectClient } from "./collect/client.js";
//   const client = await collectClient();
//   // POST { client } to your endpoint; the server pairs it with edgeContext().
//
// Or paste the compiled function inline in a <script type="module">. For tests,
// pass a synthetic `env` so the collector runs under Node without a DOM.

/** Run fn and return its value, or `fallback` if it throws / is unsupported. */
function safe(fn, fallback = undefined) {
  try {
    const v = fn();
    return v === undefined ? fallback : v;
  } catch {
    return fallback;
  }
}

async function safeAsync(fn, fallback = undefined) {
  try {
    const v = await fn();
    return v === undefined ? fallback : v;
  } catch {
    return fallback;
  }
}

/** Resolve the real browser globals; overridable for tests. */
function defaultEnv() {
  return {
    navigator: typeof navigator !== "undefined" ? navigator : undefined,
    screen: typeof screen !== "undefined" ? screen : undefined,
    window: typeof window !== "undefined" ? window : undefined,
    performance: typeof performance !== "undefined" ? performance : undefined,
    Intl: typeof Intl !== "undefined" ? Intl : undefined,
    document: typeof document !== "undefined" ? document : undefined,
    Notification: typeof Notification !== "undefined" ? Notification : undefined,
  };
}

// --- individual probes -------------------------------------------------------

/** WebGL unmasked vendor/renderer via WEBGL_debug_renderer_info. */
function webgl(env) {
  const doc = env.document;
  if (!doc || typeof doc.createElement !== "function") return {};
  const canvas = doc.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return {};
  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  if (!dbg) return {};
  return {
    webglVendor: safe(() => gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)),
    webglRenderer: safe(() => gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)),
  };
}

/**
 * True only if every function we sample still reports as native code. Automation
 * frameworks that hook canvas/WebGL/permissions to fake or suppress signals leave
 * a patched toString behind — that flips this to false.
 */
function nativesIntact(env) {
  const nav = env.navigator;
  const win = env.window;
  const candidates = [
    nav && nav.permissions && nav.permissions.query,
    win && win.HTMLCanvasElement && win.HTMLCanvasElement.prototype.toDataURL,
    win && win.WebGLRenderingContext && win.WebGLRenderingContext.prototype.getParameter,
    Function.prototype.toString,
  ].filter((f) => typeof f === "function");
  if (candidates.length === 0) return undefined;
  return candidates.every((f) => safe(() => Function.prototype.toString.call(f).includes("[native code]"), false));
}

/**
 * Smallest positive delta observed from the high-resolution clock, in ms. Normal
 * browsers report a sub-millisecond value (~0); privacy-hardened browsers coarsen
 * it to 1ms+ to blunt timing side-channels, which the hardening detector reads.
 */
function timerResolutionMs(env) {
  const perf = env.performance;
  if (!perf || typeof perf.now !== "function") return undefined;
  let min = Infinity;
  let last = perf.now();
  for (let i = 0; i < 50000 && min > 0.0001; i++) {
    const t = perf.now();
    const d = t - last;
    if (d > 0 && d < min) min = d;
    last = t;
  }
  return min === Infinity ? undefined : min;
}

/** UA Client Hints (Chromium): mobile flag, platform, and high-entropy values. */
async function clientHints(nav) {
  const uaData = nav && nav.userAgentData;
  if (!uaData) return {};
  const out = {
    uaMobile: safe(() => uaData.mobile),
    uaPlatform: safe(() => uaData.platform),
  };
  const high = await safeAsync(() => uaData.getHighEntropyValues([
    "platform", "platformVersion", "architecture", "bitness", "model", "fullVersionList",
  ]));
  if (high) {
    out.uaPlatform = high.platform ?? out.uaPlatform;
    out.uaPlatformVersion = high.platformVersion;
    out.uaFullVersionList = safe(() =>
      (high.fullVersionList || []).map((b) => `${b.brand} ${b.version}`).join(", "));
  }
  return out;
}

/** navigator.permissions.query state for notifications, guarded. */
async function notificationPermissionState(nav) {
  if (!nav || !nav.permissions || typeof nav.permissions.query !== "function") return undefined;
  const res = await safeAsync(() => nav.permissions.query({ name: "notifications" }));
  return res ? res.state : undefined;
}

// --- top-level collector -----------------------------------------------------

/**
 * Build the `client` bundle. Async because Client Hints and the permissions
 * query are promise-based. Missing globals degrade gracefully to omitted fields.
 * @param {object} [env] Injectable globals (navigator/screen/window/...); real
 *   browser globals by default. Pass a mock to run under Node.
 * @returns {Promise<object>} the `client` half of an analyze() bundle.
 */
export async function collectClient(env = defaultEnv()) {
  const nav = env.navigator ?? {};
  const scr = env.screen ?? {};
  const win = env.window ?? {};
  const tz = safe(() => env.Intl.DateTimeFormat().resolvedOptions().timeZone);

  const client = {
    ua: safe(() => nav.userAgent),
    platform: safe(() => nav.platform),
    webdriver: safe(() => nav.webdriver === true),
    language: safe(() => nav.language),
    languages: safe(() => (Array.isArray(nav.languages) ? nav.languages.slice() : undefined)),
    maxTouchPoints: safe(() => nav.maxTouchPoints),
    hardwareConcurrency: safe(() => nav.hardwareConcurrency),
    deviceMemory: safe(() => nav.deviceMemory),
    screenW: safe(() => scr.width),
    screenH: safe(() => scr.height),
    availW: safe(() => scr.availWidth),
    availH: safe(() => scr.availHeight),
    outerW: safe(() => win.outerWidth),
    outerH: safe(() => win.outerHeight),
    devicePixelRatio: safe(() => win.devicePixelRatio),
    timezone: tz,
    hasChromeObject: safe(() => typeof win.chrome !== "undefined"),
    notificationPermission: safe(() => (env.Notification ? env.Notification.permission : undefined)),
    timerResolutionMs: timerResolutionMs(env),
    toStringNative: nativesIntact(env),
    ...webgl(env),
    ...(await clientHints(nav)),
  };
  client.permissionsNotification = await notificationPermissionState(nav);

  // Drop keys that stayed undefined so the bundle carries only what was observed.
  for (const k of Object.keys(client)) if (client[k] === undefined) delete client[k];
  return client;
}
