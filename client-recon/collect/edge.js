// Server / edge collector. Builds the `edge` half of a client-recon bundle from
// what the transport already exposes — request headers plus an optional
// connection-context object (Cloudflare's `request.cf`, or the equivalent your
// proxy injects). No client cooperation required and nothing here is spoofable
// from the page.
//
// Framework-agnostic: pass a WHATWG `Headers` instance or a plain header object,
// and a `cf`-shaped context. Example (Cloudflare Pages/Workers):
//
//   import { edgeContext } from "./collect/edge.js";
//   export const onRequestGet = async ({ request }) => {
//     const edge = edgeContext({ headers: request.headers, cf: request.cf });
//     return Response.json({ edge });   // client POSTs its half; you pair them
//   };
//
// The header order returned is the order the runtime iterates headers in — a
// coarse ordering signal. Some runtimes normalize/sort header names, so treat it
// as a clustering aid, not a guarantee of true wire order.

// Connection-context fields we lift verbatim when present. Names follow the
// widely-used Cloudflare `request.cf` shape; adapt the caller if your proxy
// differs. Kept as an explicit allow-list so nothing unexpected leaks through.
const CF_FIELDS = [
  "country", "city", "region", "postalCode", "latitude", "longitude", "timezone",
  "asn", "asOrganization", "colo", "clientTcpRtt",
  "httpProtocol", "tlsVersion", "tlsCipher", "tlsClientHelloLength",
];

// Low-entropy Client Hint / preference headers worth capturing as a group.
const CLIENT_HINT_HEADERS = [
  "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
  "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-full-version-list",
  "device-memory", "downlink", "ect", "rtt", "save-data",
];

/**
 * Normalize a Headers instance or plain object into a lookup with a stable,
 * lowercased key iteration order.
 * @returns {{ get(name: string): string|undefined, keys(): string[] }}
 */
function normalizeHeaders(headers) {
  if (!headers) return { get: () => undefined, keys: () => [] };
  // WHATWG Headers (has .get + iterable keys()).
  if (typeof headers.get === "function" && typeof headers.keys === "function") {
    const keys = [...headers.keys()].map((k) => k.toLowerCase());
    return { get: (n) => headers.get(n) ?? undefined, keys: () => keys };
  }
  // Plain object: index case-insensitively, preserve insertion order.
  const map = new Map();
  for (const [k, v] of Object.entries(headers)) map.set(k.toLowerCase(), v);
  return {
    get: (n) => map.get(String(n).toLowerCase()) ?? undefined,
    keys: () => [...map.keys()],
  };
}

/**
 * Build the `edge` bundle.
 * @param {{ headers?: any, cf?: object }} input
 * @returns {object} the `edge` half of an analyze() bundle.
 */
export function edgeContext({ headers, cf } = {}) {
  const h = normalizeHeaders(headers);
  const ctx = cf ?? {};

  const edge = {
    ip: h.get("cf-connecting-ip") ?? h.get("x-forwarded-for") ?? h.get("x-real-ip"),
    userAgent: h.get("user-agent"),
    acceptLanguage: h.get("accept-language"),
    acceptEncoding: h.get("accept-encoding"),
    accept: h.get("accept"),
    dnt: h.get("dnt"),
    secGpc: h.get("sec-gpc"),
    referer: h.get("referer"),
    headerOrder: h.keys(),
  };

  for (const f of CF_FIELDS) if (ctx[f] !== undefined && ctx[f] !== null) edge[f] = ctx[f];

  // httpProtocol can also arrive as a forwarded header when cf is absent.
  edge.httpProtocol = edge.httpProtocol ?? h.get("x-forwarded-proto");

  const clientHints = {};
  for (const name of CLIENT_HINT_HEADERS) {
    const v = h.get(name);
    if (v !== undefined) clientHints[name] = v;
  }
  if (Object.keys(clientHints).length) edge.clientHints = clientHints;

  for (const k of Object.keys(edge)) if (edge[k] === undefined) delete edge[k];
  return edge;
}
