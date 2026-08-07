// Passive, server-side detectors. Everything here is derived from what the edge
// (a reverse proxy, CDN, or Cloudflare-style Worker) already observes on the
// connection — no JavaScript required and nothing the client can silently omit.
// This is the JA4-adjacent layer: it fingerprints the transport and header
// shape, and flags datacenter origins and non-browser stacks.
//
// The `edge` half of a bundle is expected to look like the object returned by a
// request-context endpoint: geo, ASN/org, TLS parameters, HTTP protocol, and
// the observed header order.
import { claim, stableHash } from "./signals.js";

const has = (v) => v !== undefined && v !== null && v !== "";

// Substrings that mark an autonomous-system org as hosting/cloud rather than a
// consumer ISP. A residential visitor almost never originates from these.
const HOSTING_ORGS = [
  "amazon", "aws", "google", "gcp", "microsoft", "azure", "digitalocean",
  "ovh", "hetzner", "linode", "akamai", "cloudflare", "fastly", "vultr",
  "leaseweb", "contabo", "scaleway", "oracle cloud", "alibaba", "tencent",
  "choopa", "m247", "datacamp", "colocation", "hosting", "server",
];

// Headers a mainstream browser effectively always sends on a top-level GET.
const BROWSER_HEADERS = ["accept", "accept-language", "accept-encoding", "user-agent"];

/** Origin AS belongs to a hosting/cloud provider, not a consumer ISP. */
export function datacenterOrigin(b) {
  const e = b.edge ?? {};
  if (!has(e.asOrganization)) return [];
  const org = e.asOrganization.toLowerCase();
  if (!HOSTING_ORGS.some((k) => org.includes(k))) return [];
  return [claim({
    id: "net.datacenter-origin",
    text: `Connection originates from a hosting provider (*${e.asOrganization}*), not a residential ISP.`,
    confidence: "likely", category: "network", weight: 6,
    evidence: [`asn=${e.asn}`, `asOrganization=${e.asOrganization}`],
    how: "Match the AS organization against a list of known cloud/hosting operators.",
  })];
}

/** Outdated TLS — modern browsers negotiate 1.2+; 1.0/1.1 signals an old stack or script. */
export function outdatedTls(b) {
  const e = b.edge ?? {};
  if (!has(e.tlsVersion)) return [];
  const m = String(e.tlsVersion).match(/1\.(\d)/);
  if (!m) return [];
  if (Number(m[1]) >= 2) return [];
  return [claim({
    id: "net.outdated-tls",
    text: `Handshake negotiated *${e.tlsVersion}* — below what any current browser uses.`,
    confidence: "likely", category: "network", weight: 5,
    evidence: [`tlsVersion=${e.tlsVersion}`, `tlsCipher=${e.tlsCipher}`],
    how: "Current browsers refuse TLS < 1.2; older versions imply a library/script client.",
  })];
}

/** Browser UA over HTTP/1.1 when it would normally reach the edge via h2/h3. */
export function protocolMismatch(b) {
  const e = b.edge ?? {};
  const looksBrowser = /chrome|firefox|safari|edg/i.test(e.userAgent ?? "");
  if (!looksBrowser || !has(e.httpProtocol)) return [];
  if (!/http\/1/i.test(e.httpProtocol)) return [];
  return [claim({
    id: "net.protocol-downgrade",
    text: `User-Agent claims a modern browser but the request arrived over *${e.httpProtocol}*.`,
    confidence: "guess", category: "network", weight: 4,
    evidence: [`httpProtocol=${e.httpProtocol}`, `userAgent=${e.userAgent}`],
    how: "Modern browsers reach an HTTP/2+ edge over h2/h3; h1 hints at a non-browser client.",
  })];
}

/** A browser UA that is missing headers every real browser sends. */
export function missingBrowserHeaders(b) {
  const e = b.edge ?? {};
  if (!Array.isArray(e.headerOrder) || !has(e.userAgent)) return [];
  if (!/chrome|firefox|safari|edg/i.test(e.userAgent)) return [];
  const present = new Set(e.headerOrder.map((h) => String(h).toLowerCase()));
  const missing = BROWSER_HEADERS.filter((h) => !present.has(h));
  if (missing.length === 0) return [];
  return [claim({
    id: "net.missing-browser-headers",
    text: `Request omits headers a real browser always sends: *${missing.join(", ")}*.`,
    confidence: "likely", category: "automation", weight: 6,
    evidence: [`missing=${missing.join(",")}`, `headerOrder=${e.headerOrder.join(",")}`],
    how: "Compare the observed header set against the baseline a browser emits on a GET.",
  })];
}

/** Chrome UA with no Client Hints — Chromium sends sec-ch-ua by default. */
export function missingClientHints(b) {
  const e = b.edge ?? {};
  const isChromium = /chrome|edg|crios/i.test(e.userAgent ?? "") && !/firefox/i.test(e.userAgent ?? "");
  if (!isChromium || !Array.isArray(e.headerOrder)) return [];
  const present = new Set(e.headerOrder.map((h) => String(h).toLowerCase()));
  if (present.has("sec-ch-ua")) return [];
  return [claim({
    id: "net.missing-client-hints",
    text: "Client presents as Chromium but sent no sec-ch-ua Client Hints.",
    confidence: "likely", category: "automation", weight: 5,
    evidence: [`headerOrder=${e.headerOrder.join(",")}`],
    how: "Chromium attaches low-entropy UA Client Hints by default; scripts usually don't.",
  })];
}

/**
 * A coarse, deterministic transport fingerprint in the spirit of JA3/JA4:
 * hash the stable shape of the connection (TLS version + cipher + ClientHello
 * length + header order) into a short cluster key. Not a substitute for a real
 * JA4 computed from the ClientHello bytes — it is a clustering aid over the
 * attributes an edge Worker readily exposes.
 * @returns {string|null} 8-hex cluster key, or null if too little is known.
 */
export function edgeFingerprint(edge) {
  if (!edge) return null;
  const parts = [
    edge.tlsVersion, edge.tlsCipher, edge.tlsClientHelloLength, edge.httpProtocol,
    Array.isArray(edge.headerOrder) ? edge.headerOrder.join(",") : edge.headerOrder,
  ].filter(has);
  if (parts.length < 2) return null;
  return stableHash(parts.join("|"));
}

export const EDGE_DETECTORS = [
  datacenterOrigin,
  outdatedTls,
  protocolMismatch,
  missingBrowserHeaders,
  missingClientHints,
];
