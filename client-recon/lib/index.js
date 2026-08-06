// client-recon public API. Feed analyze() a bundle of raw client + edge signals
// and get back the derived claims, a transport fingerprint, and an anomaly
// score/verdict for a triage gate. Detectors are pure and independent, so the
// caller can also import any single one for targeted checks.
import { score } from "./signals.js";
import { LIE_DETECTORS } from "./lies.js";
import { HEADLESS_DETECTORS } from "./headless.js";
import { EDGE_DETECTORS, edgeFingerprint } from "./edge.js";

export { claim, score, stableHash } from "./signals.js";
export { edgeFingerprint } from "./edge.js";
export { LIE_DETECTORS } from "./lies.js";
export { HEADLESS_DETECTORS } from "./headless.js";
export { EDGE_DETECTORS } from "./edge.js";

// Everything, in evaluation order. Client-side detectors first, edge last.
export const ALL_DETECTORS = [
  ...LIE_DETECTORS,
  ...HEADLESS_DETECTORS,
  ...EDGE_DETECTORS,
];

/**
 * Run detectors over a bundle and summarize.
 * @param {{ client?: object, edge?: object }} bundle
 * @param {{ detectors?: Function[] }} [opts]
 * @returns {{ claims: import("./signals.js").Claim[], score: number,
 *             verdict: string, hard: boolean, fingerprint: string|null,
 *             categories: Record<string, number> }}
 */
export function analyze(bundle, opts = {}) {
  const b = bundle ?? {};
  const detectors = opts.detectors ?? ALL_DETECTORS;
  const claims = [];
  for (const d of detectors) {
    // A misbehaving detector must not sink the whole analysis; record and move on.
    try {
      const got = d(b);
      if (Array.isArray(got)) claims.push(...got);
    } catch (err) {
      claims.push({
        id: `error.${d.name || "detector"}`,
        text: `Detector ${d.name || "?"} threw: ${err.message}`,
        confidence: "guess", category: "deception", weight: 0, evidence: [], how: "",
      });
    }
  }
  // Highest-weight, most-confident claims first, so a reviewer reads the tells in order.
  const order = { certain: 0, likely: 1, guess: 2 };
  claims.sort((a, c) => (order[a.confidence] - order[c.confidence]) || (c.weight - a.weight));

  const categories = {};
  for (const c of claims) categories[c.category] = (categories[c.category] ?? 0) + 1;

  return {
    ...score(claims),
    claims,
    fingerprint: edgeFingerprint(b.edge),
    categories,
  };
}
