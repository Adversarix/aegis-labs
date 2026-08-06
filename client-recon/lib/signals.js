// client-recon signal/claim engine. The detectors elsewhere in this module are
// written independently of each other and of whatever collector produced the
// raw bundle, so this file is the contract they share: a Signal is a raw
// measurement, a Claim is a plain-English assertion derived from signals, and
// analyze() folds a set of claims into a single anomaly score + verdict.
//
// Nothing here trusts the client. Client-supplied fields are attacker-
// controllable; edge-observed fields are merely harder to forge. Detectors
// encode that asymmetry — the highest-weight claims come from cross-checking a
// client's self-report against what the edge actually saw.

/**
 * @typedef {"certain" | "likely" | "guess"} Confidence
 * How strongly the evidence supports a claim. Drives both the score multiplier
 * and whether a single claim can hard-set the verdict.
 */

/**
 * @typedef {Object} Claim
 * @property {string} id           Stable identifier, e.g. "ua.platform-mismatch".
 * @property {string} text         Plain-English assertion for a human reviewer.
 * @property {Confidence} confidence
 * @property {"deception" | "automation" | "network" | "hardening"} category
 * @property {number} weight       Narrative importance, 0-10 (cf. cookie's scale).
 * @property {string[]} evidence   Signal ids / values the claim rests on.
 * @property {string} how          One line on the method, so findings are auditable.
 */

// Confidence -> score multiplier. A "guess" contributes a third of its weight,
// a "certain" claim its full weight. Kept deliberately conservative so a pile
// of weak guesses cannot on its own manufacture a high-confidence verdict.
const CONFIDENCE_MULT = { certain: 1.0, likely: 0.6, guess: 0.3 };

// A single certain claim at or above this weight is, by itself, enough to call
// the client adversarial regardless of the summed score (e.g. navigator.webdriver).
const HARD_VERDICT_WEIGHT = 8;

// "hardening" claims describe privacy-defensive clients (Brave, Tor Browser,
// anti-fingerprint extensions). They are informative for clustering but are not
// evidence of malicious intent, so they never contribute to the anomaly score.
const NON_SCORING = new Set(["hardening"]);

/**
 * Construct a Claim with defaults filled in. Detectors call this so the shape
 * stays uniform and evidence is never accidentally omitted.
 * @param {Partial<Claim> & { id: string, text: string }} c
 * @returns {Claim}
 */
export function claim(c) {
  return {
    id: c.id,
    text: c.text,
    confidence: c.confidence ?? "guess",
    category: c.category ?? "deception",
    weight: clamp(c.weight ?? 5, 0, 10),
    evidence: c.evidence ?? [],
    how: c.how ?? "",
  };
}

/**
 * Fold claims into a 0-100 anomaly score and a verdict band. The score is a
 * heuristic for triage/clustering, not a probability; the verdict is what an
 * automated gate should key on.
 * @param {Claim[]} claims
 * @returns {{ score: number, verdict: string, hard: boolean }}
 */
export function score(claims) {
  let points = 0;
  let hard = false;
  for (const c of claims) {
    if (NON_SCORING.has(c.category)) continue;
    points += c.weight * (CONFIDENCE_MULT[c.confidence] ?? 0.3);
    if (c.confidence === "certain" && c.weight >= HARD_VERDICT_WEIGHT) hard = true;
  }
  const s = clamp(Math.round(points), 0, 100);
  return { score: s, verdict: verdictFor(s, hard), hard };
}

// Bands are intentionally coarse — the downstream gate wants a decision, not a
// false sense of precision. `hard` short-circuits to the top band.
function verdictFor(s, hard) {
  if (hard || s >= 70) return "adversarial";
  if (s >= 40) return "suspect";
  if (s >= 15) return "anomalous";
  return "clean";
}

export function clamp(n, lo, hi) {
  return Math.min(hi, Math.max(lo, n));
}

/**
 * Deterministic 32-bit FNV-1a hash rendered as 8 lowercase hex chars. Used to
 * turn a set of stable attributes (fonts, TLS shape, header order) into a short
 * cluster key without pulling in a crypto dependency, and it produces the same
 * value in a browser or on the edge.
 * @param {string} str
 * @returns {string}
 */
export function stableHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    // 32-bit FNV prime multiply via shifts to stay in integer range.
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
