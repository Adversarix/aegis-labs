// Custody ledger — the shared append-only, HMAC-signed, hash-chained event log
// used by every store that must be accountable (munitions-custody-policy.md §4/§6,
// evidence-custody-spec.md §4). One implementation, consumed by both
// `src/munitions-store` and `src/evidence-store`, so there is a single chain to
// audit and a single place to harden.
//
// The ledger is deliberately storage- and domain-agnostic. It knows nothing about
// munitions or evidence: it appends signed events to a plain array the caller owns
// (a munition's `ledger[]`, a finding's custody chain), and verifies that array.
// The caller supplies the signing key, the set of actions that require a human
// authorization, and the event contents. Everything that makes the chain tamper-
// evident lives here.
//
// Compatibility: the signing scheme (canonical JSON, sha256 event hash over
// body+prev, HMAC-SHA256 over the event hash, prev = previous event's hmac,
// "GENESIS" at the root) is byte-identical to the inline scheme currently in
// `src/munitions-store/store.js`. Adopting this module there is a behavior-
// preserving refactor: existing on-disk ledgers still verify.
//
// Pure Node builtins, no external deps, so both seams can import it and it is
// unit-testable in isolation.
import { createHmac, createHash, timingSafeEqual } from "node:crypto";

export const GENESIS = "GENESIS";

// Shallow canonical JSON: sort top-level keys, stable stringify. Matches the
// existing munitions store. Event bodies are flat (fixed fields + flat `extra`),
// so shallow sort is sufficient; do not pass nested objects as `extra` values and
// expect their inner keys to be ordered.
export const canonical = (o) => JSON.stringify(o, Object.keys(o).sort());

export const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// Derive a stable 32-byte signing key from caller-supplied material (hex or
// passphrase). Same derivation the munitions store uses, so a store can hand its
// existing key straight through.
export const deriveKey = (material) => createHash("sha256").update(String(material)).digest();

/**
 * Create a ledger bound to one signing key and one authorization policy.
 *
 * @param {object} cfg
 * @param {Buffer|string} cfg.key            Signing key (Buffer) or material to derive one from.
 * @param {Iterable<string>} [cfg.humanActions]  Actions that require a human authorization
 *                                            object `{role, actor}`; all others are harness-
 *                                            authorized. Each store passes its own vocabulary:
 *                                            munitions -> ["arm","detonate","export","dispose"];
 *                                            evidence  -> ["exported","dispose"].
 * @returns {{append, verify, requireAuthz, authzRef}}
 */
export function createLedger({ key, humanActions = [] } = {}) {
  if (key == null) throw new Error("createLedger requires a signing key");
  const signingKey = Buffer.isBuffer(key) ? key : deriveKey(key);
  const humanSet = new Set(humanActions);

  // Hash of a human authorization token — stored instead of the token itself, so
  // the ledger records *that* an action was authorized and by whom-hash, without
  // persisting the secret.
  const authzRef = (authorization) =>
    authorization ? sha256(canonical(authorization)) : null;

  // A human authorization must be an object carrying at least {role, actor}. The
  // harness cannot fabricate one for itself.
  function requireAuthz(action, authorization) {
    if (!humanSet.has(action)) return;
    if (!authorization || !authorization.role || !authorization.actor) {
      const e = new Error(
        `action '${action}' requires a human authorization {role, actor}; the harness cannot self-authorize`
      );
      e.code = "AUTHZ_REQUIRED";
      throw e;
    }
  }

  // Append a signed, hash-chained event to `events` (the caller's ledger array).
  // Pure mechanical primitive: it does NOT enforce authorization. Authorization is
  // an explicit guard the caller invokes at the top of a human-gated operation
  // (`requireAuthz`), kept separate so an action can be appended by an authority
  // other than a human token (e.g. a chamber-authorized detonation) without being
  // refused. If an `authorization` object is passed it is recorded by hash. Returns
  // the event.
  function append(events, { action, actor, run_id = null, authorization = null, reason = "", extra = {} }) {
    if (!Array.isArray(events)) throw new Error("append requires the ledger array as first arg");
    if (!action || !actor) throw new Error("append requires {action, actor}");

    const prev = events.length ? events[events.length - 1].hmac : GENESIS;
    const body = {
      seq: events.length,
      prev,
      action,
      actor,
      run_id,
      authorization_ref: authzRef(authorization),
      reason,
      ...extra,
    };
    const event_hash = sha256(canonical(body) + prev);
    const hmac = createHmac("sha256", signingKey).update(event_hash).digest("hex");
    const event = { ...body, event_hash, hmac };
    events.push(event);
    return event;
  }

  // Walk the chain and recompute every event hash and HMAC. Detects: wrong seq,
  // broken prev linkage, edited body (hash mismatch), and forged/edited signature
  // (hmac mismatch). Returns {ok:true} or {ok:false, brokenAt, reason}. Pure — it
  // never throws on a bad chain, it reports.
  function verify(events) {
    if (!Array.isArray(events)) return { ok: false, brokenAt: -1, reason: "ledger is not an array" };
    let prev = GENESIS;
    for (let i = 0; i < events.length; i++) {
      const ev = events[i];
      if (!ev || typeof ev !== "object") return { ok: false, brokenAt: i, reason: "event is not an object" };
      if (ev.seq !== i) return { ok: false, brokenAt: i, reason: `seq ${ev.seq} != position ${i}` };
      if (ev.prev !== prev) return { ok: false, brokenAt: i, reason: "prev does not chain to previous hmac" };

      // Reconstruct the signed body by dropping the two computed fields.
      const { event_hash, hmac, ...body } = ev;
      const expectHash = sha256(canonical(body) + prev);
      if (expectHash !== event_hash) return { ok: false, brokenAt: i, reason: "event body hash mismatch (tampered)" };

      const expectHmac = createHmac("sha256", signingKey).update(event_hash).digest("hex");
      const a = Buffer.from(String(hmac), "hex");
      const b = Buffer.from(expectHmac, "hex");
      if (a.length !== b.length || !timingSafeEqual(a, b)) {
        return { ok: false, brokenAt: i, reason: "signature mismatch (wrong key or forged)" };
      }
      prev = hmac;
    }
    return { ok: true };
  }

  return { append, verify, requireAuthz, authzRef };
}
