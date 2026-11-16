// Tests for the shared custody ledger (ledger.js). Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { createLedger, deriveKey, canonical, sha256, GENESIS } from "./ledger.js";

const KEY = deriveKey("unit-test-key");
const mk = (humanActions = ["export", "dispose"]) => createLedger({ key: KEY, humanActions });

test("append chains events and verify holds", () => {
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness", reason: "init" });
  L.append(chain, { action: "bound", actor: "operator", run_id: "r1", extra: { capture_id: "abc", role: "trigger" } });
  assert.equal(chain.length, 2);
  assert.equal(chain[0].seq, 0);
  assert.equal(chain[0].prev, GENESIS);
  assert.equal(chain[1].prev, chain[0].hmac);
  assert.deepEqual(L.verify(chain), { ok: true });
});

test("append returns the event and preserves extra fields", () => {
  const L = mk();
  const chain = [];
  const ev = L.append(chain, { action: "bound", actor: "op", extra: { capture_id: "x", role: "response" } });
  assert.equal(ev.capture_id, "x");
  assert.equal(ev.role, "response");
  assert.ok(ev.event_hash && ev.hmac);
});

test("append rejects bad args", () => {
  const L = mk();
  assert.throws(() => L.append(null, { action: "a", actor: "b" }), /ledger array/);
  assert.throws(() => L.append([], { actor: "b" }), /\{action, actor\}/);
  assert.throws(() => L.append([], { action: "a" }), /\{action, actor\}/);
});

test("verify detects a tampered body", () => {
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness", reason: "init" });
  L.append(chain, { action: "bound", actor: "op", reason: "orig" });
  chain[1].reason = "edited";
  const r = L.verify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 1);
  assert.match(r.reason, /hash mismatch/);
});

test("verify detects a forged/edited signature", () => {
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness" });
  // Flip the signature to a valid-length but wrong hex value.
  chain[0].hmac = chain[0].hmac.replace(/^./, (c) => (c === "a" ? "b" : "a"));
  const r = L.verify(chain);
  assert.equal(r.ok, false);
  assert.match(r.reason, /signature mismatch/);
});

test("verify detects a broken prev linkage", () => {
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness" });
  L.append(chain, { action: "bound", actor: "op" });
  chain[1].prev = GENESIS; // unlink
  const r = L.verify(chain);
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 1);
});

test("verify under the wrong key fails", () => {
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness" });
  const other = createLedger({ key: deriveKey("different"), humanActions: [] });
  assert.equal(other.verify(chain).ok, false);
});

test("requireAuthz gates human actions and allows a token", () => {
  const L = mk(["export", "dispose"]);
  assert.throws(() => L.requireAuthz("export", null), /AUTHZ_REQUIRED|requires a human authorization/);
  assert.throws(() => L.requireAuthz("export", { role: "x" }), /requires a human authorization/); // no actor
  assert.doesNotThrow(() => L.requireAuthz("export", { role: "disclosure-owner", actor: "kish" }));
  // non-human actions are never gated
  assert.doesNotThrow(() => L.requireAuthz("bound", null));
});

test("append does NOT enforce authz (chamber-authorized action path)", () => {
  // A human-set action appended without a token must still be recorded: this is the
  // detonate case, chamber-authorized rather than token-authorized.
  const L = mk(["detonate", "export"]);
  const chain = [];
  assert.doesNotThrow(() => L.append(chain, { action: "detonate", actor: "chamber", run_id: "r9" }));
  assert.equal(L.verify(chain).ok, true);
});

test("authzRef hashes the token, null when absent", () => {
  const L = mk();
  assert.equal(L.authzRef(null), null);
  const ref = L.authzRef({ role: "r", actor: "a" });
  assert.equal(ref, sha256(canonical({ role: "r", actor: "a" })));
  // the token itself is never stored, only its hash
  const chain = [];
  L.append(chain, { action: "export", actor: "a", authorization: { role: "r", actor: "a", secret: "t0ken" } });
  assert.ok(chain[0].authorization_ref);
  assert.equal(JSON.stringify(chain[0]).includes("t0ken"), false);
});

test("byte-compatible with the documented inline scheme", () => {
  // Pin the wire format: identical to the scheme the munitions store used inline.
  const L = mk();
  const canon = (o) => JSON.stringify(o, Object.keys(o).sort());
  const sh = (s) => createHash("sha256").update(s).digest("hex");
  const inline = (events, { action, actor, run_id = null, authorization = null, reason = "", extra = {} }) => {
    const prev = events.length ? events[events.length - 1].hmac : "GENESIS";
    const body = { seq: events.length, prev, action, actor, run_id,
      authorization_ref: authorization ? sh(canon(authorization)) : null, reason, ...extra };
    const event_hash = sh(canon(body) + prev);
    const hmac = createHmac("sha256", KEY).update(event_hash).digest("hex");
    events.push({ ...body, event_hash, hmac });
  };
  const a = [], b = [];
  const spec1 = { action: "create", actor: "harness", reason: "x", extra: { foo: 1 } };
  const spec2 = { action: "export", actor: "a", authorization: { role: "r", actor: "a" }, extra: { destination: "d" } };
  L.append(a, spec1); inline(b, spec1);
  L.append(a, spec2); inline(b, spec2);
  assert.deepEqual(a, b);
});

test("KNOWN LIMITATION: tail truncation is not self-detectable", () => {
  // verify() validates whatever array it is given; a dropped tail leaves a shorter
  // but internally-valid chain. The store layer must anchor the head hmac + count
  // externally to detect truncation (see evidence-custody-spec.md build notes).
  const L = mk();
  const chain = [];
  L.append(chain, { action: "create", actor: "harness" });
  L.append(chain, { action: "bound", actor: "op" });
  chain.pop(); // truncate the tail
  assert.equal(L.verify(chain).ok, true); // documents the gap, intentionally
});
