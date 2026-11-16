// Tests for the evidence store (store.js). Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openEvidenceStore } from "./store.js";

const fresh = () => openEvidenceStore(mkdtempSync(join(tmpdir(), "evstore-")), { key: "fixed-test-key" });
const AUTHZ = { role: "disclosure-owner", actor: "kish" };

test("seal is content-addressed and dedups", () => {
  const s = fresh();
  const a = s.seal("GET /admin HTTP/1.1\nHost: t", { media_type: "http_exchange" });
  const b = s.seal("GET /admin HTTP/1.1\nHost: t", { media_type: "http_exchange" });
  assert.equal(a.capture_id, b.capture_id);
  assert.equal(a.deduped, false);
  assert.equal(b.deduped, true);
});

test("bind refuses an unsealed capture", () => {
  const s = fresh();
  assert.throws(() => s.bind("f1", { capture_id: "deadbeef", role: "trigger", weight: "probative" }),
    (e) => e.code === "BIND_UNSEALED");
});

test("bind + verifyCustody holds; span quote re-derives from sealed bytes", () => {
  const s = fresh();
  const body = "HTTP/1.1 200 OK\nflag{proven}\n";
  const { capture_id } = s.seal(body, { media_type: "http_exchange" });
  const off = body.indexOf("flag{proven}");
  s.bind("f1", { capture_id, span: { offset: off, length: 12 }, role: "response", weight: "probative", claim: "leak" });
  assert.equal(s.verifyCustody("f1").ok, true);
  assert.equal(s.quote(capture_id, { offset: off, length: 12 }).toString(), "flag{proven}");
});

test("verifyCustody detects a tampered capture blob", () => {
  const dir = mkdtempSync(join(tmpdir(), "evstore-"));
  const s = openEvidenceStore(dir, { key: "fixed-test-key" });
  const { capture_id } = s.seal("proof bytes", { media_type: "tool_io" });
  s.bind("f1", { capture_id, role: "trigger", weight: "probative" });
  // Corrupt the ciphertext on disk.
  const p = join(dir, "captures", `${capture_id}.json`);
  const rec = JSON.parse(readFileSync(p, "utf8"));
  rec.enc.ct = rec.enc.ct.replace(/^../, "00");
  writeFileSync(p, JSON.stringify(rec));
  const r = s.verifyCustody("f1");
  assert.equal(r.ok, false);
  assert.match(r.reason, /tampered|decrypt/);
});

test("hasProbativeBinding gates confirmation", () => {
  const s = fresh();
  const { capture_id } = s.seal("x", { media_type: "tool_io" });
  s.bind("f1", { capture_id, role: "precondition", weight: "context" });
  assert.equal(s.hasProbativeBinding("f1"), false);
  s.bind("f1", { capture_id, role: "trigger", weight: "probative" });
  assert.equal(s.hasProbativeBinding("f1"), true);
});

test("deriveView masks secrets and is content-addressed", () => {
  const s = fresh();
  const raw = "GET / HTTP/1.1\nAuthorization: Bearer abc.def.ghi\nCookie: sid=secret123\n";
  const { capture_id } = s.seal(raw, { media_type: "http_exchange" });
  const v = s.deriveView("f1", { capture_id, mask: true });
  assert.equal(v.bytes.includes("secret123"), false);
  assert.equal(v.bytes.includes("abc.def.ghi"), false);
  assert.match(v.bytes, /<redacted/);
  assert.ok(v.view_id);
});

test("assembleBundle requires a human authorization", () => {
  const s = fresh();
  const { capture_id } = s.seal("proof", { media_type: "tool_io" });
  s.bind("f1", { capture_id, role: "trigger", weight: "probative", claim: "rce" });
  assert.throws(() => s.assembleBundle("f1", {}), (e) => e.code === "AUTHZ_REQUIRED" || /authorization/.test(e.message));
});

test("assembleBundle excludes raw bytes and context, includes a verifiable manifest", () => {
  const s = fresh();
  const raw = "resp Authorization: Bearer tok123 flag{x}";
  const { capture_id } = s.seal(raw, { media_type: "http_exchange" });
  s.bind("f1", { capture_id, role: "response", weight: "probative", claim: "leak" });
  s.bind("f1", { capture_id, role: "precondition", weight: "context", claim: "note" });
  const bundle = s.assembleBundle("f1", { authorization: AUTHZ, minimal_reproducer: "curl ..." });
  assert.equal(bundle.proof_views.length, 1);               // context dropped
  assert.equal(bundle.proof_views[0].view.includes("tok123"), false); // masked
  assert.ok(bundle.custody_manifest.length >= 2);
  assert.ok(bundle.excludes.some((x) => /weapon/.test(x)));
  // exported event recorded
  assert.ok(s.getFinding("f1").events >= 3);
});

test("assembleBundle refuses when custody is broken", () => {
  const dir = mkdtempSync(join(tmpdir(), "evstore-"));
  const s = openEvidenceStore(dir, { key: "fixed-test-key" });
  const { capture_id } = s.seal("proof", { media_type: "tool_io" });
  s.bind("f1", { capture_id, role: "trigger", weight: "probative" });
  const p = join(dir, "captures", `${capture_id}.json`);
  const rec = JSON.parse(readFileSync(p, "utf8")); rec.enc.ct = "00" + rec.enc.ct.slice(2);
  writeFileSync(p, JSON.stringify(rec));
  assert.throws(() => s.assembleBundle("f1", { authorization: AUTHZ }), (e) => e.code === "CUSTODY_BROKEN");
});

test("dispose crypto-shreds; manifest survives the bytes", () => {
  const s = fresh();
  const { capture_id } = s.seal("proof bytes", { media_type: "tool_io" });
  s.bind("f1", { capture_id, role: "trigger", weight: "probative" });
  assert.throws(() => s.dispose(capture_id, {}), (e) => e.code === "AUTHZ_REQUIRED" || /authorization/.test(e.message));
  const d = s.dispose(capture_id, { authorization: AUTHZ });
  assert.equal(d.shredded, true);
  assert.equal(s.verifyCustody("f1").ok, true);   // disposed capture allowed, chain intact
  assert.throws(() => s.quote(capture_id));        // bytes gone
});

test("retest adds a retest binding and event", () => {
  const s = fresh();
  const c1 = s.seal("first proof", { media_type: "tool_io" }).capture_id;
  s.bind("f1", { capture_id: c1, role: "trigger", weight: "probative" });
  const c2 = s.seal("later proof", { media_type: "tool_io" }).capture_id;
  const r = s.retest("f1", { capture_id: c2 });
  assert.ok(r.binding_id);
  assert.equal(s.verifyCustody("f1").ok, true);
  assert.equal(s.getFinding("f1").bindings, 2);
});
