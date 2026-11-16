// Tests for the mediation seam's evidence tap. Run: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openEvidenceTap } from "./evidence-tap.js";

const tmp = () => mkdtempSync(join(tmpdir(), "evtap-"));

test("disabled tap is a no-op when no store dir is configured", () => {
  const tap = openEvidenceTap({});
  assert.equal(tap.enabled, false);
  assert.equal(tap.seal("run_poc", { exit: 0 }), null);
});

test("seal returns a capture_id and the capture is in the store", () => {
  const tap = openEvidenceTap({ dir: tmp(), key: "k", run_id: "r1" });
  assert.equal(tap.enabled, true);
  const cap = tap.seal("run_poc",
    { argv: ["/work/vuln_poc"], input_hex: "4141", exit: 1, crashed: true, stdout: "SUMMARY: AddressSanitizer: heap-buffer-overflow", stderr: "" },
    "marker-hmac-abc");
  assert.ok(cap && cap.length === 64);          // sha256 hex
  assert.equal(tap.store.captureExists(cap), true);
});

test("a sealed tool_io capture can be bound and verifies, and the output is recoverable", () => {
  const dir = tmp();
  const tap = openEvidenceTap({ dir, key: "k", run_id: "r1" });
  const cap = tap.seal("fuzz",
    { argv: ["/usr/bin/fuzz"], exit: 1, crashed: true, reproducer_input_hex: "deadbeef", stdout: "crash flag{proven}", stderr: "" },
    "mk");
  // The confirm path binds the seam's capture as proof of a finding.
  tap.store.bind("finding-1", { capture_id: cap, role: "trigger", weight: "probative", claim: "fuzz crash" });
  assert.equal(tap.store.hasProbativeBinding("finding-1"), true);
  assert.equal(tap.store.verifyCustody("finding-1").ok, true);
  // The sealed bytes carry the observed output verbatim.
  const bytes = tap.store.quote(cap).toString("utf8");
  assert.match(bytes, /flag\{proven\}/);
  assert.match(bytes, /"tool":"fuzz"/);
  assert.match(bytes, /"run_id":"r1"/);
});

test("different tool output content-addresses to different captures", () => {
  const tap = openEvidenceTap({ dir: tmp(), key: "k", run_id: "r1" });
  const a = tap.seal("run_shell", { argv: "id", exit: 0, stdout: "uid=0", stderr: "" }, "m");
  const b = tap.seal("run_shell", { argv: "id", exit: 1, stdout: "permission denied", stderr: "" }, "m");
  assert.notEqual(a, b);
  // NB: byte-identical observations (same tool/argv/output within the same ms)
  // content-address to the SAME capture_id by design (dedup, spec §3.1). The
  // mediation log, not the capture, is the per-execution event record.
});
