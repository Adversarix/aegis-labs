// Unit tests for the munitions store (custody policy in code). No deps, no docker.
// Run: node store.test.mjs
import { openStore } from "./store.js";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };
const threw = (fn, code) => { try { fn(); return false; } catch (e) { return code ? e.code === code : true; } };

const dir = mkdtempSync(join(tmpdir(), "munstore-"));
const store = openStore(dir, { key: "test-store-key" });

// --- create: inert by default, promoted from discovery ---
const created = store.create({
  artifact: { reproducer_input_hex: "41".repeat(20), recipe: "clang -fsanitize=address vuln.c", crash_report: "stack-buffer-overflow" },
  provenance: { finding_id: "F-1", run_id: "R-1", trajectory_ref: "traj-1" },
});
const id = created.id;
ok("create -> custody_state at_rest", created.custody_state === "at_rest");
ok("create -> inert (armed false)", created.armed === false);
ok("create -> exploitation level crash", created.exploitation.level === "crash");
ok("create -> one ledger event (create)", created.events === 1);

// --- artifact is encrypted at rest (no plaintext in the record file) ---
const raw = readFileSync(join(dir, "munitions", `${id}.json`), "utf8");
ok("artifact encrypted at rest (no plaintext reproducer)", !raw.includes("41414141") && raw.includes("artifact_enc"));

// --- open (ingest for develop): returns decrypted artifact, logs access ---
const opened = store.open(id, { actor: "harness", run_id: "R-2" });
ok("open -> decrypts artifact", opened.artifact.crash_report === "stack-buffer-overflow");
ok("open -> logs access event", opened.events === 2);

// --- update: develop records ladder progress ---
const updated = store.update(id, { level: "exploit", primitives: ["pc-control"], mitigations_defeated: ["none"], reliability: 1.0 },
  { run_id: "R-2" });
ok("update -> level advanced to exploit", updated.exploitation.level === "exploit");
ok("update -> reliability recorded", updated.exploitation.reliability === 1.0);

// --- harness cannot self-authorize dispose ---
ok("dispose without authorization is refused", threw(() => store.dispose(id), "AUTHZ_REQUIRED"));
ok("dispose with a bare object (no role/actor) is refused",
   threw(() => store.dispose(id, { authorization: {} }), "AUTHZ_REQUIRED"));

// --- arming refused at green tier even WITH a human token ---
ok("arm refused (chamber unavailable) even with authz",
   threw(() => store.arm(id, { authorization: { role: "armorer", actor: "alice" } }), "CHAMBER_UNAVAILABLE"));

// --- integrity holds over the lifecycle so far ---
ok("verify ok before disposal", store.verify(id).ok === true);

// --- dispose with a human authorization: crypto-shred + terminal ---
const disposed = store.dispose(id, { authorization: { role: "custodian", actor: "alice" }, reason: "study closed" });
ok("dispose -> custody_state disposed", disposed.custody_state === "disposed");
ok("dispose -> artifact shredded", disposed.shredded === true);
const rawAfter = JSON.parse(readFileSync(join(dir, "munitions", `${id}.json`), "utf8"));
ok("dispose -> ciphertext destroyed (unrecoverable)", rawAfter.artifact_enc === null);
ok("open after dispose throws", threw(() => store.open(id)));
ok("verify ok after disposal (closes with dispose)", store.verify(id).ok === true);

// --- tamper detection: edit a ledger event on disk ---
const m2 = store.create({ artifact: { reproducer_input_hex: "42", recipe: "x", crash_report: "y" } });
const f2 = join(dir, "munitions", `${m2.id}.json`);
const doc = JSON.parse(readFileSync(f2, "utf8"));
doc.ledger[0].reason = "tampered";               // edit an event body, leave hashes
writeFileSync(f2, JSON.stringify(doc, null, 2));
ok("verify detects a tampered ledger event", store.verify(m2.id).ok === false);

// --- list ---
ok("list returns both munitions", store.list().length === 2);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
