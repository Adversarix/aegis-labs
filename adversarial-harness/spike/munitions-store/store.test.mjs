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

// --- disclosure overlay gates arm/export (disclosure-policy.md §8) ---
const tp = store.create({ artifact: { reproducer_input_hex: "ab", recipe: "r", crash_report: "c" },
  ownership: "third-party", target_match: "stb_image@2.19", disclosure_status: "embargoed" });
const owned = store.create({ artifact: { reproducer_input_hex: "cd", recipe: "r", crash_report: "c" }, ownership: "owned" });
const ARMORER = { role: "armorer", actor: "bob" };
const HUMAN = { role: "custodian", actor: "alice" };

ok("export refused for a third-party find (EXPORT_FORBIDDEN)", threw(() => store.export(tp.id, { authorization: HUMAN }), "EXPORT_FORBIDDEN"));
ok("export requires a human authorization", threw(() => store.export(owned.id, {}), "AUTHZ_REQUIRED"));
ok("export allowed for an owned munition with authz", store.export(owned.id, { authorization: HUMAN }).exported === true);

ok("arm refused against a different target (DISCLOSURE_INBOX_ONLY)",
  threw(() => store.arm(tp.id, { authorization: ARMORER, chamber_run_id: "C-1", target: "other@1.0" }), "DISCLOSURE_INBOX_ONLY"));
ok("arm allowed in-box against the discovered target", store.arm(tp.id, { authorization: ARMORER, chamber_run_id: "C-1", target: "stb_image@2.19" }).armed === true);
store.disarm(tp.id, { chamber_run_id: "C-1" });

store.set_disclosure_status(tp.id, "withdrawn");
ok("arm refused once the case is withdrawn (DISCLOSURE_CLOSED)",
  threw(() => store.arm(tp.id, { authorization: ARMORER, chamber_run_id: "C-2", target: "stb_image@2.19" }), "DISCLOSURE_CLOSED"));
ok("export still refused after withdrawn (weapon never leaves)", threw(() => store.export(tp.id, { authorization: HUMAN }), "EXPORT_FORBIDDEN"));
ok("set_disclosure_status rejects an unknown status", threw(() => store.set_disclosure_status(tp.id, "bogus")));
ok("verify holds across disclosure ops", store.verify(tp.id).ok === true);

// --- list ---
ok("list returns all four munitions", store.list().length === 4);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
