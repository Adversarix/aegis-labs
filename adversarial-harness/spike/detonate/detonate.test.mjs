// Detonate stage tests — the build-first slice (detonate-stage.md §9) on the
// control-plane substrate. Proves the loop, the invariants, custody arming, and
// the load-bearing property: teardown guaranteed under a mid-detonation kill.
// Run: node detonate.test.mjs
import { openStore } from "../munitions-store/store.js";
import { LocalHarnessSubstrate, FirecrackerSubstrate } from "./substrate.mjs";
import { detonateRun, passesBuildFirst } from "./detonate.mjs";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log(`  ok  ${n}`)) : (fail++, console.error(`FAIL  ${n}`)); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const armorer = { role: "armorer", actor: "alice" };

// --- full benign detonation on the control-plane substrate ---
const dir = mkdtempSync(join(tmpdir(), "detonate-store-"));
const store = openStore(dir, { key: "detonate-test-key" });
const m = store.create({ artifact: { reproducer_input_hex: "41".repeat(20), recipe: "r", crash_report: "overflow" } });

const report = await detonateRun({
  substrate: new LocalHarnessSubstrate(), store, munitionId: m.id, armorer,
  markerKey: "runkey", chamberRunId: "run-1", benign: true,
});
ok("effect: objective marker fired", report.effect?.marker_fired === true);
ok("IOCs emitted for the sensor", Array.isArray(report.iocs) && report.iocs.length > 0);
ok("marker present on the detonation", typeof report.marker === "string" && report.marker.length === 64);
const v = report.containment_verdict;
ok("invariant: dry-run-first held", v.dry_run_first === true);
ok("invariant: no real egress", v.no_egress === true);
ok("invariant: teardown verified (guest destroyed)", v.teardown_verified === true);
ok("substrate correctly reports non-isolating (control-plane)", v.isolation === "control-plane (non-isolating)");

const gate = passesBuildFirst(report);
ok("build-first: capability gate (effect observed)", gate.capability === true);
ok("build-first: containment gate (invariants held)", gate.containment === true);

// --- custody ledger: arm -> detonate -> disarm, back to inert ---
const after = store.list().find((x) => x.id === m.id);
ok("munition returned to inert (at_rest, armed=false)", after.custody_state === "at_rest" && after.armed === false);
const ledger = JSON.parse(readFileSync(join(dir, "munitions", `${m.id}.json`), "utf8")).ledger.map((e) => e.action);
ok("ledger records create,access?,arm,detonate,disarm", ["arm", "detonate", "disarm"].every((a) => ledger.includes(a)));
ok("store integrity verifies after the run", store.verify(m.id).ok === true);

// --- isolation invariant: a REAL munition is refused on a non-isolating substrate ---
let refused = false;
try {
  await detonateRun({ substrate: new LocalHarnessSubstrate(), store, munitionId: m.id, armorer,
    markerKey: "k", chamberRunId: "run-real", benign: false });
} catch (e) { refused = e.code === "NO_ISOLATION"; }
ok("real munition refused on non-isolating substrate", refused);

// --- FirecrackerSubstrate declares hardware isolation (would accept real munitions) ---
ok("FirecrackerSubstrate.isolates() is true", new FirecrackerSubstrate().isolates() === true);

// --- THE BUILD-FIRST EARLY-EXIT GATE: teardown guaranteed under a mid-detonation kill ---
const killDir = mkdtempSync(join(tmpdir(), "detonate-kill-"));
const guestFile = join(killDir, "guest.path");
const child = spawn("node", [join(HERE, "kill-runner.mjs")],
  { env: { ...process.env, STORE_DIR: killDir, GUESTFILE: guestFile }, stdio: "ignore" });
// wait until the runner has provisioned the guest and is stalling in live-fire
for (let i = 0; i < 100 && !existsSync(guestFile); i++) await sleep(50);
const guestDir = existsSync(guestFile) ? readFileSync(guestFile, "utf8").trim() : "";
ok("guest was provisioned (exists mid-detonation)", guestDir && existsSync(guestDir));
child.kill("SIGTERM");                 // kill mid-detonation
await new Promise((r) => child.once("exit", r));
await sleep(100);
ok("guest DESTROYED after mid-detonation kill (teardown guaranteed)", guestDir && !existsSync(guestDir));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
