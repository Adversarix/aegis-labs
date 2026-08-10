// Detonation orchestrator (detonate-stage.md §4, §6). Substrate-agnostic. Enforces
// the six chamber invariants in code and drives the custody arm -> detonate ->
// disarm path. Produces a detonation report: effect + IOCs + a containment-integrity
// verdict.
//
// Invariants (detonate-stage.md §6), all enforced here:
//   1. isolation      — a REAL munition runs only on an isolating substrate.
//   2. net containment— assertNoEgress after firing; real outbound is a failure.
//   3. teardown       — guaranteed on completion, failure, OR kill (finally + signals).
//   4. dry-run-first  — live-fire only after a passing dry-run.
//   5. signed markers — a per-run marker injected into the detonation + telemetry.
//   6. kill switch    — a kill forces disarm + teardown; store defaults closed.
import { signMarker } from "../mediation-seam/marker.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function detonateRun({
  substrate, store, munitionId, armorer, markerKey, chamberRunId,
  benign = true, stallMs = 0, log = () => {}, onGuest = () => {},
} = {}) {
  const marker = signMarker(markerKey || "detonate-key", { chamber_run_id: chamberRunId, munition: munitionId }).hmac;
  const verdict = { isolation: null, no_egress: null, dry_run_first: false, teardown_verified: false, markers: !!marker, kill_switch: "not-triggered" };
  let guest = null, armed = false, torn = false;

  // Invariant 3 + 6: guaranteed teardown + disarm even on an external kill.
  const emergency = () => {
    try { if (guest && !torn) { substrate.teardown(guest); torn = true; } } catch {}
    try { if (armed) { store.disarm(munitionId, { chamber_run_id: chamberRunId, reason: "kill switch" }); } } catch {}
  };
  const onSignal = (sig) => { verdict.kill_switch = sig; emergency(); process.exit(sig === "SIGINT" ? 130 : 143); };
  process.once("SIGTERM", () => onSignal("SIGTERM"));
  process.once("SIGINT", () => onSignal("SIGINT"));

  try {
    // Invariant 1: real munitions require hardware isolation.
    verdict.isolation = substrate.isolates() ? "hardware-virtualized" : "control-plane (non-isolating)";
    if (!benign && !substrate.isolates()) {
      throw Object.assign(new Error("refused: a real munition requires an isolating substrate (microVM/VM)"), { code: "NO_ISOLATION" });
    }

    log("provision"); guest = await substrate.provision(chamberRunId); onGuest(guest);

    // Custody: armorer-authorized arm, bound to this chamber run (the harness cannot self-authorize).
    log("arm"); store.arm(munitionId, { authorization: armorer, chamber_run_id: chamberRunId }); armed = true;

    // Invariant 4: dry-run first.
    log("dry-run"); const dry = await substrate.detonate(guest, { marker, dryRun: true, benign });
    verdict.dry_run_first = dry.dryRun === true;
    if (!verdict.dry_run_first) throw new Error("dry-run did not run; refusing live-fire");

    if (stallMs) await sleep(stallMs);   // the live-fire window (kill target in tests)

    // Live-fire (only after the dry-run) + custody detonate event + markers.
    log("detonate"); const shot = await substrate.detonate(guest, { marker, dryRun: false, benign });
    store.detonate(munitionId, { chamber_run_id: chamberRunId, marker });

    // Invariant 2: network containment.
    log("assert-no-egress"); const egress = await substrate.assertNoEgress(guest);
    verdict.no_egress = egress.ok; verdict.no_egress_note = egress.note;

    // Observe + report.
    const report = {
      chamber_run_id: chamberRunId, munition: munitionId, marker,
      effect: shot.effect, iocs: shot.iocs, telemetry_ref: guest.telemetry ?? null,
      containment_verdict: verdict,
    };
    return report;
  } finally {
    // Invariant 3: teardown always; custody disarm -> back to inert.
    try { if (guest && !torn) { await substrate.teardown(guest); torn = true; } } catch {}
    // Invariant 3, verified: ask the SUBSTRATE to confirm the guest is gone, so this
    // holds on the real microVM substrate (a Firecracker guest has no `.dir`), not just
    // the control-plane one. False on any substrate whose teardown did not take.
    try { verdict.teardown_verified = guest ? await substrate.verifyTornDown(guest) : true; }
    catch { verdict.teardown_verified = false; }
    try { if (armed) store.disarm(munitionId, { chamber_run_id: chamberRunId, reason: "run ended" }); } catch {}
    process.removeAllListeners("SIGTERM"); process.removeAllListeners("SIGINT");
  }
}

// Whether a detonation report passes the build-first slice's dual gate
// (detonate-stage.md §9): effect observed AND every invariant held.
export function passesBuildFirst(report) {
  const v = report.containment_verdict;
  return {
    capability: !!report.effect?.marker_fired && (report.iocs?.length > 0),
    containment: v.no_egress === true && v.dry_run_first === true && v.teardown_verified === true && v.markers === true,
  };
}
