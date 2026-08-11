// aegis detonate — the red-tier chamber flow (detonate-stage.md, DESIGN.md §6.1),
// wired as a first-class CLI command. Like `store dispose`, it is HUMAN-GATED: arm
// + detonate cannot be self-authorized by the agent, so this is a CLI command that
// supplies the armorer authorization {role, actor} the store requires — never a
// Goose tool. It runs the orchestrator in-process (not a Goose run) so the six
// chamber invariants are enforced in code on every fire.
import { randomBytes } from "node:crypto";
import { PATHS } from "./config.js";

// Build the substrate the run detonates on. `local` is the non-isolating control
// plane (benign only; refuses real munitions). `firecracker` is the real microVM
// substrate for a Linux/KVM host (drivable locally or over gcloud ssh).
async function buildSubstrate(args) {
  const { LocalHarnessSubstrate, FirecrackerSubstrate } = await import(PATHS.detonateSubstrate);
  const kind = args.substrate || "local";
  if (kind === "local") return { kind, substrate: new LocalHarnessSubstrate() };
  if (kind === "firecracker") {
    return { kind, substrate: new FirecrackerSubstrate({
      mode: args.mode || "local",
      gcpInstance: args["gcp-instance"] || null,
      gcpZone: args["gcp-zone"] || "us-east1-b",
      jailerRoot: args["jailer-root"] || "/srv/detonate/jail",
    }) };
  }
  throw new Error(`unknown --substrate '${kind}' (local | firecracker)`);
}

export async function detonateCommand(cfg, args) {
  if (!args.munition) {
    throw new Error("usage: aegis detonate --munition <id> --role <role> --actor <name> [--substrate local|firecracker] [--real] [--dry-run]");
  }
  // Human authorization, exactly as `store dispose` requires it (the harness cannot
  // self-authorize arming a munition).
  if (!args.role || !args.actor) {
    throw new Error("detonate requires a human authorization: --role and --actor (the armorer)");
  }

  const { substrate, kind } = await buildSubstrate(args);
  const benign = !args.real;
  const chamberRunId = args.run || `cli-${randomBytes(4).toString("hex")}`;
  const armorer = { role: args.role, actor: args.actor };
  const isoNote = substrate.isolates() ? "hardware-isolating" : "control-plane (non-isolating)";

  if (args["dry-run"]) {
    const lines = [
      "detonate plan (not fired):",
      `  substrate:     ${kind} — ${isoNote}` + (kind === "firecracker" ? ` (mode=${substrate.mode})` : ""),
      `  munition:      ${args.munition}`,
      `  payload:       ${benign ? "benign marker-firing stand-in" : "REAL munition"}`,
      `  authorization: ${armorer.role}/${armorer.actor} (armorer)`,
      `  chamber_run:   ${chamberRunId}`,
    ];
    if (!benign && !substrate.isolates()) {
      lines.push("  refusal:       a REAL munition needs an isolating substrate — this run would be refused (NO_ISOLATION)");
    }
    return lines.join("\n");
  }

  // On the real substrate, fail fast with a clear message if the host is not ready
  // (no /dev/kvm, firecracker, or jailer) rather than deep inside provisioning.
  if (kind === "firecracker" && typeof substrate.preflight === "function") {
    try { await substrate.preflight(); }
    catch (e) { throw new Error(`firecracker host not ready: ${e.message}`); }
  }

  const { openStore } = await import(PATHS.storeLib);
  const store = openStore(cfg.store_dir, { key: cfg.store_key });
  const { detonateRun, passesBuildFirst } = await import(PATHS.detonate);

  const report = await detonateRun({
    substrate, store, munitionId: args.munition, armorer,
    markerKey: cfg.marker_key, chamberRunId, benign,
    log: (s) => process.stderr.write(`  .. ${s}\n`),
  });

  const v = report.containment_verdict;
  const gate = passesBuildFirst(report);
  return [
    `detonation ${report.chamber_run_id} complete`,
    `  effect:      marker_fired=${!!report.effect?.marker_fired}  iocs=${report.iocs?.length ?? 0}`,
    `  containment: isolation="${v.isolation}"  no_egress=${v.no_egress}  dry_run_first=${v.dry_run_first}  teardown_verified=${v.teardown_verified}  markers=${v.markers}`,
    `  build-first: capability=${gate.capability}  containment=${gate.containment}`,
    `  marker:      ${report.marker}`,
  ].join("\n");
}
