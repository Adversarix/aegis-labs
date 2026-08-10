// Detonation substrate abstraction (detonate-stage.md §5-6, detonate-substrate-requirements.md).
//
// The orchestrator is substrate-agnostic; a Substrate provides the guest lifecycle
// and the containment primitives. Two implementations:
//
//   LocalHarnessSubstrate  — a CONTROL-PLANE test substrate for a machine without
//     KVM. It exercises the full detonation loop, custody arming, the T0 sinkhole,
//     marker injection, and — critically — guaranteed teardown (including under a
//     mid-detonation kill). It does NOT provide hardware isolation, so it
//     `isolates() === false`, and the orchestrator refuses REAL munitions on it
//     (only benign, marker-firing detonations). It proves the LOGIC, not the
//     blast-radius guarantee.
//
//   FirecrackerSubstrate   — the real substrate for a Linux/KVM host (e.g. the GCP
//     instance). One disposable microVM per detonation under the jailer, air-gapped
//     guest wired only to the sinkhole, snapshot + guaranteed teardown. `isolates()
//     === true`. Code-complete; runs only where /dev/kvm and firecracker exist.
import { mkdtempSync, rmSync, existsSync, writeFileSync, readFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

export class Substrate {
  isolates() { return false; }
  async provision(runId) { throw new Error("not implemented"); }
  async detonate(guest, opts) { throw new Error("not implemented"); }
  async assertNoEgress(guest) { throw new Error("not implemented"); }
  async teardown(guest) { throw new Error("not implemented"); }
  // Independent post-teardown check: prove the guest is actually gone. The
  // orchestrator asks the SUBSTRATE (not a local heuristic) so the containment
  // verdict reflects real host state on every substrate.
  async verifyTornDown(guest) { throw new Error("not implemented"); }
}

// ---------------------------------------------------------------------------
// LocalHarnessSubstrate — control-plane test substrate (no hardware isolation).
// ---------------------------------------------------------------------------
export class LocalHarnessSubstrate extends Substrate {
  constructor() { super(); this.name = "local-harness"; }
  isolates() { return false; }

  async provision(runId) {
    const dir = mkdtempSync(join(tmpdir(), `detonate-guest-${runId}-`));
    // The "deception network" for T0: a local recorder. Any egress the payload
    // attempts is written here; there is no real outbound path in this harness.
    const sinkhole = join(dir, "sinkhole.log");
    const telemetry = join(dir, "telemetry.log");
    writeFileSync(sinkhole, ""); writeFileSync(telemetry, "");
    return { runId, dir, sinkhole, telemetry, isolated: false };
  }

  // Benign detonation: fire the objective marker (effect), emit an IOC the sensor
  // captures, and "call home" to the T0 sinkhole (recorded, never real egress).
  // `dryRun` plans without executing. A real weapon is refused upstream (isolate()).
  async detonate(guest, { marker, dryRun = false, benign = true } = {}) {
    if (!benign) throw new Error("LocalHarnessSubstrate refuses real munitions (no hardware isolation)");
    const plan = { steps: ["fire objective marker", "emit IOC to sensor", "beacon to T0 sinkhole"] };
    if (dryRun) return { dryRun: true, plan, effect: null, iocs: [] };
    // effect: the objective marker fires, carrying the run's signed marker
    writeFileSync(join(guest.dir, "objective_marker"), marker || "objective-fired");
    // sensor captures a marker-tagged IOC
    const ioc = { type: "beacon", host: "c2.example.invalid", marker };
    appendFileSync(guest.telemetry, JSON.stringify({ ts_marker: marker, event: "process_exec", detail: "payload" }) + "\n");
    appendFileSync(guest.telemetry, JSON.stringify({ ts_marker: marker, event: "net_attempt", detail: ioc.host }) + "\n");
    // "egress": recorded by the deception sinkhole, never leaves the box
    appendFileSync(guest.sinkhole, JSON.stringify({ marker, dst: ioc.host, served: "T0-sinkhole" }) + "\n");
    return { dryRun: false, plan, effect: { marker_fired: true }, iocs: [ioc] };
  }

  // Control-plane egress check: the only recorded egress went to the T0 sinkhole.
  // NOTE: this is a logical check, not a hardware air-gap guarantee — that requires
  // the microVM substrate. Stated honestly so the verdict is not overclaimed.
  async assertNoEgress(guest) {
    const lines = existsSync(guest.sinkhole) ? readFileSync(guest.sinkhole, "utf8").trim().split("\n").filter(Boolean) : [];
    const offbox = lines.map((l) => JSON.parse(l)).filter((e) => e.served !== "T0-sinkhole");
    return { ok: offbox.length === 0, real_egress: offbox.length, note: "control-plane check; hardware air-gap needs the microVM substrate" };
  }

  // Guaranteed teardown: destroy the guest dir. Idempotent (safe under repeated /
  // mid-detonation kill invocation).
  async teardown(guest) {
    if (guest?.dir && existsSync(guest.dir)) rmSync(guest.dir, { recursive: true, force: true });
    return { torn_down: true, exists: guest?.dir ? existsSync(guest.dir) : false };
  }

  // Verified by the guest dir being gone (idempotent; true if never provisioned).
  async verifyTornDown(guest) { return !guest?.dir || !existsSync(guest.dir); }
}

// ---------------------------------------------------------------------------
// FirecrackerSubstrate — real microVM substrate for a Linux/KVM host.
// ---------------------------------------------------------------------------
// Shells out to the host (locally if this IS the KVM host, or over `gcloud compute
// ssh` to the provisioned GCP instance). Code-complete; every method fails clearly
// where /dev/kvm or firecracker is absent, so it never silently degrades to a
// non-isolating run.
export class FirecrackerSubstrate extends Substrate {
  constructor({ mode = "local", gcpInstance = null, gcpZone = "us-east1-b", jailerRoot = "/srv/detonate/jail" } = {}) {
    super();
    this.name = "firecracker";
    this.mode = mode;              // "local" (this host has /dev/kvm) | "gcp-ssh"
    this.gcpInstance = gcpInstance;
    this.gcpZone = gcpZone;
    this.jailerRoot = jailerRoot;
  }
  isolates() { return true; }

  // Run a command on the KVM host (locally or via gcloud ssh). Requires auth+host.
  _host(cmd) {
    if (this.mode === "gcp-ssh") {
      if (!this.gcpInstance) throw new Error("FirecrackerSubstrate(gcp-ssh) needs gcpInstance");
      return execFileSync("gcloud", ["compute", "ssh", this.gcpInstance, "--zone", this.gcpZone,
        "--tunnel-through-iap", "--command", cmd], { encoding: "utf8", timeout: 120000 });
    }
    return execFileSync("bash", ["-lc", cmd], { encoding: "utf8", timeout: 120000 });
  }

  async preflight() {
    // Must have /dev/kvm and firecracker on the host, else refuse (no silent degrade).
    const out = this._host("test -e /dev/kvm && command -v firecracker && command -v jailer && echo READY");
    if (!/READY/.test(out)) throw new Error("Firecracker host not ready: need /dev/kvm + firecracker + jailer");
    return { ready: true };
  }

  async provision(runId) {
    // Boot one disposable microVM under the jailer from a known-clean snapshot,
    // with a tap wired ONLY to the in-boundary sinkhole (no default route).
    // (Host-side script `chamber-provision.sh` is deployed with the substrate.)
    const out = this._host(`sudo /srv/detonate/chamber-provision.sh ${runId} ${this.jailerRoot}`);
    const guest = JSON.parse(out.trim());  // { runId, vmid, socket, tap, sinkhole }
    return { ...guest, isolated: true };
  }
  async detonate(guest, { marker, dryRun = false } = {}) {
    const flag = dryRun ? "--dry-run" : "--live";
    const out = this._host(`sudo /srv/detonate/chamber-detonate.sh ${guest.vmid} ${flag} --marker ${marker}`);
    return JSON.parse(out.trim());  // { dryRun, effect, iocs }
  }
  async assertNoEgress(guest) {
    // Real check: assert zero packets left the guest subnet for anything but the sinkhole.
    const out = this._host(`sudo /srv/detonate/chamber-assert-no-egress.sh ${guest.vmid}`);
    return JSON.parse(out.trim());  // { ok, real_egress }
  }
  async teardown(guest) {
    const out = this._host(`sudo /srv/detonate/chamber-teardown.sh ${guest.vmid} ${this.jailerRoot} || true`);
    return JSON.parse(out.trim() || '{"torn_down":true}');
  }
  async verifyTornDown(guest) {
    if (!guest?.vmid) return true;   // never provisioned -> nothing to tear down
    // Independent host check: microVM process, jail dir, tap, and egress chain all gone.
    const out = this._host(`sudo /srv/detonate/chamber-verify-teardown.sh ${guest.vmid} ${this.jailerRoot}`);
    return JSON.parse(out.trim()).torn_down === true;
  }
}
