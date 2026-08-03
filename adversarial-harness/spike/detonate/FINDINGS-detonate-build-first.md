# Detonate Stage — Build-First Findings

**Status:** control plane complete + verified; real substrate pending a live KVM host · **Date:** 2026-08-03
Spec: [`../../detonate-stage.md`](./../../detonate-stage.md) §9 · [`../../detonate-substrate-requirements.md`](./../../detonate-substrate-requirements.md)

The red-tier detonation chamber's **control plane** is built and verified. A real detonation of a
real munition needs the Firecracker/KVM substrate (a live Linux host); everything that is
substrate-independent — the loop, the six invariants, custody arming, the deception sinkhole, marker
injection, and the load-bearing teardown guarantee — is implemented and tested on a control-plane
substrate.

## What the build-first slice requires (and what we met)

`detonate-stage.md` §9 sets a dual gate and an early-exit signal:

- **Capability/effect:** the detonation fires the objective marker AND marker-aware telemetry
  captures it. → met (benign detonation on the control-plane substrate: marker fired, IOCs emitted
  to the sensor).
- **Containment:** every §6 invariant verifiably holds. → met (dry-run-first, no real egress,
  guaranteed teardown, signed markers, isolation-refusal for real munitions).
- **Early-exit gate:** *if teardown is not provably guaranteed under a mid-detonation kill, stop and
  fix containment before anything else.* → **proven**: a detonation stalled in its live-fire window,
  the orchestrator process killed with SIGTERM, and the guest was **destroyed** by the signal-handler
  teardown. This is the invariant the whole stage rests on, and it holds.

## Tests (16, all pass)

Run: `node detonate.test.mjs`. Highlights:

- Full benign detonation: effect (marker fired), IOCs for the sensor, a signed run marker.
- Invariants: dry-run-first held; no real egress; teardown verified (guest gone).
- Build-first dual gate passes (capability + containment).
- Custody ledger: `arm -> detonate -> disarm`, munition back to `at_rest`/inert, store integrity
  verifies. Arm was armorer-authorized and chamber-bound (the harness cannot self-authorize).
- Isolation invariant: a REAL munition is **refused** (`NO_ISOLATION`) on the non-isolating
  substrate; `FirecrackerSubstrate.isolates()` is true (it would accept one).
- **Teardown guaranteed under a mid-detonation kill** (the early-exit gate).

## Honest scope of the control-plane substrate

`LocalHarnessSubstrate` proves the orchestration and invariant-enforcement LOGIC; it does **not**
provide hardware isolation, and it says so (`isolates() === false`, and `assertNoEgress` returns a
"control-plane check, not a hardware air-gap" note). That is why the orchestrator refuses real
munitions on it. The blast-radius guarantee — a real payload with a kernel exploit cannot escape —
is a property of the microVM substrate, not of this harness. The control plane is correct; the
containment guarantee is only as strong as the substrate under it.

## The real substrate (ready to deploy)

`FirecrackerSubstrate` + `firecracker-host/` are code-complete: one disposable microVM per
detonation under the jailer, a disposable overlay off a read-only clean snapshot, a tap wired only to
the T0 sinkhole with a host iptables DROP+count air-gap (so `assert-no-egress` is a real zero-egress
proof), and idempotent teardown. These have not run on a live host yet.

## Next step (gated on infrastructure)

Point `FirecrackerSubstrate({ mode: "gcp-ssh", gcpInstance, gcpZone })` at the provisioned GCP KVM
host, run `setup-host.sh` there (place a guest kernel + a clean rootfs snapshot with the vulnerable
service + sensor), and re-run the build-first slice **on the real substrate** — first proving
teardown-under-kill on a live microVM, then the first real detonation + the first detection-gap data
point (add a detection rule, re-run, did it fire on the emitted IOCs).

Blocked only on reaching that host (gcloud re-auth); the code is ready.
