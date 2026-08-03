# Detonate stage (red tier)

The red-tier detonation chamber (`../../detonate-stage.md`, `../../DESIGN.md` §6.1,
`../../detonate-substrate-requirements.md`). Arms a finished munition, fires it against a
disposable guest, captures effect + IOCs, and guarantees teardown — all under the six chamber
invariants enforced in code.

**Two parts, split on purpose:** the orchestrator + invariants are **substrate-agnostic** and
tested here; the hardware-isolation guarantee lives in the **substrate**. A real detonation runs
only on an isolating substrate (Firecracker microVM). A machine without KVM can still exercise and
verify the whole control plane on a non-isolating test substrate — it just cannot run a real weapon.

## Components

| File | Role |
|---|---|
| `detonate.mjs` | orchestrator: the loop + the six invariants + custody arm/detonate/disarm + the report |
| `substrate.mjs` | `LocalHarnessSubstrate` (control-plane, non-isolating) and `FirecrackerSubstrate` (real, Linux/KVM) |
| `firecracker-host/` | host-side scripts the FirecrackerSubstrate drives: `setup-host.sh`, `chamber-{provision,detonate,assert-no-egress,teardown}.sh`, `sinkhole.py` (T0) |
| `detonate.test.mjs` | build-first slice tests, incl. teardown-under-kill |

## The six invariants (all enforced in `detonate.mjs`)

1. **Isolation** — a real munition runs only where `substrate.isolates()`; refused (`NO_ISOLATION`)
   on a non-isolating substrate. Benign, marker-firing detonations are allowed on the control plane.
2. **Network containment** — `assertNoEgress` after firing; real outbound is a failure. The
   deception net (T0 sinkhole) serves any beacon inside the boundary.
3. **Guaranteed teardown** — on completion, failure, OR kill (a `finally` block plus SIGTERM/SIGINT
   handlers). Idempotent. This is the load-bearing property.
4. **Dry-run-first** — live-fire only after a passing dry-run.
5. **Signed markers** — a per-run marker injected into the detonation + telemetry (attributable).
6. **Kill switch** — a kill forces disarm + teardown; the store defaults closed.

Custody: `arm` is armorer-authorized and bound to the chamber run (the harness cannot
self-authorize); the ledger records `arm -> detonate -> disarm` and the munition returns to inert
(`munitions-custody-policy.md` §6-7).

## Run the tests (any machine)

```bash
node detonate.test.mjs   # 16 tests on the control-plane substrate, incl. teardown-under-kill
```

## Run for real (Linux/KVM host, e.g. the GCP instance)

1. On the host: `firecracker-host/setup-host.sh` (installs firecracker+jailer, lays out the jail
   root, T0 sinkhole, air-gap net; place a guest kernel + a clean rootfs snapshot).
2. Drive it from the orchestrator with `FirecrackerSubstrate({ mode: "gcp-ssh", gcpInstance, gcpZone })`
   (or `mode: "local"` if running on the host). `isolates() === true`, so real munitions are accepted.

The host scripts are code-complete skeletons (real firecracker/jailer/iptables command shapes) and
have not run on a live host yet — that is the next step, gated on the KVM host being reachable.

## Build-first status

The build-first slice's dual gate (`detonate-stage.md` §9) is met on the control-plane substrate:
effect observed (marker fired + IOCs) AND every invariant held — including the early-exit gate,
**teardown provably guaranteed under a mid-detonation kill**. See
[`FINDINGS-detonate-build-first.md`](./FINDINGS-detonate-build-first.md).
