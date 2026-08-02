# Detonate Stage — Substrate Requirements

**Status:** Requirements (nothing built) · **Date:** 2026-08-02
Parent: [`DESIGN.md`](./DESIGN.md) §6.1 · Stage spec: [`detonate-stage.md`](./detonate-stage.md) ·
Custody: [`munitions-custody-policy.md`](./munitions-custody-policy.md)

What infrastructure the red-tier **detonate** stage needs before it can be built. The stage spec
(`detonate-stage.md`) says what the chamber does; this doc says what host, virtualization, network,
sensor, and custody substrate has to exist under it. Everything here is **designed, not built** —
detonate is the last stage on purpose (`detonate-stage.md` §9), and it cannot run on the current
Apple Silicon workstation (see §2).

## 1. The forced decision: microVM/VM, not containers

`DESIGN.md` §6.1 settles this and it is non-negotiable for any run that can reach the red tier. A
detonation runs real, potentially self-propagating or destructive code. Containers (Docker) share
the host kernel, so a payload carrying a kernel exploit or container escape means a shared kernel is
a shared blast radius. The minimum is **hardware-virtualized isolation: one disposable microVM or
full VM per detonation, no shared kernel with the host or with other runs.**

Everything the green tier built (discovery + develop) legitimately runs in `--network none` Docker
because those targets are benign and not trying to escape. Detonation is exactly the tier where that
stops being adequate.

| Substrate | Isolation boundary | Verdict for detonation |
|---|---|---|
| Docker (namespaces/cgroups) | shared host kernel | **No** — shared kernel = shared blast radius |
| gVisor | user-space kernel intercepting syscalls | No — stronger than Docker, but not the hardware-virtualization bar |
| **Firecracker microVM** | hardware virtualization, separate guest kernel | **Yes** — the reference substrate |
| **Kata Containers** | OCI workflow wrapping a Firecracker/QEMU microVM | Yes — the pragmatic bridge (Docker-like UX, real VM boundary) |
| Full VM (QEMU/KVM) | hardware virtualization | Yes — heavier/slower per shot; fine as a first cut |

## 2. Host requirements

- **Linux with KVM.** Firecracker and Kata need `/dev/kvm` (a Linux host with hardware
  virtualization). This is the hard gate.
- **Architecture must match the munition.** Our green-tier targets are **aarch64**, so aarch64
  munitions detonate on an **arm64 KVM host** (e.g. a Graviton/Ampere Linux box). Real ExploitGym
  and most real-world x86 munitions need an **x86_64 KVM host**. A production lab likely wants both;
  start with whichever matches the munitions you will actually detonate.
- **Not this workstation.** Apple Silicon macOS cannot run Firecracker natively, and nested KVM
  under Apple's hypervisor is not viable. Docker Desktop here already runs inside its own Linux VM;
  you cannot nest a detonation microVM under it reliably. Detonate must live on a dedicated
  Linux/KVM host (bare-metal, or a cloud instance that exposes nested virtualization / is itself
  bare-metal).
- **Defense in depth.** Run Firecracker under its **jailer** (cgroups, namespaces, chroot,
  seccomp) so a VMM escape still lands in a locked-down sandbox, not on the host.
- **Disposable host posture.** The host is part of the blast-radius calculation. Prefer an
  ephemeral, reimageable host with no standing credentials and no route to production networks.

## 3. Guest lifecycle (the load-bearing invariants)

From `detonate-stage.md` §5-6. Each must be enforced in code, not by operator discipline:

- **One disposable guest per detonation.** Boot from a known-clean snapshot; never reuse a guest.
- **Snapshot + guaranteed teardown.** The guest is destroyed on completion, failure, OR kill.
  Persistence cannot survive teardown. This is the invariant the whole stage rests on: the
  build-first early-exit signal (§6) is *if teardown is not provably guaranteed under a
  mid-detonation kill, stop and fix containment before anything else.*
- **Dry-run-first.** A detonation is planned and gate-checked in dry-run; live-fire is an explicit,
  scoped promotion from a passing dry-run, never an agent's first action.
- Substrate implication: the microVM must have fast snapshot/restore and a teardown path that a
  run-level kill can invoke synchronously and verify (guest process gone, disk/overlay discarded).

## 4. Network containment + the deception network

- **Default air-gap.** A detonation guest has no real NIC. Real outbound traffic is an error the
  code raises (`detonate-stage.md` §6 invariant 2).
- **Deception network for contained egress.** Where a payload must "phone home" to exhibit
  behavior, egress is served **inside the isolation boundary** by a fake network, never real egress.
  Fidelity is tiered (`detonate-stage.md` §5), pick the minimum that makes the payload observable:
  - **T0 sinkhole** — fake DNS + catch-all TCP/HTTP responder.
  - **T1 simulated services** — INetSim/FakeNet-style DNS/HTTP/SMTP/C2 that answer plausibly.
  - **T2 simulated internet** — richer fake topology for multi-stage payloads.
- Substrate implication: a guest `tap`/`veth` wired only to an in-boundary sinkhole VM/process, with
  the host firewall asserting **zero** real egress from the guest subnet. The build-first slice needs
  only T0.

## 5. Sensor stack

The chamber is measurement, not just firing (`detonate-stage.md` §5, §8), so the twin is
instrumented:

- **Host telemetry** — process/file/registry/syscall auditing inside the guest (auditd / Sysmon-
  equivalent / an EDR agent under test).
- **Network capture** — full pcap inside the isolation boundary.
- **Detection rules under test** — the SIEM/EDR ruleset whose coverage is the point of the
  detection-gap signal. Sourcing is an open item (`detonate-stage.md` §10).
- Substrate implication: a telemetry sink outside the disposable guest (so it survives teardown),
  plus the marker-injection path below so its records are attributable.

## 6. Signed markers

Every synthetic action and every emitted artifact/IOC carries the run's HMAC-signed marker
(`detonate-stage.md` §5 marker injection). Injection points: the payload's actions, the twin's
telemetry, and the recorded IOCs, so chamber telemetry can never be confused with a real incident
and a real intruder cannot impersonate the sim. We already have the marker mechanism (`marker.js`,
injected as `$AEGIS_MARKER` today); detonate extends the injection points into the guest + sensors.

## 7. Munitions arming path (custody-governed)

Arming happens only inside the chamber, only for an authorized run (`munitions-custody-policy.md`
§6-7). The substrate must support:

- **Armorer authorization** — a human token per `arm`, bound to this single scoped run; the harness
  never self-authorizes a detonation. (Our store already refuses `arm` at green tier with
  `CHAMBER_UNAVAILABLE`; the chamber is what makes arming meaningful.)
- **Inert-to-armed only in-chamber** — the munition is decrypted/armed only inside the guest for the
  run, auto-disarmed on run end, and the ledger records `arm` -> `detonate` -> `disarm`.
- **Kill switch** — halts arm/detonate, forces disarm + teardown, store defaults closed.
- Substrate implication (custody §10 residual): a **key-custody model** where the at-rest decryption
  key is armorer-held, so the harness alone cannot decrypt a munition to an armed form outside an
  authorized chamber run.

## 8. What we already have vs. what detonate adds

| Piece | Status |
|---|---|
| L4/L5 munition to detonate (develop stage output) | **built** (green) |
| Signed-marker mechanism | **built** (extend injection points) |
| Mediation gate deciding *whether* a detonation is authorized | **built** (the gate; red-tier classes denied by default) |
| Custody store modeling arm/detonate/disarm states, refusing arm at green tier | **built** |
| microVM/VM substrate + jailer | to build |
| Snapshot + guaranteed-teardown-under-kill | to build (the early-exit gate) |
| Deception network (T0 first) | to build |
| Sensor stack + detection-rule intake | to build |
| Armorer key-custody / arming path | to build |

The gate governs *whether* a detonation is authorized; the chamber governs *where* it happens and
guarantees it cannot leak. They are separate on purpose: the gate can be defeated by a bug, the
chamber must hold even then (`DESIGN.md` §6.1).

## 9. Phased build path (grounded in the §9 build-first slice)

1. **Stand up the host.** A dedicated Linux/KVM instance matching the munition arch (arm64 for our
   current targets). Firecracker + jailer, no route to production.
2. **Minimal chamber.** One microVM booting a clean snapshot of the deliberately-vulnerable target;
   one host-telemetry sensor; a T0 sinkhole. Input: the develop stage's L4 ret2win munition.
3. **Prove teardown-under-kill first.** Before any real detonation work, verify the guest is
   destroyed even when the run is killed mid-detonation. If not provable, stop and fix containment —
   this is the whole stage's foundation.
4. **First detonation.** Fire the L4 munition; assert both signals hold: the objective marker fires
   AND marker-aware telemetry captures it (effect observed), and every §6 invariant verifiably holds
   (isolation, zero real egress, dry-run-preceded live-fire, guaranteed teardown).
5. **First detection-gap data point.** Add a detection rule and re-run: did it fire on the emitted
   IOCs?
6. **Then scale** fidelity (T1/T2), twin richness, and the amber/third-party path (with the §7
   pre-disclosure detonation gate).

## 10. Open items the substrate choice interacts with

From `detonate-stage.md` §10 and `DESIGN.md` §9:

- **Uniform vs. tiered substrate** — run everything on microVMs for uniformity, or keep green/amber
  on containers and reserve microVMs for red? (Trades teardown-guarantee strength against setup cost.)
- **Deception-network default tier** and per-run override policy.
- **Sensor composition** — synthetic telemetry vs. a real EDR agent under test; standard host-audit
  sources.
- **Detection-rule sourcing** — whose ruleset is under test, supplied how per run.
- **Twin richness** — single-host vs. multi-host twins for blast-radius / lateral-movement
  measurement (ties to `agentic-identity-pivots`).
- **Key-custody model** — where the armorer-held arming key lives; whether arming needs a separate
  key ceremony.

## 11. One-line summary

Detonate needs a **dedicated Linux/KVM host (arch-matched to the munitions), Firecracker microVMs
under the jailer with snapshot + guaranteed teardown, an air-gapped guest wired only to an
in-boundary deception sinkhole, an out-of-guest sensor sink, and an armorer-held key-custody arming
path** — none of which exists on the current Apple Silicon workstation, so it is the one part of the
system that requires new infrastructure rather than more code on this machine.
