# Detonate Stage — Build-First Findings

**Status:** control plane verified; the FULL build-first slice (effect + containment + detection-gap) ran live on a REAL Firecracker microVM · **Date:** 2026-08-03
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

## Verified on a REAL Firecracker microVM (2026-08-03)

The load-bearing gate now holds on actual hardware virtualization, not just the control-plane
substrate. On the provisioned GCP host `crucible-fc-host` (n2-standard-4, x86_64, Ubuntu 22.04,
kernel 6.8-gcp, `/dev/kvm` present with nested virt, firecracker v1.16.1, staged guest kernel +
6GB rootfs):

- Booted one disposable microVM from a **disposable overlay off a read-only base** (the base image
  is never mutated). Confirmed a live guest: **4 vCPU threads**, ~80 MB, real KVM-backed.
- **Air-gapped**: zero guest NICs on the host — no egress path by construction.
- **Teardown-under-kill**: killed the microVM mid-run (SIGKILL, the mid-detonation kill) → the guest
  was **destroyed** (process gone) and the disposable overlay discarded, so **no guest state
  survives teardown**.

This is the build-first early-exit gate proven on the real substrate: teardown is guaranteed on a
live hardware-isolated guest. (Arch note: this host is x86_64; detonating our aarch64 develop
munitions needs an arm64 KVM host — an orthogonal provisioning choice. The chamber logic is
arch-independent; this proof used the host's own x86 guest image.)

Remaining for a full real detonation: deploy the chamber scripts (`setup-host.sh` + `chamber-*.sh`)
and a rootfs carrying the vulnerable service + telemetry sensor, then fire a benign payload and
produce the first detection-gap data point.

## Full real detonation on the microVM (2026-08-03)

Beyond the teardown gate, the **complete build-first slice ran live** on `crucible-fc-host` — a
benign detonation in a networked, air-gapped Firecracker microVM (booted from a disposable overlay,
guest reached over SSH via the staged key, host tap wired only to a T0 sinkhole with `ip_forward=0`
+ an iptables egress chain).

- **Dry-run first**: guest reachable + sinkhole up confirmed before any payload.
- **Effect (capability)**: the benign payload fired the objective marker in-guest (the marker read
  back matches the signed run marker `7b218c96…`), plus a recognizable suspicious action (read
  `/etc/shadow`, 20 lines).
- **Contained egress**: the C2 beacon to `c2.evil.test/checkin?m=<marker>` was served by the T0
  deception sinkhole (IOC recorded); the real-internet egress test (guest -> 8.8.8.8:53) was
  **blocked** — nothing left the box.
- **Detection-gap data point**: a `beacon-to-c2` rule run over the sinkhole IOC **fired** ->
  detection **COVERED** (the first coverage measurement; swapping the ruleset is how gaps are found).
- **Teardown guaranteed**: the microVM was destroyed and the disposable overlay discarded — no guest
  state survives.

Both build-first gates are met on the real substrate: **capability (effect observed + telemetry
captured) AND containment (every §6 invariant held)**. This is a genuine red-tier detonation on real
hardware virtualization, benign payload, fully contained.

Honest limits of this first live run: the "sensor" was the network sinkhole (no in-guest auditd/EDR
yet); the payload was a benign stand-in, not a real munition (and this host is x86_64, so it could
not run our aarch64 develop munitions regardless); the chamber was driven by ad-hoc host scripts,
not yet the committed `chamber-*.sh` + jailer path. Hardening those (in-guest EDR sensor, jailer,
the committed scripts, an arm64 host for real munitions) is the follow-on.

## In-guest host sensor wired: auditd (2026-08-03)

The first live run's only sensor was the network sinkhole. We have now wired a **real in-guest host
sensor** so detonation telemetry no longer depends on the payload choosing to beacon. Per the
`detonate-stage.md` §10 decision, the default sensor is Falco (eBPF, CO-RE), but the staged guest
kernel (6.1.102, and every Firecracker CI kernel) lacks `CONFIG_DEBUG_INFO_BTF`, and BTFHub does not
cover bespoke Firecracker-CI kernels — so eBPF CO-RE cannot load. We therefore wired the §10
**fallback**, **auditd** (kernel `CONFIG_AUDITSYSCALL=y`, no eBPF/BTF required), for now.

What ran, on the same GCP microVM, benign payload, fully air-gapped:

- **Daemon up in-guest**: auditd started (robust `systemctl -> service -> direct` fallback,
  verified `pgrep -x auditd`), `pid=578`, `enabled=1`, 3 rules loaded: `execve` (key `proc_exec`),
  a `-w /etc/shadow -p r` watch (key `shadow_read`), and `connect` (key `net_connect`).
- **Payload effect captured by the host sensor**: the benign payload read `/etc/shadow` (20 lines);
  auditd logged it. Audit log grew to 469 lines with **10 shadow-related events**.
- **Detection rule fired on host telemetry**: a `sensitive-file-read(/etc/shadow)` rule run over the
  audit log **fired with 5 hits -> COVERED** — now from a real host-telemetry signal, not just the
  network IOC. The network beacon still hit the sinkhole (HTTP 200) and the real-egress test stayed
  blocked; the guest was destroyed on teardown.

So the detonation now produces **two independent detection signals** (host syscall/file telemetry via
auditd, plus the network IOC via the sinkhole), and the guest self-reports the sensitive-file access.
Caveat: the `ausearch -k` key-scoped queries for `proc_exec`/`net_connect` returned 0 in this run (a
query/format quirk — the events are present in the raw log); the primary working signal is the
`/etc/shadow` file-watch, which is the detection we assert.

The Falco/eBPF path (the §10 *default*) is tracked as a follow-up: **Adversarix/aegis-labs#38** —
build a BTF-enabled Firecracker guest kernel (`CONFIG_DEBUG_INFO_BTF=y`) so Falco (and Sysmon+Sigma)
can load, replacing auditd as the primary sensor.

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
