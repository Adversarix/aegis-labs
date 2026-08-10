# Firecracker chamber - deploy runbook

**Status:** draft v0.1 (2026-08-10) · **Owner:** K. Galappatti (AEGIS Labs)
**Scope:** operationalize the committed `firecracker-host/` scripts + `FirecrackerSubstrate`
into a repeatable red-tier detonation on a real Linux/KVM host, replacing the ad-hoc host
scripts used for the 2026-08-03 proof.

Read alongside: [`../README.md`](../README.md), [`../FINDINGS-detonate-build-first.md`](../FINDINGS-detonate-build-first.md),
[`../../../detonate-substrate-requirements.md`](../../../detonate-substrate-requirements.md),
[`../../../DESIGN.md`](../../../DESIGN.md) §6.1.

---

## 0. What this runbook is (and is not)

The control plane is done and the load-bearing gate already ran on real hardware. On
2026-08-03 a full benign detonation ran live on a real Firecracker microVM (`crucible-fc-host`,
GCP n2-standard-4, x86_64): disposable overlay off a read-only base, air-gapped tap to a T0
sinkhole, teardown-under-kill proven, auditd host telemetry, and a first detection-gap data
point. See the FINDINGS.

**That run was driven by ad-hoc host scripts, not the committed path.** This runbook closes
that gap: it deploys the committed `setup-host.sh` + `chamber-*.sh` under the jailer and drives
them through `FirecrackerSubstrate` + `detonateRun`, so the detonation is reproducible from the
orchestrator instead of by hand.

This runbook does **not** cover a real (non-benign) munition. That additionally needs (a) the
custody store armed by a human armorer, and (b) an **arm64 KVM host** if the munition is one of
our aarch64 develop munitions (the current host is x86_64; the chamber logic is arch-independent,
the guest image is not). Real munitions stay out of scope until the two blocking code gaps in
§7 are closed.

---

## 1. Target host

Either host works for the benign build-first re-run; the arch caveat only bites for real
aarch64 munitions.

| Host | Arch | KVM | Access | Notes |
|---|---|---|---|---|
| `crucible-fc-host` (GCP n2-standard-4) | x86_64 | yes (nested) | `gcloud compute ssh --tunnel-through-iap` | the 2026-08-03 host; blocked only on gcloud re-auth |
| `kish-linux-01.tail210073.ts.net` | x86_64 | docker+kvm | tailnet SSH, `aegis` account | **no-sudo `aegis` account** - setup + chamber scripts need root (`iptables`, `jailer`, `ip netns`), so this needs a sudo-capable account or the chamber scripts pre-installed by root |

**Driver selects the host.** `FirecrackerSubstrate` has two modes:

- `mode: "local"` - run the orchestrator on the KVM host itself; `_host` runs `bash -lc`.
- `mode: "gcp-ssh"` - drive remotely; `_host` runs `gcloud compute ssh <gcpInstance> --zone <gcpZone> --tunnel-through-iap --command ...`. Needs `gcpInstance`, `gcpZone`.

Every `chamber-*.sh` call is wrapped in `sudo` by the substrate, so the SSH account must have
passwordless sudo for those scripts (or run the orchestrator as root on the host).

---

## 2. Prerequisites

On the workstation driving a remote host:
- `gcloud` authenticated (`gcloud auth login`; the 2026-08-03 blocker was re-auth) with compute + IAP access to the instance.
- Node available to run `detonate.test.mjs` / a drive script.

On the KVM host:
- `/dev/kvm` present (nested virt on GCP; bare-metal elsewhere).
- Outbound network for the one-time `setup-host.sh` (it curls the firecracker release), then air-gapped for detonation.
- Root / passwordless sudo for the chamber scripts.

---

## 3. Phases

Each phase has a hard acceptance gate. Do not advance past a failing gate.

### Phase A - one-time host setup

```bash
# on the host (or: gcloud compute ssh ... --command 'sudo bash -s' < setup-host.sh)
sudo ./setup-host.sh
```

`setup-host.sh` installs firecracker + jailer, creates `/srv/detonate/{jail,assets,snapshots,runs}`,
sets `net.ipv4.ip_forward=0`, and installs `sinkhole.py` + the four `chamber-*.sh` into
`/srv/detonate/`.

- **Version pin:** the script pins `FC_VER=v1.10.1`; the 2026-08-03 ad-hoc run used v1.16.1.
  Decide the pin deliberately and record it. Bump `FC_VER` in the script if v1.16.x is the
  intended baseline, so the committed path matches what was validated.
- **Gate:** `command -v firecracker && command -v jailer && ls /srv/detonate/chamber-*.sh` all succeed.

### Phase B - stage the clean guest assets

`setup-host.sh` leaves two `TODO` placeholders - the chamber cannot boot without them:

```
/srv/detonate/assets/vmlinux            guest kernel
/srv/detonate/assets/rootfs.base.ext4   read-only clean rootfs (vulnerable service + sensor)
```

The base rootfs must carry:
- the target/vulnerable service the benign payload exercises,
- the in-guest host sensor. Current default is **auditd** (`CONFIG_AUDITSYSCALL=y`, no BTF).
  Falco/eBPF is the intended default but the Firecracker-CI kernel lacks `CONFIG_DEBUG_INFO_BTF`;
  a BTF-enabled guest kernel is tracked in **Adversarix/aegis-labs#38**. Use auditd here.
- a guest cmdline giving `ip=172.31.0.2` with **no gateway** (air-gapped by construction).

Keep the base read-only; each run boots a disposable overlay (`chamber-provision.sh` does the
`cp --reflink=auto`).

- **Gate:** `test -f /srv/detonate/assets/vmlinux && test -f /srv/detonate/assets/rootfs.base.ext4`, and a manual boot of the base reaches the guest with auditd running and no default route.

### Phase C - preflight through the substrate

```js
import { FirecrackerSubstrate } from "./substrate.mjs";
const sub = new FirecrackerSubstrate({ mode: "gcp-ssh", gcpInstance: "crucible-fc-host", gcpZone: "us-east1-b" });
await sub.preflight();   // checks /dev/kvm + firecracker + jailer, throws if not READY
console.log(sub.isolates());  // true -> real munitions would be accepted
```

- **Gate:** `preflight()` returns `{ ready: true }`. A failure here means Phase A did not land.

### Phase D - re-prove teardown-under-kill on the committed path

This is the early-exit gate from `detonate-stage.md` §9 and it is proven **first**, before any
detonation, on the committed jailer path (the 2026-08-03 proof used ad-hoc scripts).

Provision one guest, then kill the orchestrator mid-run (SIGTERM/SIGKILL) and confirm the guest
process, the jail dir, the tap, and the egress chain are all gone.

```bash
# manual smoke, on the host:
sudo /srv/detonate/chamber-provision.sh smoke1 /srv/detonate/jail   # boots one microVM
# ... kill firecracker mid-window, then:
sudo /srv/detonate/chamber-teardown.sh det-smoke1
#   expect: {"torn_down":true,...}; then verify nothing survives:
pgrep -f 'firecracker.*det-smoke1'; ls /srv/detonate/jail/firecracker/det-smoke1 2>&1; ip link show fc-det-smoke1 2>&1; sudo iptables -L EG_det-smoke1 2>&1
```

- **Gate (load-bearing):** after teardown, the firecracker process is gone, the jail dir is
  removed, the tap is deleted, and `EG_<vmid>` chain does not exist. If teardown is not provably
  guaranteed under a mid-detonation kill, **stop and fix containment before anything else.**

### Phase E - dry-run, then first benign live detonation

Drive the full slice via `detonateRun` with the real substrate and a **benign** payload:

```js
import { detonateRun, passesBuildFirst } from "./detonate.mjs";
const report = await detonateRun({
  substrate: sub, store, munitionId, armorer: "<armorer-token>",
  markerKey: process.env.AEGIS_MARKER_KEY, chamberRunId: "fc-benign-1", benign: true,
});
console.log(passesBuildFirst(report));  // { capability, containment }
```

`detonateRun` enforces the order: armorer-authorized `arm` -> `dry-run` (must return `dryRun:true`)
-> live-fire -> `assert-no-egress` -> report -> `finally` teardown + disarm.

- **Gate (capability):** `report.effect.marker_fired === true` and `report.iocs.length > 0`
  (the signed marker fired in-guest and telemetry captured it).

### Phase F - assert-no-egress + first committed-path detection-gap point

`assert-no-egress` reads the host iptables DROP counter on the guest subnet; it must be zero.

- **Gate (containment):** `assertNoEgress` returns `{ ok: true, real_egress: 0 }`, and the real-egress
  probe (guest -> 8.8.8.8:53) is blocked. Then run a detection rule over the emitted IOCs
  (network sinkhole IOC and/or the auditd `/etc/shadow` file-watch) and record COVERED / gap.
  Swapping the ruleset is how gaps are found; this is the reproducible detection-gap measurement.

---

## 4. Committed-path code gaps (CLOSED by #61)

These were in the committed code, not the host, and were the real deploy work. Both are closed by
PR #61; the entries stay here as the record of what the committed path now does and what the
real-host Phases D-F still validate.

1. **`chamber-detonate.sh` live-fire transport - CLOSED.** It previously called a placeholder
   `ssh-guest "$VMID" ...` with `TODO(deploy): wire the guest agent transport (vsock) + the munition
   hand-off`, so live-fire could not push a payload or read effect back. It now uses the transport
   the 2026-08-03 run validated: **SSH over the deception tap** to the guest's fixed air-gapped
   address (`172.31.0.2`) with a staged host-side key (`setup-host.sh` generates it; the public half
   is baked into the base rootfs in Phase B). `AEGIS_MUNITION` scps an armorer-armed munition in
   (else the baked benign agent fires); `--dry-run` really probes reachability/sinkhole/marker; and
   `--live` returns `{effect:{marker_fired}, iocs}` assembled from two independent signals (T0
   sinkhole network log + in-guest auditd `shadow_read`).

2. **Verified teardown - CLOSED.** `detonate.mjs` set `teardown_verified` from `!guest?.dir`, which
   is unconditionally `true` for a Firecracker guest (no `.dir`), so `passesBuildFirst` containment
   passed vacuously on the real substrate. Teardown verification is now delegated to the substrate:
   `Substrate.verifyTornDown(guest)` - `LocalHarnessSubstrate` checks the guest dir is gone;
   `FirecrackerSubstrate` runs the new `chamber-verify-teardown.sh`, which independently confirms the
   microVM process, jail/overlay dir, tap, and egress chain are all gone on the host. `detonateRun`
   awaits it (`false` on any substrate whose teardown did not take).

Verified by `detonate.test.mjs` (19/19, incl. the new `verifyTornDown` contract). Real-host Phases
D-F still exercise this on the live KVM host.

---

## 5. Follow-ons (not blocking the benign re-run)

- **Falco/eBPF sensor** to replace auditd as primary (BTF-enabled guest kernel) - Adversarix/aegis-labs#38.
- **arm64 KVM host** to detonate our aarch64 develop munitions.
- **`aegis` CLI wiring** for the detonate flow (today it is not a CLI subcommand; it attaches to the store/custody path - see `../../aegis/README.md`).
- **`FC_VER` pin** reconciled between `setup-host.sh` (v1.10.1) and the validated v1.16.1.

---

## 6. Safety notes

- Benign payloads only until §4 gaps close and a human armorer authorizes a real munition.
- The chamber holds even if the mediation gate is defeated (§6.1); teardown (Phase D) is the
  property everything else rests on - never skip it, never advance past its gate.
- Never egress the weapon. Detonation produces traces, IOCs, and the mediation/detonation log,
  not the munition bytes.
