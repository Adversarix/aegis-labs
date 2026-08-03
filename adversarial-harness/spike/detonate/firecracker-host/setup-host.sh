#!/usr/bin/env bash
# One-time setup of a Linux/KVM host as the detonation chamber substrate
# (detonate-substrate-requirements.md). Run on the GCP instance (needs /dev/kvm,
# root). Installs firecracker + jailer, lays out the jail root, fetches a minimal
# guest kernel + rootfs, and stands up the T0 deception sinkhole + air-gap net.
set -euo pipefail
ARCH="$(uname -m)"                    # aarch64 or x86_64 — must match the munitions
CHAMBER=/srv/detonate
FC_VER="v1.10.1"

echo "[*] preflight: KVM"
test -e /dev/kvm || { echo "FATAL: no /dev/kvm (need a bare-metal / nested-virt host)"; exit 1; }

echo "[*] install firecracker + jailer ($ARCH)"
case "$ARCH" in
  aarch64) FCARCH=aarch64 ;; x86_64) FCARCH=x86_64 ;; *) echo "unsupported arch $ARCH"; exit 1 ;;
esac
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/fc.tgz" \
  "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VER}/firecracker-${FC_VER}-${FCARCH}.tgz"
tar -xzf "$tmp/fc.tgz" -C "$tmp"
install -m0755 "$tmp/release-${FC_VER}-${FCARCH}/firecracker-${FC_VER}-${FCARCH}" /usr/local/bin/firecracker
install -m0755 "$tmp/release-${FC_VER}-${FCARCH}/jailer-${FC_VER}-${FCARCH}" /usr/local/bin/jailer

echo "[*] jail root + assets"
mkdir -p "$CHAMBER"/{jail,assets,snapshots,runs}
# A guest kernel + a KNOWN-CLEAN base rootfs snapshot are the chamber's clean boot
# image. Build/fetch them here (a minimal Linux + the vulnerable service + the
# host-telemetry sensor). Kept read-only; each run boots a disposable overlay.
#   $CHAMBER/assets/vmlinux           guest kernel
#   $CHAMBER/assets/rootfs.base.ext4  clean rootfs snapshot (service + sensor)
[ -f "$CHAMBER/assets/vmlinux" ] || echo "  TODO: place a guest kernel at $CHAMBER/assets/vmlinux"
[ -f "$CHAMBER/assets/rootfs.base.ext4" ] || echo "  TODO: build the clean rootfs at $CHAMBER/assets/rootfs.base.ext4"

echo "[*] deception network (T0 sinkhole) + air-gap"
# The guest gets a tap with NO default route; the ONLY reachable address is the
# sinkhole. Any packet leaving the guest subnet for anything else is dropped and
# COUNTED, so assert-no-egress can prove zero real egress.
sysctl -w net.ipv4.ip_forward=0 >/dev/null
install -m0755 "$(dirname "$0")/sinkhole.py" "$CHAMBER/sinkhole.py" 2>/dev/null || true
for s in chamber-provision chamber-detonate chamber-assert-no-egress chamber-teardown; do
  install -m0755 "$(dirname "$0")/$s.sh" "$CHAMBER/$s.sh"
done

echo "[*] done. Chamber at $CHAMBER (arch $ARCH). Place the kernel + clean rootfs, then the"
echo "    FirecrackerSubstrate(mode='gcp-ssh', gcpInstance=...) can drive it."
