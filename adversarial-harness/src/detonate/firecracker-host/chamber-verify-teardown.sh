#!/usr/bin/env bash
# Independent post-teardown verification (NOT the teardown itself): prove nothing
# from the run survives on the host — no microVM process, no jail/overlay dir, no
# tap, no egress chain. Called by FirecrackerSubstrate.verifyTornDown() so the
# orchestrator's containment verdict reflects real host state. Emits JSON.
# Args: <vmid> [jailerRoot]
set -uo pipefail
VMID="$1"; JAILER_ROOT="${2:-/srv/detonate/jail}"
JAIL="$JAILER_ROOT/firecracker/$VMID"
TAP="fc-${VMID:0:11}"

proc_gone=true;  pgrep -f "firecracker.*$VMID" >/dev/null 2>&1 && proc_gone=false
dir_gone=true;   [ -e "$JAIL" ] && dir_gone=false
tap_gone=true;   ip link show "$TAP" >/dev/null 2>&1 && tap_gone=false
chain_gone=true; iptables -L "EG_$VMID" >/dev/null 2>&1 && chain_gone=false

torn=false
if $proc_gone && $dir_gone && $tap_gone && $chain_gone; then torn=true; fi
echo "{\"torn_down\":$torn,\"vmid\":\"$VMID\",\"proc_gone\":$proc_gone,\"dir_gone\":$dir_gone,\"tap_gone\":$tap_gone,\"chain_gone\":$chain_gone}"
