#!/usr/bin/env bash
# Guaranteed teardown: kill the microVM, stop the sinkhole, discard the disposable
# overlay + jail, remove the tap + egress chain. Idempotent (safe on any exit/kill).
# Emits JSON. Args: <vmid>
set -uo pipefail
VMID="$1"; JAILER_ROOT="${2:-/srv/detonate/jail}"; JAIL="$JAILER_ROOT/firecracker/$VMID/root"
pkill -f "firecracker.*$VMID" 2>/dev/null || true
[ -f "$JAIL/sinkhole.pid" ] && kill "$(cat "$JAIL/sinkhole.pid")" 2>/dev/null || true
ip netns del "$VMID" 2>/dev/null || true
TAP="fc-${VMID:0:11}"; ip link del "$TAP" 2>/dev/null || true
iptables -D FORWARD -i "$TAP" -j "EG_$VMID" 2>/dev/null || true
iptables -F "EG_$VMID" 2>/dev/null || true; iptables -X "EG_$VMID" 2>/dev/null || true
rm -rf "$JAILER_ROOT/firecracker/$VMID" 2>/dev/null || true   # overlay + jail gone -> persistence cannot survive
echo "{\"torn_down\":true,\"vmid\":\"$VMID\"}"
