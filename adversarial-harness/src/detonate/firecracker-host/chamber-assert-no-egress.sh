#!/usr/bin/env bash
# Assert ZERO real egress: the guest-subnet DROP counter (everything not the
# sinkhole) must be 0. This is the real network-containment check (vs the
# control-plane substrate's logical one). Emits JSON. Args: <vmid>
set -euo pipefail
VMID="$1"
DROPS=$(iptables -vxn -L "EG_$VMID" 2>/dev/null | awk '/DROP/{print $1; exit}')
DROPS="${DROPS:-0}"
echo "{\"ok\":$( [ "$DROPS" -eq 0 ] && echo true || echo false ),\"real_egress\":$DROPS,\"note\":\"host iptables drop-counter on the guest subnet\"}"
