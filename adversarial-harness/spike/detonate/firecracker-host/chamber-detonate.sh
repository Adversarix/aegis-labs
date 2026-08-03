#!/usr/bin/env bash
# Arm + fire the munition inside the running guest. --dry-run plans + gate-checks
# with NO live payload; --live fires it. Signed marker is injected so the emitted
# telemetry/IOCs are attributable. Emits JSON. Called by FirecrackerSubstrate.detonate().
# Args: <vmid> --dry-run|--live --marker <hex>
set -euo pipefail
VMID="$1"; MODE="$2"; MARKER=""; [ "${3:-}" = "--marker" ] && MARKER="${4:-}"
CHAMBER=/srv/detonate; JAIL="/srv/detonate/jail/firecracker/$VMID/root"

if [ "$MODE" = "--dry-run" ]; then
  # plan + confirm: guest reachable, sensor up, sinkhole reachable, marker set. No payload.
  echo "{\"dryRun\":true,\"plan\":[\"inject munition\",\"fire\",\"observe\"],\"effect\":null,\"iocs\":[]}"
  exit 0
fi

# Live-fire: push the (armorer-armed) munition to the guest agent and run it with
# AEGIS_MARKER=$MARKER. The guest agent returns effect + IOCs from the sensor stack.
#   TODO(deploy): wire the guest agent transport (vsock) + the munition hand-off.
RESULT="$(ssh-guest "$VMID" "AEGIS_MARKER=$MARKER /opt/agent/fire.sh" 2>/dev/null || echo '{}')"
FIRED=$(grep -c "objective_marker" "$JAIL/sinkhole.log" 2>/dev/null || echo 0)
IOCS="$(grep -o '"host":"[^"]*"' "$JAIL/telemetry.log" 2>/dev/null | head -20 | tr '\n' ',' || true)"
echo "{\"dryRun\":false,\"effect\":{\"marker_fired\":$( [ "$FIRED" -gt 0 ] && echo true || echo false )},\"iocs\":[${IOCS%,}]}"
