#!/usr/bin/env bash
# Arm + fire the munition inside the running guest. --dry-run plans + gate-checks
# with NO live payload; --live pushes the (armorer-armed) munition over the guest
# transport and fires it with the signed marker so emitted telemetry/IOCs are
# attributable. Emits JSON. Called by FirecrackerSubstrate.detonate().
# Args: <vmid> --dry-run|--live --marker <hex>
# Transport (matches the validated ad-hoc run): SSH over the deception tap to the
# guest's fixed air-gapped address. The guest reaches ONLY the T0 sinkhole; the
# host<->guest control channel rides the same tap (no default route in the guest).
# Env (optional):
#   AEGIS_GUEST_IP    guest address on the tap        (default 172.31.0.2)
#   AEGIS_GUEST_KEY   host-side private key for it    (default /srv/detonate/assets/guest_key)
#   AEGIS_MUNITION    host path to a munition to push (default: run the baked benign agent)
set -uo pipefail
VMID="$1"; MODE="$2"; MARKER=""; [ "${3:-}" = "--marker" ] && MARKER="${4:-}"
CHAMBER=/srv/detonate; JAIL="/srv/detonate/jail/firecracker/$VMID/root"
GUEST_IP="${AEGIS_GUEST_IP:-172.31.0.2}"
GUEST_KEY="${AEGIS_GUEST_KEY:-$CHAMBER/assets/guest_key}"

guest_ssh() { ssh -i "$GUEST_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=8 -o BatchMode=yes "root@$GUEST_IP" "$@"; }
guest_scp() { scp -i "$GUEST_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=8 -o BatchMode=yes "$1" "root@$GUEST_IP:$2"; }

if [ "$MODE" = "--dry-run" ]; then
  # Plan + gate-check with no payload: guest reachable, sinkhole up, marker set.
  reachable=false; guest_ssh true >/dev/null 2>&1 && reachable=true
  sinkhole_up=false; [ -f "$JAIL/sinkhole.pid" ] && kill -0 "$(cat "$JAIL/sinkhole.pid")" 2>/dev/null && sinkhole_up=true
  marker_set=false; [ -n "$MARKER" ] && marker_set=true
  echo "{\"dryRun\":true,\"plan\":[\"push munition\",\"fire\",\"observe\"],\"reachable\":$reachable,\"sinkhole_up\":$sinkhole_up,\"marker_set\":$marker_set,\"effect\":null,\"iocs\":[]}"
  exit 0
fi

# Live-fire. Munition hand-off: push the armorer-armed munition into the guest if
# one was supplied; otherwise fire.sh runs the baked benign stand-in.
if [ -n "${AEGIS_MUNITION:-}" ] && [ -f "$AEGIS_MUNITION" ]; then
  guest_ssh "mkdir -p /opt/agent" >/dev/null 2>&1 || true
  guest_scp "$AEGIS_MUNITION" "/opt/agent/munition" >/dev/null 2>&1 || true
  guest_ssh "chmod +x /opt/agent/munition" >/dev/null 2>&1 || true
fi

# Fire with the signed marker. fire.sh runs the munition if present, else the
# benign agent, and echoes the marker back on success.
RESULT="$(guest_ssh "AEGIS_MARKER=$MARKER /opt/agent/fire.sh" 2>/dev/null || echo '')"

# Effect: the objective marker fired iff the guest echoed it back OR it reached the
# sinkhole (a marker-tagged beacon). Match the marker itself, not a fixed literal.
FIRED=false
if [ -n "$MARKER" ]; then
  { echo "$RESULT" | grep -q "$MARKER"; } && FIRED=true
  { grep -q "$MARKER" "$JAIL/sinkhole.log" 2>/dev/null; } && FIRED=true
fi

# IOCs, from two independent signals:
#   network — beacons the T0 sinkhole served (host-side log).
#   host    — the in-guest auditd sensor's sensitive-file-read hits (shadow_read).
iocs=()
NET_HITS="$(grep -c '"served": "T0-sinkhole"' "$JAIL/sinkhole.log" 2>/dev/null || echo 0)"
[ "${NET_HITS:-0}" -gt 0 ] 2>/dev/null && iocs+=("{\"type\":\"network\",\"channel\":\"t0-sinkhole\",\"hits\":$NET_HITS}")
HOST_HITS="$(guest_ssh "ausearch -k shadow_read 2>/dev/null | grep -c '^type=SYSCALL'" 2>/dev/null || echo 0)"
[ "${HOST_HITS:-0}" -gt 0 ] 2>/dev/null && iocs+=("{\"type\":\"host\",\"sensor\":\"auditd\",\"rule\":\"shadow_read\",\"hits\":$HOST_HITS}")

IFS=,; echo "{\"dryRun\":false,\"effect\":{\"marker_fired\":$FIRED},\"iocs\":[${iocs[*]-}]}"
