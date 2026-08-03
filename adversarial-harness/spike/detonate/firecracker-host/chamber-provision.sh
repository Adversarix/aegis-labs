#!/usr/bin/env bash
# Boot ONE disposable microVM per detonation under the jailer, from the clean
# snapshot, wired to the T0 sinkhole with NO default route. Emits JSON on stdout.
# Called by FirecrackerSubstrate.provision().  Args: <runId> <jailerRoot>
set -euo pipefail
RUN_ID="$1"; JAILER_ROOT="${2:-/srv/detonate/jail}"; CHAMBER=/srv/detonate
VMID="det-${RUN_ID}"
JAIL="$JAILER_ROOT/firecracker/$VMID/root"
mkdir -p "$JAIL"

# Disposable overlay off the read-only clean rootfs snapshot (never mutate the base).
cp --reflink=auto "$CHAMBER/assets/rootfs.base.ext4" "$JAIL/rootfs.ext4"
cp "$CHAMBER/assets/vmlinux" "$JAIL/vmlinux"

# Deception-net tap: a host veth/tap the guest can reach ONLY the sinkhole through.
TAP="fc-${VMID:0:11}"
ip tuntap add "$TAP" mode tap 2>/dev/null || true
ip addr add 172.31.0.1/30 dev "$TAP" 2>/dev/null || true
ip link set "$TAP" up
# Air-gap: DROP + COUNT anything from the guest /30 not destined for the sinkhole.
SINK=172.31.0.1
iptables -N "EG_$VMID" 2>/dev/null || iptables -F "EG_$VMID"
iptables -A "EG_$VMID" -s 172.31.0.0/30 -d "$SINK" -j ACCEPT
iptables -A "EG_$VMID" -s 172.31.0.0/30 -j DROP        # counted; assert == 0 later
iptables -C FORWARD -i "$TAP" -j "EG_$VMID" 2>/dev/null || iptables -I FORWARD -i "$TAP" -j "EG_$VMID"
# start the T0 sinkhole bound to $SINK for this run (fake DNS + catch-all HTTP)
python3 "$CHAMBER/sinkhole.py" --bind "$SINK" --log "$JAIL/sinkhole.log" --pidfile "$JAIL/sinkhole.pid" &

# Launch firecracker under the jailer (seccomp + cgroups + chroot + netns).
jailer --id "$VMID" --exec-file /usr/local/bin/firecracker --uid 10000 --gid 10000 \
  --chroot-base-dir "$JAILER_ROOT" --netns "/var/run/netns/${VMID}" -- \
  --api-sock /run/firecracker.socket --boot-timer >/dev/null 2>&1 &
sleep 0.5
# (Guest kernel cmdline gives the guest ip=172.31.0.2, no gateway -> air-gapped.)

cat <<JSON
{"runId":"$RUN_ID","vmid":"$VMID","socket":"$JAIL/run/firecracker.socket","tap":"$TAP","sinkhole":"$JAIL/sinkhole.log","isolated":true}
JSON
