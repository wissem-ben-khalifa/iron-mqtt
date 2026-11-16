#!/usr/bin/env bash
# M8 reachability/isolation evidence (the Ping story). Shows that the network segmentation
# in the threat model is real: devices reach the broker but NOT the data plane (MongoDB),
# and the attacker likewise cannot reach MongoDB. Run via ./iron ping-matrix.
#
# Uses a throwaway netutils container attached to the relevant network, pinging by IP.
set -uo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_FILE="compose.yaml:compose.devices.yaml"
NET_IOT=iron-mqtt_iot_net
NET_BACKEND=iron-mqtt_backend_net
BROKER=172.28.0.10
MONGO=172.29.0.10

ping1() {  # ping1 <network> <target-ip> ; echoes OK/UNREACHABLE
  if docker run --rm --network "$1" iron-mqtt/netutils ping -c1 -W2 "$2" >/dev/null 2>&1; then
    echo OK; else echo UNREACHABLE; fi
}

echo "IRON-MQTT reachability matrix ($(date -u +%FT%TZ))"
echo
printf '%-34s %-14s %s\n' "from (network)" "to" "result"
printf '%-34s %-14s %s\n' "a device on iot_net"    "broker $BROKER" "$(ping1 $NET_IOT $BROKER)"
printf '%-34s %-14s %s\n' "a device on iot_net"    "mongo  $MONGO"  "$(ping1 $NET_IOT $MONGO)"
printf '%-34s %-14s %s\n' "the backend plane"      "mongo  $MONGO"  "$(ping1 $NET_BACKEND $MONGO)"
printf '%-34s %-14s %s\n' "the backend plane"      "broker $BROKER" "$(ping1 $NET_BACKEND $BROKER)"
echo
echo "Expected: devices reach the broker but NOT MongoDB (MongoDB is on the backend plane only);"
echo "the backend plane reaches MongoDB. This is the Ping evidence that the device<->data-plane"
echo "trust boundary is enforced by network segmentation, not just by application logic."
