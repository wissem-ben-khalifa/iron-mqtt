#!/usr/bin/env bash
# M2 check: does the capture sensor really see the fleet, and do the evidence pcaps show
# (a) every device's TLS handshake, (b) rogue clients rejected, (c) decryptable MQTT
# with a keylog? Produces captures/evidence/m2-*.pcap for Wireshark. Run via ./iron capture-check.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_FILE="compose.yaml:compose.devices.yaml"
EV=captures/evidence
TSHARK=(docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/captures:/captures" iron-mqtt/netutils)
mkdir -p "$EV"
DEVICES=$(docker compose config --services | grep '^device-' | sort)
N=$(echo "$DEVICES" | wc -l)

t0=$(date +%s)
echo "[1/5] restarting $N devices so their TLS handshakes are captured"
docker compose restart $DEVICES >/dev/null 2>&1
sleep 15

echo "[2/5] rogue / no-cert attempts (TLS 1.2 cleartext + TLS 1.3 with keylog)"
docker compose --profile test run --rm --no-deps tests python -m scripts.rogue_demo 2>/dev/null

echo "[3/5] one MQTT session with a keylog (for decrypted-view evidence)"
docker compose --profile test run --rm --no-deps tests python -m scripts.keylog_demo \
  --keylog /captures/evidence/m2-session.keylog 2>/dev/null

sleep 7  # let the sensor close its current 5-second chunk
chmod 600 "$EV"/*.keylog  # keylogs are secrets: owner-only
rm -f "$EV/m2-handshakes-and-rogue.pcap"
chunks=$(find captures/live -name '*.pcap' -newermt "@$((t0 - 5))" | sort | sed 's#^captures#/captures#')
"${TSHARK[@]}" mergecap -w /captures/evidence/m2-handshakes-and-rogue.pcap $chunks
echo "[4/5] merged $(echo "$chunks" | wc -w) chunks -> $EV/m2-handshakes-and-rogue.pcap"

P=/captures/evidence/m2-handshakes-and-rogue.pcap
T() { "${TSHARK[@]}" tshark -r "$P" "$@" 2>/dev/null; }
echo "[5/5] analysis"
hello_ips=$(T -Y 'tls.handshake.type==1' -T fields -e ip.src | sort -u)
fleet_hello=$(echo "$hello_ips" | grep -c '^172\.28\.0\.1[0-9][0-9]$' || true)
echo "  ClientHello from fleet IPs: $fleet_hello / $N"
echo "  all ClientHello sources: $(echo $hello_ips)"
data_ips=$(T -Y 'tcp.dstport==8883 && tcp.len>0' -T fields -e ip.src | sort -u | grep -c '^172\.28\.0\.1' || true)
echo "  fleet IPs sending data to 8883: $data_ips / $N"
echo "  TLS 1.2 client certificates in cleartext (subject CN, issuer CN) from the tests container:"
T -Y 'ip.src==172.28.0.250 && tls.handshake.type==11' -T fields -e x509sat.uTF8String | sort | uniq -c | sed 's/^/    /'
echo "  TLS alerts sent by the broker (cleartext in TLS 1.2):"
T -Y 'ip.src==172.28.0.10 && tls.alert_message' -T fields -e ip.dst -e tls.alert_message.desc | sort | uniq -c | sed 's/^/    /'
echo "  decrypted with the TLS 1.3 rogue keylog (alert 116=certificate_required / 48=unknown_ca):"
T -o "tls.keylog_file:/captures/evidence/rogue-tls13.keylog" -Y 'ip.src==172.28.0.10 && tls.alert_message' \
  -T fields -e ip.dst -e tls.alert_message.desc | sort | uniq -c | sed 's/^/    /'
echo "  MQTT decrypted with the session keylog (only that session; everything else stays opaque):"
T -o "tls.keylog_file:/captures/evidence/m2-session.keylog" -Y mqtt -T fields -e ip.src -e _ws.col.Info \
  | cut -c1-110 | sed 's/^/    /'
plain_mqtt=$(T -Y mqtt | wc -l)
echo "  MQTT packets readable WITHOUT a keylog: $plain_mqtt (expected 0: everything is TLS)"

ok=1
[ "$fleet_hello" -eq "$N" ] || ok=0
[ "$data_ips" -eq "$N" ] || ok=0
[ "$plain_mqtt" -eq 0 ] || ok=0
echo "CAPTURE CHECK: $([ $ok -eq 1 ] && echo PASS || echo FAIL)"
[ $ok -eq 1 ]
