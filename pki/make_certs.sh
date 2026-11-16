#!/usr/bin/env bash
# Generates the range's throwaway private PKI into certs/ (gitignored, never committed).
#
#   certs/ca/ca.{crt,key}                 range CA (trust anchor for broker and clients)
#   certs/broker/broker.{crt,key}         broker server cert, SAN DNS:broker
#   certs/devices/device-NN.{crt,key}     one client cert per device (CN = device id)
#   certs/services/<name>.{crt,key}       client certs for internal services (ingest, api)
#   certs/rogue/foreign-ca.{crt,key}      a DIFFERENT CA the broker does not trust
#   certs/rogue/rogue.{crt,key}           client cert signed by the foreign CA (attack #1)
#
# Idempotent: existing files are kept, so DEVICES=30 ./pki/make_certs.sh only adds
# the missing device certs. Keys are ECDSA P-256; everything is mode 600 (containers
# run as the host user, so they can still read their own mounted files).
set -euo pipefail

DEVICES="${DEVICES:-10}"
OUT="${1:-certs}"
DAYS=825
SERVICES=(ingest api)

umask 077
mkdir -p "$OUT"/{ca,broker,devices,services,rogue}

gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

make_ca() {  # make_ca <key> <crt> <common name>
  [ -f "$2" ] && return
  gen_key "$1"
  openssl req -x509 -new -key "$1" -sha256 -days 3650 -subj "/CN=$3" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$2"
  echo "created CA: $3"
}

issue() {  # issue <ca-crt> <ca-key> <out-prefix> <common name> <extensions>
  local ca_crt=$1 ca_key=$2 prefix=$3 cn=$4 ext=$5
  [ -f "$prefix.crt" ] && return
  gen_key "$prefix.key"
  openssl req -new -key "$prefix.key" -subj "/CN=$cn" -out "$prefix.req"
  openssl x509 -req -in "$prefix.req" -CA "$ca_crt" -CAkey "$ca_key" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days "$DAYS" \
    -extfile <(printf '%b' "$ext") -out "$prefix.crt" 2>/dev/null
  rm -f "$prefix.req"
  echo "issued: $cn"
}

SERVER_EXT='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:broker,DNS:localhost,IP:127.0.0.1\n'
CLIENT_EXT='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'

make_ca "$OUT/ca/ca.key" "$OUT/ca/ca.crt" "IRON-MQTT Range CA"
issue "$OUT/ca/ca.crt" "$OUT/ca/ca.key" "$OUT/broker/broker" broker "$SERVER_EXT"

for i in $(seq 1 "$DEVICES"); do
  id=$(printf 'device-%02d' "$i")
  issue "$OUT/ca/ca.crt" "$OUT/ca/ca.key" "$OUT/devices/$id" "$id" "$CLIENT_EXT"
done

for s in "${SERVICES[@]}"; do
  issue "$OUT/ca/ca.crt" "$OUT/ca/ca.key" "$OUT/services/$s" "$s" "$CLIENT_EXT"
done

# The rogue side: a self-made CA the broker has never seen, and a client cert from it.
make_ca "$OUT/rogue/foreign-ca.key" "$OUT/rogue/foreign-ca.crt" "Foreign CA (untrusted)"
issue "$OUT/rogue/foreign-ca.crt" "$OUT/rogue/foreign-ca.key" "$OUT/rogue/rogue" device-01 "$CLIENT_EXT"

# Sanity: every range-issued cert must verify against the range CA, and the rogue must not.
for c in "$OUT"/broker/*.crt "$OUT"/devices/*.crt "$OUT"/services/*.crt; do
  openssl verify -CAfile "$OUT/ca/ca.crt" "$c" >/dev/null
done
if openssl verify -CAfile "$OUT/ca/ca.crt" "$OUT/rogue/rogue.crt" >/dev/null 2>&1; then
  echo "ERROR: rogue cert verifies against the range CA" >&2; exit 1
fi
echo "PKI ok: $(ls "$OUT"/devices/*.crt | wc -l) device certs, services: ${SERVICES[*]}, rogue: untrusted"
