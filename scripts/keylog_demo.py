"""Evidence helper: one MQTT/TLS session whose TLS secrets are logged for Wireshark.

Uses the same client factory as the devices, with device-01's identity but its own
client id (so the real device-01 is not disconnected). It publishes one status
message, which is allowed by the ACL for user device-01, then disconnects.

The keylog is written ONLY under /captures/evidence (gitignored, hook-blocked); the
factory refuses any other location. Keylogs are for Wireshark evidence, never IDS input.

    python -m scripts.keylog_demo --keylog /captures/evidence/m2-session.keylog
"""

from __future__ import annotations

import argparse
import json
import time

from services.common.mqtt import MqttSettings, connect_blocking, make_client


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keylog", required=True)
    ap.add_argument("--device", default="device-01")
    args = ap.parse_args()

    settings = MqttSettings(ca="/pki/ca/ca.crt", cert=f"/pki/devices/{args.device}.crt",
                            key=f"/pki/devices/{args.device}.key", keylog=args.keylog)
    client = make_client(f"{args.device}-evidence", settings)
    rc = connect_blocking(client, settings)
    assert rc is not None and not rc.is_failure, rc
    payload = json.dumps({"device_id": args.device, "state": "online", "note": "keylog evidence", "ts": time.time()})
    info = client.publish(f"devices/{args.device}/status", payload, qos=1)
    info.wait_for_publish(5)
    time.sleep(0.5)
    client.disconnect()
    client.loop_stop()
    print(f"published {len(payload)} B to devices/{args.device}/status at {time.strftime('%H:%M:%S')}; keylog: {args.keylog}")


if __name__ == "__main__":
    main()
