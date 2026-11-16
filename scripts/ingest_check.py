"""M3 check: does MongoDB hold exactly what the fleet sent?

1. An independent MQTT subscriber (not the ingest service) records every
   (device, seq) telemetry message seen on the broker for --seconds.
2. After a short grace period, every one of those messages must be in MongoDB's
   time-series `telemetry` collection exactly once.
3. Per device and boot, the stored sequence numbers over the observed range must be
   contiguous (no gaps, no duplicates), and the registry's gap counter must not grow.
4. End-to-end latency (device send -> ingest receive) per device type, computed by a
   MongoDB aggregation pipeline with $percentile.

Runs in the `tests` container as the read-only `analyst` Mongo user.
    python -m scripts.ingest_check --seconds 120
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from datetime import datetime, timezone

from services.common.db import connect, database
from services.common.mqtt import MqttSettings, connect_blocking, make_client


def latency_by_type(db, since: datetime) -> list[dict]:
    pipeline = [
        {"$match": {"recv_ts": {"$gte": since}}},
        {"$group": {
            "_id": "$meta.type",
            "messages": {"$sum": 1},
            "p50_ms": {"$percentile": {"input": "$latency_ms", "p": [0.5], "method": "approximate"}},
            "p95_ms": {"$percentile": {"input": "$latency_ms", "p": [0.95], "method": "approximate"}},
            "max_ms": {"$max": "$latency_ms"},
        }},
        {"$sort": {"_id": 1}},
    ]
    return list(db.telemetry.aggregate(pipeline))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=120)
    ap.add_argument("--grace", type=float, default=3.0)
    args = ap.parse_args()

    seen: dict[str, set[tuple[int, int]]] = defaultdict(set)  # device -> {(boot, seq)}

    def on_message(client, userdata, msg):
        env = json.loads(msg.payload)
        seen[msg.topic.split("/")[1]].add((env.get("boot"), int(env["seq"])))

    settings = MqttSettings(ca="/pki/ca/ca.crt", cert="/pki/services/ingest.crt", key="/pki/services/ingest.key")
    client = make_client(f"ingest-check-{int(time.time())}", settings)
    client.on_message = on_message
    assert not connect_blocking(client, settings).is_failure
    client.subscribe("devices/+/telemetry", qos=1)
    started = datetime.now(timezone.utc)
    db = database(connect())
    gaps_before = {d["_id"]: d.get("gaps", 0) for d in db.devices.find({}, {"gaps": 1})}
    time.sleep(args.seconds)
    client.loop_stop()
    client.disconnect()
    time.sleep(args.grace)

    ok = True
    print(f"observed on the wire for {args.seconds:.0f} s: "
          f"{sum(len(v) for v in seen.values())} messages from {len(seen)} devices")
    print(f"{'device':10} {'wire':>5} {'in db':>6} {'missing':>7} {'dupes':>5} {'db seq gaps':>11} {'new registry gaps':>17}")
    for dev in sorted(seen):
        wire = seen[dev]
        stored = []
        for boot in {b for b, _ in wire}:
            seqs = sorted(s for b, s in wire if b == boot)
            # every stored message of this boot within the observed seq range
            stored += [(boot, d["seq"]) for d in db.telemetry.find(
                {"meta.device_id": dev, "boot": boot, "seq": {"$gte": seqs[0], "$lte": seqs[-1]}}, {"seq": 1})]
        missing = len(wire - set(stored))
        dupes = len(stored) - len(set(stored))
        contiguous_gaps = 0
        for boot in {b for b, _ in stored}:
            s = sorted(q for b, q in set(stored) if b == boot)
            contiguous_gaps += s[-1] - s[0] + 1 - len(s)
        reg = db.devices.find_one({"_id": dev}) or {}
        new_gaps = reg.get("gaps", 0) - gaps_before.get(dev, 0)
        passed = missing == 0 and dupes == 0 and contiguous_gaps == 0 and new_gaps == 0
        ok &= passed
        print(f"{dev:10} {len(wire):5} {len(stored):6} {missing:7} {dupes:5} {contiguous_gaps:11} "
              f"{new_gaps:17}  {'ok' if passed else 'FAIL'}")

    print("\nend-to-end latency by device type (MongoDB $percentile aggregation, this window):")
    for row in latency_by_type(db, started):
        print(f"  {row['_id']:12} n={row['messages']:5}  p50={row['p50_ms'][0]:.2f} ms  "
              f"p95={row['p95_ms'][0]:.2f} ms  max={row['max_ms']:.2f} ms")
    print("INGEST CHECK:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
