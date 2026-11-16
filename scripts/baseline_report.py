"""Benign baseline (or any window) from MongoDB: per-device loss and per-type latency.

Loss is counted from sequence numbers: within each (device, boot), every seq between the
first and last one stored in the window should be present. Latency = ingest receive time
minus device send time. Use it on a clean run (no restarts, outages or pauses) to get the
honest-device baseline that M5's attack impact is compared against.

    python -m scripts.baseline_report --start 2026-10-15T13:43:40Z --end 2026-10-15T14:08:40Z
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime

import numpy as np

from services.common.db import connect, database


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def report(db, start: datetime, end: datetime, exclude: set[str] | None = None) -> dict:
    exclude = exclude or set()
    docs = list(db.telemetry.find({"ts": {"$gte": start, "$lt": end}},
                                  {"meta": 1, "boot": 1, "seq": 1, "latency_ms": 1}))
    by_dev = defaultdict(lambda: defaultdict(list))
    lat_by_type = defaultdict(list)
    types = {}
    for d in docs:
        dev = d["meta"]["device_id"]
        if dev in exclude:
            continue
        types[dev] = d["meta"]["type"]
        by_dev[dev][d.get("boot")].append(d["seq"])
        lat_by_type[d["meta"]["type"]].append(d["latency_ms"])
    devices = {}
    for dev, boots in sorted(by_dev.items()):
        received = sum(len(v) for v in boots.values())
        expected = sum(max(v) - min(v) + 1 for v in boots.values())
        devices[dev] = {"type": types[dev], "boots": len(boots), "received": received,
                        "expected": expected, "lost": expected - received}
    latency = {}
    for t, values in sorted(lat_by_type.items()):
        a = np.asarray(values)
        latency[t] = {"messages": len(a), "p50_ms": round(float(np.percentile(a, 50)), 2),
                      "p95_ms": round(float(np.percentile(a, 95)), 2),
                      "p99_ms": round(float(np.percentile(a, 99)), 2), "max_ms": round(float(a.max()), 2)}
    all_lat = np.asarray([x for v in lat_by_type.values() for x in v])
    return {"start": start.isoformat(), "end": end.isoformat(), "devices": devices, "latency_by_type": latency,
            "fleet": {"messages": len(all_lat), "lost": sum(d["lost"] for d in devices.values()),
                      "p50_ms": round(float(np.percentile(all_lat, 50)), 2),
                      "p95_ms": round(float(np.percentile(all_lat, 95)), 2),
                      "p99_ms": round(float(np.percentile(all_lat, 99)), 2),
                      "max_ms": round(float(all_lat.max()), 2)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    r = report(database(connect()), parse(args.start), parse(args.end))
    print(f"window {r['start']} -> {r['end']}")
    print(f"{'device':10} {'type':12} {'boots':>5} {'received':>8} {'expected':>8} {'lost':>4}")
    for dev, d in r["devices"].items():
        print(f"{dev:10} {d['type']:12} {d['boots']:5} {d['received']:8} {d['expected']:8} {d['lost']:4}")
    print("latency by type (device send -> ingest receive):")
    for t, l in r["latency_by_type"].items():
        print(f"  {t:12} n={l['messages']:5} p50={l['p50_ms']} p95={l['p95_ms']} p99={l['p99_ms']} max={l['max_ms']} ms")
    f = r["fleet"]
    print(f"fleet: {f['messages']} messages, {f['lost']} lost, p50={f['p50_ms']} p95={f['p95_ms']} "
          f"p99={f['p99_ms']} max={f['max_ms']} ms")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=2)


if __name__ == "__main__":
    main()
