"""M7 check: with the live detector running, measure detection latency and false alarms.

- Observes a benign window first and counts any ml_flood incidents raised in it (false alarms).
- Launches N floods at known times; for each, finds the ml_flood incident from the attacker IP
  overlapping it and reads its recorded detection latency (incident time - window end).
- Reports median/max detection latency, detection rate (floods caught / floods run), ML false
  alarms per hour over the benign window, and the threshold rule's false alarms for contrast.

    python -m scripts.detector_check --floods 3 --rate 3000 --duration 15
Runs in the tests container (API token + analyst Mongo user).
"""

from __future__ import annotations

import argparse
import os
import statistics
import time
from datetime import datetime, timezone

import httpx

from services.common.db import connect, database

ATTACKER_IP = "172.28.0.40"
API = os.environ["API_URL"]
H = {"Authorization": f"Bearer {os.environ['API_TOKEN']}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--floods", type=int, default=3)
    ap.add_argument("--rate", type=float, default=3000)
    ap.add_argument("--duration", type=float, default=15)
    ap.add_argument("--gap", type=float, default=20)
    ap.add_argument("--benign", type=float, default=60)
    args = ap.parse_args()
    db = database(connect())
    now = lambda: datetime.now(timezone.utc)

    benign_start = now()
    print(f"observing {args.benign:.0f}s benign (counting false alarms) ...")
    time.sleep(args.benign)
    benign_end = now()
    ml_fa = db.incidents.count_documents(
        {"kind": "ml_flood", "detected_at": {"$gte": benign_start, "$lt": benign_end}})
    th_fa = db.incidents.count_documents(
        {"kind": "threshold_flood", "detected_at": {"$gte": benign_start, "$lt": benign_end}})
    benign_hours = args.benign / 3600

    floods = []
    with httpx.Client(base_url=API, headers=H, timeout=30) as api:
        for i in range(args.floods):
            start = now()
            api.post("/attacks/flood", json={"rate_per_s": args.rate, "duration_s": args.duration, "qos": 0})
            print(f"flood {i + 1}/{args.floods} at {start.strftime('%H:%M:%S')}")
            time.sleep(args.duration)
            api.post("/attacks/stop")
            floods.append((start, now()))
            time.sleep(args.gap)
    time.sleep(8)  # let the detector process the final chunk

    latencies, caught = [], 0
    for start, end in floods:
        inc = db.incidents.find_one(
            {"kind": "ml_flood", "source.src_ip": ATTACKER_IP,
             "window.end": {"$gte": start}, "window.start": {"$lte": end}},
            sort=[("window.start", 1)])
        if inc:
            caught += 1
            latencies.append(inc.get("detection_latency_s", float("nan")))
            print(f"  flood {start.strftime('%H:%M:%S')}: caught, model {inc['detector'].get('model_version')}, "
                  f"latency {inc.get('detection_latency_s', 0):.1f}s, {inc.get('windows')} windows")
        else:
            print(f"  flood {start.strftime('%H:%M:%S')}: MISSED")

    print(f"\ndetection rate: {caught}/{len(floods)} floods caught by the ML detector")
    if latencies:
        print(f"detection latency: median {statistics.median(latencies):.1f}s, max {max(latencies):.1f}s")
    print(f"ML false alarms in {args.benign:.0f}s benign: {ml_fa}  ({ml_fa / benign_hours:.1f}/hr)")
    print(f"threshold false alarms in the same window: {th_fa}  ({th_fa / benign_hours:.1f}/hr)")
    ok = caught == len(floods) and ml_fa == 0
    print("DETECTOR CHECK:", "PASS" if ok else "CHECK")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
