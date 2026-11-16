"""M5 check: launch a compromised-device flood and MEASURE its impact on honest devices.

Compares a benign window immediately before the attack with the attack window itself,
for the 9 honest devices (the compromised device-07 is excluded: its own topic is the
flood target). The flood is triggered through the control-plane API, which records it to
the `runs` collection as ground truth; this script reads that run back.

Impact = change in honest-device end-to-end latency (p50/p95/p99) and message loss, plus
how hard the flood actually hit (messages/s the attacker achieved).

    python -m scripts.attack_check --rate 500 --duration 60 --qos 0
Runs in the tests container (API token + analyst Mongo user in env).
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone

import httpx

from services.common.db import connect, database
from scripts.baseline_report import report

COMPROMISED = "device-07"
API = os.environ["API_URL"]
H = {"Authorization": f"Bearer {os.environ['API_TOKEN']}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=500)
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--qos", type=int, default=0)
    ap.add_argument("--payload-bytes", type=int, default=120)
    ap.add_argument("--settle", type=float, default=20, help="benign seconds to observe before attacking")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    db = database(connect())
    now = lambda: datetime.now(timezone.utc)

    benign_start = now()
    print(f"observing benign traffic for {args.settle:.0f} s ...")
    time.sleep(args.settle)
    benign_end = now()

    with httpx.Client(base_url=API, headers=H, timeout=30) as api:
        attack_start = now()  # authoritative window start: our own clock, not a stored field
        r = api.post("/attacks/flood", json={"rate_per_s": args.rate, "duration_s": args.duration,
                                             "qos": args.qos, "payload_bytes": args.payload_bytes})
        r.raise_for_status()
        run_id = r.json()["run_id"]
        print(f"flood launched: run {run_id}, rate {args.rate}/s, qos {args.qos}, {args.duration:.0f} s")
        # Measure impact over the generation window only [start, start+duration]. The backlog
        # drain afterwards is reported separately; stored run timestamps are not trusted here.
        time.sleep(args.duration)
        attack_end = now()
        agent = api.post("/attacks/stop").json()  # finalizes ground truth on the run

    time.sleep(3)  # let telemetry from the generation window land in MongoDB
    honest = {COMPROMISED}
    before = report(db, benign_start, benign_end, exclude=honest)
    during = report(db, attack_start, attack_end, exclude=honest)

    sent = agent.get("sent", 0)
    achieved = agent.get("actual_rate_per_s", 0)
    dur = (attack_end - attack_start).total_seconds()
    gen_s = agent.get("gen_seconds")
    drain_s = agent.get("drain_seconds")
    print(f"\nflood: {sent} messages, {achieved}/s achieved over {gen_s}s generation "
          f"(target {args.rate}/s, qos {args.qos}); +{drain_s}s TLS backlog drain")
    print(f"honest devices (9, excluding {COMPROMISED}):")
    fmt = "  {:8} msgs={:5} lost={:3} p50={:6.2f} p95={:7.2f} p99={:7.2f} max={:8.2f} ms"
    print("  --- benign window ({:.0f} s) ---".format((benign_end - benign_start).total_seconds()))
    print(fmt.format("before", before["fleet"]["messages"], before["fleet"]["lost"],
                     before["fleet"]["p50_ms"], before["fleet"]["p95_ms"],
                     before["fleet"]["p99_ms"], before["fleet"]["max_ms"]))
    print("  --- attack window ({:.0f} s) ---".format(dur))
    print(fmt.format("during", during["fleet"]["messages"], during["fleet"]["lost"],
                     during["fleet"]["p50_ms"], during["fleet"]["p95_ms"],
                     during["fleet"]["p99_ms"], during["fleet"]["max_ms"]))

    result = {"run_id": run_id, "flood": {"target_rate_per_s": args.rate, "achieved_rate_per_s": achieved,
                                          "sent": sent, "qos": args.qos, "gen_seconds": gen_s,
                                          "drain_seconds": drain_s, "window_s": round(dur, 1)},
              "honest_before": before["fleet"], "honest_during": during["fleet"],
              "honest_during_by_type": during["latency_by_type"]}
    verdict = {
        "latency_p95_ratio": round(during["fleet"]["p95_ms"] / before["fleet"]["p95_ms"], 2)
        if before["fleet"]["p95_ms"] else None,
        "honest_loss_during": during["fleet"]["lost"],
    }
    result["verdict"] = verdict
    print(f"\nimpact: honest p95 latency x{verdict['latency_p95_ratio']} "
          f"({before['fleet']['p95_ms']:.2f} -> {during['fleet']['p95_ms']:.2f} ms), "
          f"honest loss during attack = {verdict['honest_loss_during']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
    print("ATTACK CHECK: done (impact measured)")


if __name__ == "__main__":
    main()
