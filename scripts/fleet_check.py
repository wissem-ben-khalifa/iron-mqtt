"""M1 check: listen to the whole fleet for a while and measure what actually arrives.

Runs inside the `tests` container (whole PKI at /pki), subscribing as the `ingest`
identity. For every device it reports messages received, loss (gaps in the
device's sequence numbers), observed rate vs the profile's expected mean rate, and
end-to-end latency (receive time minus the device's send timestamp; containers share
the host kernel clock, so this difference is meaningful).

    python -m scripts.fleet_check --seconds 300 [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from collections import defaultdict

from services.common.mqtt import MqttSettings, connect_blocking, make_client

# Expected mean telemetry messages per minute, derived from the profile parameters.
EXPECTED_PER_MIN = {
    "env_sensor": 60 / 5.0,                        # strictly periodic
    "smart_plug": 60 / 10.0,                       # strictly periodic
    "door_sensor": 60 * 2 / (45.0 + 11.0),         # open (Poisson, mean 45 s) + close (2-20 s)
    "camera": 60 * 40 / (120.0 + 20.0),            # ~40 msgs per burst, mean idle 120 s
}
PERIODIC = {"env_sensor", "smart_plug"}
TOLERANCE = 0.05


def percentile(values, q):
    if not values:
        return float("nan")
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=300)
    ap.add_argument("--json", default=None)
    ap.add_argument("--expect", type=int, default=10, help="devices device-01..N that must be heard")
    args = ap.parse_args()

    per_dev = defaultdict(lambda: {"type": None, "seqs": [], "lat_ms": []})
    statuses = defaultdict(int)
    lock = threading.Lock()

    def on_message(client, userdata, msg):
        now = time.time()
        if msg.topic.endswith("/status"):
            statuses[msg.topic.split("/")[1]] += 1
            return
        env = json.loads(msg.payload)
        with lock:
            d = per_dev[env["device_id"]]
            d["type"] = env["type"]
            d["seqs"].append(env["seq"])
            d["lat_ms"].append((now - env["ts"]) * 1000)

    settings = MqttSettings(ca="/pki/ca/ca.crt", cert="/pki/services/ingest.crt",
                            key="/pki/services/ingest.key")
    client = make_client(f"fleet-check-{int(time.time())}", settings)
    client.on_message = on_message
    rc = connect_blocking(client, settings)
    assert rc is not None and not rc.is_failure, rc
    client.subscribe([("devices/+/telemetry", 1), ("devices/+/status", 1)])
    time.sleep(args.seconds)
    client.loop_stop()
    client.disconnect()

    expected_ids = [f"device-{i:02d}" for i in range(1, args.expect + 1)]
    silent = [dev for dev in expected_ids if dev not in per_dev and statuses[dev] == 0]
    quiet = [dev for dev in expected_ids if dev not in per_dev and statuses[dev] > 0]
    rows, ok = [], not silent
    for dev in sorted(per_dev):
        d = per_dev[dev]
        seqs = sorted(d["seqs"])
        span = seqs[-1] - seqs[0] + 1
        lost = span - len(set(seqs))
        dups = len(seqs) - len(set(seqs))
        rate = len(seqs) / (args.seconds / 60)
        expected = EXPECTED_PER_MIN[d["type"]]
        dev_ratio = rate / expected
        periodic = d["type"] in PERIODIC
        passed = lost == 0 and dups == 0 and (not periodic or abs(dev_ratio - 1) <= TOLERANCE)
        ok &= passed
        rows.append({
            "device": dev, "type": d["type"], "received": len(seqs), "lost": lost, "dups": dups,
            "rate_per_min": round(rate, 2), "expected_per_min": round(expected, 2),
            "ratio": round(dev_ratio, 3), "checked_rate": periodic,
            "lat_p50_ms": round(percentile(d["lat_ms"], 0.50), 2),
            "lat_p95_ms": round(percentile(d["lat_ms"], 0.95), 2),
            "status_msgs": statuses[dev], "pass": passed,
        })

    heard = len(expected_ids) - len(silent)
    print(f"listened {args.seconds:.0f} s; devices heard: {heard}/{len(expected_ids)} "
          f"(telemetry from {len(rows)}; heartbeat only: {quiet or 'none'}; silent: {silent or 'none'})")
    print(f"{'device':10} {'type':12} {'recv':>5} {'lost':>4} {'rate/min':>8} {'expect':>7} "
          f"{'ratio':>6} {'p50 ms':>7} {'p95 ms':>7}  pass")
    for r in rows:
        mark = "yes" if r["pass"] else "NO"
        rate_note = "" if r["checked_rate"] else " (stochastic: rate reported, not checked)"
        print(f"{r['device']:10} {r['type']:12} {r['received']:5} {r['lost']:4} {r['rate_per_min']:8} "
              f"{r['expected_per_min']:7} {r['ratio']:6} {r['lat_p50_ms']:7} {r['lat_p95_ms']:7}  {mark}{rate_note}")
    all_lat = [x for d in per_dev.values() for x in d["lat_ms"]]
    print(f"fleet latency p50={percentile(all_lat, .5):.2f} ms p95={percentile(all_lat, .95):.2f} ms "
          f"max={max(all_lat):.2f} ms over {len(all_lat)} messages")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"seconds": args.seconds, "devices": rows}, fh, indent=2)
    print("FLEET CHECK:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
