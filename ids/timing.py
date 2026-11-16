"""Timing realism: do per-client inter-arrival patterns transfer between MQTTset and the fleet?

Sizes do not transfer (plaintext vs TLS, see the feature spike), but *when* a client
speaks is independent of encryption. Method, identical for both sources:

  1. Take client->broker TCP segments that carry payload (empty ACKs excluded).
  2. Drop keepalives so they do not distort timing:
       - MQTTset (plaintext): keep only segments whose first byte is an MQTT PUBLISH
         fixed header (packet type 3).
       - Fleet (TLS, MQTT is invisible): drop 24-byte segments, which is exactly a TLS
         record carrying a 2-byte PINGREQ (5 B header + 2 B + 1 B type + 16 B tag).
         Fleet status heartbeats (every 60 s) are PUBLISHes and stay in.
  3. Per client: message rate, median gap, coefficient of variation CV = std/mean of
     the gaps, burstiness B = (std - mean)/(std + mean)  (-1 periodic, 0 Poisson, ->1 bursty).

    python -m ids.timing --source fleet   --pcap '/captures/runs/x/*.pcap' --port 8883
    python -m ids.timing --source mqttset --pcap /data/.../legit.pcap      --port 1883
"""

from __future__ import annotations

import argparse
import glob
import json
from collections import defaultdict

import dpkt
import numpy as np

from ids.features import _addr, _ip_layer

PINGREQ_TLS_SEGMENT = 24
MQTT_PUBLISH = 3


def message_times(paths: list[str], port: int, source: str) -> dict[str, list[float]]:
    """Timestamps of non-keepalive client->broker data segments, per client IP."""
    times: dict[str, list[float]] = defaultdict(list)
    for path in paths:
        with open(path, "rb") as fh:
            try:
                reader = dpkt.pcap.Reader(fh)
            except ValueError:
                fh.seek(0)
                reader = dpkt.pcapng.Reader(fh)
            link = reader.datalink()
            for ts, buf in reader:
                try:
                    ip = _ip_layer(link, buf)
                except (dpkt.UnpackError, ValueError, IndexError):
                    continue
                tcp = getattr(ip, "data", None)
                if not isinstance(tcp, dpkt.tcp.TCP) or tcp.dport != port or not tcp.data:
                    continue
                if source == "mqttset" and tcp.data[0] >> 4 != MQTT_PUBLISH:
                    continue
                if source == "fleet" and len(tcp.data) == PINGREQ_TLS_SEGMENT:
                    continue
                times[_addr(ip.src)].append(float(ts))
    return times


def stats(ts: list[float]) -> dict:
    t = np.sort(np.asarray(ts))
    gaps = np.diff(t)
    if len(gaps) < 5:
        return {"messages": len(t), "note": "too few messages"}
    mean, std = float(gaps.mean()), float(gaps.std())
    span_min = (t[-1] - t[0]) / 60
    return {
        "messages": len(t),
        "rate_per_min": round(len(t) / span_min, 2) if span_min else None,
        "median_gap_s": round(float(np.median(gaps)), 3),
        "cv": round(std / mean, 3) if mean else None,
        "burstiness": round((std - mean) / (std + mean), 3) if (std + mean) else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["fleet", "mqttset"], required=True)
    ap.add_argument("--pcap", required=True, help="file or glob")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--clients", default=None, help="regex of client IPs to keep")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    import re
    keep = re.compile(args.clients) if args.clients else None
    per_client = {ip: stats(ts) for ip, ts in message_times(sorted(glob.glob(args.pcap)), args.port, args.source).items()
                  if keep is None or keep.match(ip)}
    print(f"{'client':16} {'msgs':>6} {'rate/min':>8} {'median gap s':>12} {'CV':>6} {'B':>6}")
    for ip in sorted(per_client):
        r = per_client[ip]
        if "note" in r:
            print(f"{ip:16} {r['messages']:6}  {r['note']}")
            continue
        print(f"{ip:16} {r['messages']:6} {r['rate_per_min']:8} {r['median_gap_s']:12} {r['cv']:6} {r['burstiness']:6}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(per_client, fh, indent=2)


if __name__ == "__main__":
    main()
