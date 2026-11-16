"""Feature spike: do our TLS-visible features look comparable on MQTTset and on the fleet?

Runs ids.features.extract unchanged on:
  - fleet benign pcaps (captures/live, MQTT over TLS on 8883),
  - a slice of MQTTset's legitimate week (plaintext MQTT on 1883),
  - MQTTset's flood capture (attack only; one attacker connection).
and prints per-feature medians and 95th percentiles, plus raw segment-size stats.
This is a look at the data before any model exists; nothing here is a result about detection.

    python -m ids.spike --fleet '/captures/live/*.pcap' --legit /data/legit_slice.pcap \
        --flood /data/mqttset/pcap/capture_flood.pcap
"""

from __future__ import annotations

import argparse
import glob
import json
import re

import numpy as np
import pandas as pd

from ids.features import FEATURES, extract, packets

SHOW = ["pkts_up", "bytes_up", "data_pkts_up", "payload_up_mean", "payload_up_max",
        "iat_up_mean", "pkts_down", "bytes_ratio_up_down", "conns", "syn_up"]


FLEET_IP = re.compile(r"172\.28\.0\.1\d\d$")  # fleet devices only (not tests/evidence at .250)


def segment_sizes(paths, port, client_re=None):
    """TCP payload length of client->broker segments that carry payload (empty ACKs excluded)."""
    sizes = [plen for p in paths for (_, src, _, _, dp, _, plen, _) in packets(p)
             if plen and dp == port and (client_re is None or client_re.match(src))]
    a = np.array(sizes or [0])
    return {"segments": len(sizes), "min": int(a.min()), "median": float(np.median(a)),
            "p95": float(np.percentile(a, 95)), "max": int(a.max())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fleet", required=True, help="glob of fleet pcaps")
    ap.add_argument("--legit", required=True)
    ap.add_argument("--flood", required=True)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    fleet_paths = sorted(glob.glob(args.fleet))
    sources = {
        # Fleet devices only (172.28.0.101-199); drops the tests/evidence container.
        "fleet_benign_tls": (lambda df: df[df.client_ip.str.match(FLEET_IP.pattern)])(
            pd.DataFrame(extract(fleet_paths, broker_port=8883))),
        "mqttset_legit": pd.DataFrame(extract([args.legit], broker_port=1883)),
        "mqttset_flood": pd.DataFrame(extract([args.flood], broker_port=1883)),
    }
    print("windows (client x 5 s) per source:",
          {k: f"{len(v)} rows, {v.client_ip.nunique()} clients" for k, v in sources.items()})
    print("\nclient->broker TCP payload length, segments with payload only (empty ACKs excluded), bytes:")
    seg = {"fleet_benign_tls": segment_sizes(fleet_paths, 8883, FLEET_IP),
           "mqttset_legit": segment_sizes([args.legit], 1883),
           "mqttset_flood": segment_sizes([args.flood], 1883)}
    for k, v in seg.items():
        print(f"  {k:18} {v}")

    rows = []
    for feat in SHOW:
        row = {"feature": feat}
        for name, df in sources.items():
            row[f"{name} p50"] = df[feat].median()
            row[f"{name} p95"] = df[feat].quantile(0.95)
        rows.append(row)
    table = pd.DataFrame(rows).set_index("feature")
    with pd.option_context("display.width", 200, "display.max_columns", 20, "display.float_format", "{:.3g}".format):
        print("\nper-window feature distributions (p50 / p95):")
        print(table)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"segments": seg, "table": table.reset_index().to_dict(orient="records"),
                       "features": FEATURES}, fh, indent=2, default=float)


if __name__ == "__main__":
    main()
