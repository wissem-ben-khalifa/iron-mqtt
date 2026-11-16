"""System-level features for the robust-feature model (core tier, defensive feature engineering).

Adds signals that a single compromised device cannot set directly, joined onto the same
per-(client, 5 s window) rows as ids/features.py:

Broker fan-out / aggregate distribution (from the capture, broker side):
  fanout_payload   bytes the broker forwards to the ingest subscriber in the window
  ingest_rwnd_min  smallest TCP receive window ingest advertises to the broker (backpressure)
  ingest_zero_win  ACKs from ingest advertising a zero window
  fleet_up_payload total upstream payload of all sources in the window
  active_sources   sources sending payload in the window
  share_up         this source's share of fleet_up_payload

Collateral impact on honest devices (from MongoDB telemetry, the M5 measurement):
  fleet_latency_ms median over devices of each device's median end-to-end latency in the
                   window, using only messages that carry a genuine device envelope (boot/seq).
                   One device contributes one of ~10 per-device medians, so it cannot move the
                   median on its own (50% breakdown point). Windows with no messages carry the
                   previous value forward, as a live detector would.

FEATURE_CLASS records each feature's provenance class from docs/FEATURES.md (Part B):
YES = produced by the source device itself; PARTIAL = shifted by it but set elsewhere;
SYSTEM = produced by the broker, the ingest stack or other devices.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import dpkt

from ids.features import FEATURES, _addr, _ip_layer

BROKER_IP, BROKER_PORT, INGEST_IP = "172.28.0.10", 8883, "172.28.0.20"
WINDOW_S = 5.0

SYSTEM_FEATURES = ["fanout_payload", "ingest_rwnd_min", "ingest_zero_win", "fleet_up_payload",
                   "active_sources", "fleet_latency_ms"]
RELATIVE_FEATURES = ["share_up"]
ROBUST_FEATURES = FEATURES + SYSTEM_FEATURES + RELATIVE_FEATURES

_YES = {"payload_up", "iat_up_min", "payload_up_std", "data_pkts_up", "bytes_up", "pkts_up",
        "payload_up_mean", "payload_up_max", "iat_up_mean", "iat_up_std", "active_s",
        "syn_up", "fin_up", "conns"}
FEATURE_CLASS = {f: ("YES" if f in _YES else "PARTIAL") for f in FEATURES}
FEATURE_CLASS.update({
    "share_up": "PARTIAL",           # own volume / fleet volume: numerator is the device's
    "fleet_up_payload": "PARTIAL",   # sum over all sources; one device adds to it
    "fanout_payload": "PARTIAL",     # broker-produced, but scales with what is published
    "active_sources": "SYSTEM",      # how many other sources are talking
    "ingest_rwnd_min": "SYSTEM",     # ingest's TCP stack (an effect of load)
    "ingest_zero_win": "SYSTEM",
    "fleet_latency_ms": "SYSTEM",    # other devices' latency, median-of-medians
})


def _win(ts: float) -> float:
    return math.floor(ts / WINDOW_S) * WINDOW_S


def capture_system_features(pcap: str | Path) -> dict[float, dict]:
    """Per-window broker fan-out and ingest backpressure from one pcap."""
    out: dict[float, dict] = defaultdict(lambda: {"fanout_payload": 0, "ingest_rwnd_min": None,
                                                  "ingest_zero_win": 0, "fleet_up_payload": 0,
                                                  "_up_by_src": defaultdict(int)})
    with open(pcap, "rb") as fh:
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
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            src, dst, w = _addr(ip.src), _addr(ip.dst), out[_win(float(ts))]
            if src == BROKER_IP and tcp.sport == BROKER_PORT and dst == INGEST_IP:
                w["fanout_payload"] += len(tcp.data)
            elif dst == BROKER_IP and tcp.dport == BROKER_PORT:
                if src == INGEST_IP:
                    # Raw advertised window (scale factor is constant per connection).
                    w["ingest_rwnd_min"] = tcp.win if w["ingest_rwnd_min"] is None else min(w["ingest_rwnd_min"], tcp.win)
                    w["ingest_zero_win"] += int(tcp.win == 0 and not tcp.flags & dpkt.tcp.TH_RST)
                elif tcp.data:
                    w["fleet_up_payload"] += len(tcp.data)
                    w["_up_by_src"][src] += len(tcp.data)
    for w in out.values():
        w["active_sources"] = len(w.pop("_up_by_src"))
    return dict(out)


def fleet_latency(db, start: float, end: float) -> dict[float, float]:
    """Per-window median-of-device-medians latency from genuine device envelopes."""
    per = defaultdict(lambda: defaultdict(list))
    q = {"recv_ts": {"$gte": datetime.fromtimestamp(start, timezone.utc),
                     "$lt": datetime.fromtimestamp(end, timezone.utc)},
         "boot": {"$ne": None}}
    for d in db.telemetry.find(q, {"meta.device_id": 1, "latency_ms": 1, "recv_ts": 1}):
        per[_win(d["recv_ts"].timestamp())][d["meta"]["device_id"]].append(d["latency_ms"])
    return {w: statistics.median(statistics.median(v) for v in devs.values()) for w, devs in per.items()}


def augment(rows: list[dict], system: dict[float, dict], latency: dict[float, float]) -> list[dict]:
    """Join system-level features onto per-client rows; carry latency/rwnd forward when missing."""
    last_lat, last_rwnd = None, None
    filled_lat, filled_rwnd = {}, {}
    for w in sorted(set(system) | set(latency) | {r["window_start"] for r in rows}):
        last_lat = latency.get(w, last_lat)
        r = (system.get(w) or {}).get("ingest_rwnd_min")
        last_rwnd = r if r is not None else last_rwnd
        filled_lat[w], filled_rwnd[w] = last_lat, last_rwnd
    out = []
    for row in rows:
        w = row["window_start"]
        s = system.get(w, {})
        total = s.get("fleet_up_payload", 0)
        out.append({**row,
                    "fanout_payload": s.get("fanout_payload", 0),
                    "ingest_rwnd_min": filled_rwnd[w] if filled_rwnd[w] is not None else 0,
                    "ingest_zero_win": s.get("ingest_zero_win", 0),
                    "fleet_up_payload": total,
                    "active_sources": s.get("active_sources", 0),
                    "fleet_latency_ms": filled_lat[w] if filled_lat[w] is not None else 0.0,
                    "share_up": row["payload_up"] / total if total else 0.0})
    return out
