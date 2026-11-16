"""Pure incident logic for the live detector, kept free of I/O so it can be unit-tested.

Three rules fixed after the round-1 UI review (each has a test in tests/test_detector_logic.py):

1. Score a window once, on complete data. The sensor rotates capture chunks every 5 s but
   not on the 5 s window grid (chunks start at :32, :37, ... while windows start at :30, :35),
   so every window spans two chunks. Scoring each chunk on its own scored every window twice,
   on 2 s and 3 s fragments. Windows are now extracted from the previous and the current
   chunk together and emitted only when they lie entirely inside what those chunks cover.
2. Merging a window into an open incident never overwrites what raised it: the triggering
   window and its features are fixed at creation, the score kept is the peak, and the
   latest window is recorded separately.
3. Detection latency is defined from ground truth: alert raised time minus the flood start
   recorded in the `runs` collection. Without a matching run it is unknown (None), and a
   negative value is treated as a ground-truth mismatch, never stored as a latency.
"""

from __future__ import annotations

from datetime import datetime, timezone

WINDOW_S = 5.0
INCIDENT_GAP_S = 15.0       # same source within this gap extends the open incident
MAX_CHUNK_GAP_S = 6.0       # previous chunk is only joined when it is contiguous
RUN_GRACE_S = 10.0          # a window up to this long after a run's end still belongs to it


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def chunk_start(name: str) -> float:
    """Start time of a capture chunk from its file name (YYYYmmddTHHMMSS.pcap, UTC)."""
    return datetime.strptime(name[:15], "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).timestamp()


def window_key(row: dict) -> tuple[str, int]:
    return row["client_ip"], int(row["window_start"])


def complete_rows(rows: list[dict], covered_from: float, covered_to: float, emitted: set) -> list[dict]:
    """Rows whose whole window lies inside [covered_from, covered_to] and was not emitted yet,
    in time order."""
    out = [r for r in rows
           if r["window_start"] >= covered_from
           and r["window_start"] + WINDOW_S <= covered_to
           and window_key(r) not in emitted]
    return sorted(out, key=lambda r: (r["window_start"], r["client_ip"]))


def ground_truth(runs: list[dict], src_ip: str, win_start: float, win_end: float) -> dict | None:
    """The recorded flood run (ground truth) that this window belongs to, if any."""
    best = None
    for run in runs:
        for a in run.get("attacks", []):
            if a.get("src_ip") != src_ip or not a.get("started_at"):
                continue
            start = a["started_at"].timestamp()
            end_dt = a.get("ended_at") or a.get("planned_end")
            end = (end_dt.timestamp() if end_dt else win_end) + RUN_GRACE_S
            if start <= win_end and win_start <= end and (best is None or start > best["started"]):
                best = {"run_id": run["_id"], "started": start, "rate_per_s": a.get("rate_per_s")}
    return best


def new_incident(row: dict, verdict: dict, detected_at: datetime, model_version: str,
                 threshold: float, pcap: str, truth: dict | None, features: list[str]) -> dict:
    start, end = row["window_start"], row["window_start"] + WINDOW_S
    trigger_features = {f: row[f] for f in features}
    latency = close = None
    gt = None
    if truth:
        latency = (detected_at.timestamp() - truth["started"])
        close = end - truth["started"]
        gt = {"run_id": truth["run_id"], "flood_started_at": utc(truth["started"]),
              "rate_per_s": truth["rate_per_s"]}
        if latency < 0:  # the alert cannot precede the flood: ground truth does not match
            gt["mismatch"] = True
            latency = close = None
    return {
        "detected_at": detected_at,
        "kind": "ml_flood" if verdict["ml"] else "threshold_flood",
        "status": "open",
        "source": {"src_ip": row["client_ip"], "device_id": None},
        "window": {"start": utc(start), "end": utc(end)},
        "detector": {"name": "live", "model_version": model_version, "score": verdict["score"],
                     "threshold": threshold, "ml": bool(verdict["ml"]),
                     "threshold_hit": bool(verdict["threshold_hit"])},
        "trigger": {"window_start": utc(start), "window_end": utc(end), "score": verdict["score"],
                    "ml": bool(verdict["ml"]), "threshold_hit": bool(verdict["threshold_hit"]),
                    "features": trigger_features},
        "features": trigger_features,
        "windows": 1,
        "windows_ml": int(bool(verdict["ml"])),
        "windows_threshold_only": int(bool(verdict["threshold_hit"]) and not verdict["ml"]),
        "evidence": {"pcap": pcap},
        "ground_truth": gt,
        "detection_latency_s": latency,
        "window_close_s": close,
        "run_id": gt["run_id"] if gt else None,
    }


def extend_incident(row: dict, verdict: dict) -> dict:
    """MongoDB update for a window merged into an open incident. Never touches the trigger,
    the features, the detection time or the latency."""
    start, end = row["window_start"], row["window_start"] + WINDOW_S
    update = {
        "$max": {"window.end": utc(end), "detector.score": verdict["score"]},
        "$inc": {"windows": 1, "windows_ml": int(bool(verdict["ml"])),
                 "windows_threshold_only": int(bool(verdict["threshold_hit"]) and not verdict["ml"])},
        "$set": {"last_window": {"start": utc(start), "end": utc(end), "score": verdict["score"],
                                 "ml": bool(verdict["ml"]), "threshold_hit": bool(verdict["threshold_hit"]),
                                 "payload_up": row.get("payload_up")}},
    }
    if verdict["ml"]:  # an incident is ML-detected once any of its windows is
        update["$set"].update({"kind": "ml_flood", "detector.ml": True})
    return update


def merge_target_since(row: dict) -> datetime:
    """Open incidents whose last window ended after this time are extended, not duplicated."""
    return utc(row["window_start"] - INCIDENT_GAP_S)


def prune(emitted: set, before: float) -> None:
    for key in [k for k in emitted if k[1] < before]:
        emitted.discard(key)


def contiguous(prev_name: str | None, name: str) -> bool:
    return prev_name is not None and 0 < chunk_start(name) - chunk_start(prev_name) <= MAX_CHUNK_GAP_S

