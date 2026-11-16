"""Turn a run's pcap + manifest into labelled feature rows.

Labels come ONLY from the run manifest (ground truth: attacker IP + attack time windows),
never from any model. A feature window (client_ip, window_start) is labelled:
  - "attack"  if client_ip is an attacker IP and the window overlaps an attack interval,
  - "benign"  otherwise.
The client IP is used only to join the label; it is dropped from the feature matrix.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ids.features import FEATURES, extract


def _parse(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()


def label_run(run_dir: str | Path, window_s: float = 5.0) -> list[dict]:
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    pcap = run_dir / "run.pcap"
    intervals = [(a["src_ip"], _parse(a["start"]), _parse(a["end"])) for a in manifest["attacks"]]

    rows = extract([pcap], broker_port=manifest.get("broker_port", 8883), window_s=window_s)
    labelled = []
    for row in rows:
        ip, start, end = row["client_ip"], row["window_start"], row["window_start"] + window_s
        is_attack = any(aip == ip and start < a_end and end > a_start
                        for aip, a_start, a_end in intervals)
        labelled.append({**row, "label": "attack" if is_attack else "benign",
                         "run": manifest["name"], "profile_version": manifest.get("profile_version")})
    return labelled


def to_xy(rows: list[dict]):
    """Return (X, y, meta) with X restricted to FEATURES and y in {0,1} (1 = attack)."""
    import numpy as np
    X = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
    y = np.array([1 if r["label"] == "attack" else 0 for r in rows], dtype=int)
    meta = [{"client_ip": r["client_ip"], "window_start": r["window_start"],
             "run": r.get("run"), "label": r["label"]} for r in rows]
    return X, y, meta
