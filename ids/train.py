"""Train the supervised IDS on labelled runs and register the model (with lineage) in MongoDB.

Supervised gradient-boosting classifier on the TLS-visible flow features. Trains on one or
more runs, writes the model to models/ (gitignored), and records a versioned document in the
`models` collection with the exact windows it was trained on (ids + time ranges) — the model
lineage the poisoning work (core tier) needs.

    python -m ids.train --runs train-A [train-C ...] --algo gb
"""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier

from ids.features import FEATURES
from ids.labeling import label_run, to_xy
from services.common.db import connect, database

MODELS_DIR = Path(os.environ.get("MODELS_DIR", "/models"))
ALGOS = {
    "gb": lambda: GradientBoostingClassifier(random_state=0),
    "rf": lambda: RandomForestClassifier(n_estimators=200, random_state=0, class_weight="balanced"),
}


def load_runs(names: list[str], runs_root: Path, window_s: float):
    rows = []
    for name in names:
        rows += label_run(runs_root / name, window_s=window_s)
    return rows


def next_version(db) -> str:
    n = db.models.count_documents({})
    return f"m{n + 1:04d}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--algo", choices=list(ALGOS), default="gb")
    ap.add_argument("--window-s", type=float, default=5.0)
    ap.add_argument("--runs-root", default="/captures/runs")
    ap.add_argument("--register/--no-register", dest="register", default=True, action=argparse.BooleanOptionalAction)
    args = ap.parse_args()

    rows = load_runs(args.runs, Path(args.runs_root), args.window_s)
    X, y, meta = to_xy(rows)
    print(f"training on {len(args.runs)} run(s): {X.shape[0]} windows, "
          f"{int(y.sum())} attack / {int((y == 0).sum())} benign, {X.shape[1]} features")
    if y.sum() == 0 or (y == 0).sum() == 0:
        raise SystemExit("need both benign and attack windows to train")

    model = ALGOS[args.algo]()
    model.fit(X, y)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    db = database(connect())
    version = next_version(db)
    path = MODELS_DIR / f"{version}.joblib"
    joblib.dump({"model": model, "features": FEATURES, "algo": args.algo, "window_s": args.window_s}, path)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()

    window_ids = [f"{m['run']}:{m['client_ip']}:{int(m['window_start'])}" for m in meta]
    time_ranges = [{"run": r, "min": min(m["window_start"] for m in meta if m["run"] == r),
                    "max": max(m["window_start"] for m in meta if m["run"] == r)} for r in args.runs]
    importances = dict(sorted(zip(FEATURES, model.feature_importances_.tolist()),
                              key=lambda kv: -kv[1]))

    if args.register:
        db.models.insert_one({
            "_id": version, "created_at": datetime.now(timezone.utc), "algorithm": args.algo,
            "params": {"window_s": args.window_s},
            "parent_version": None,
            "trained_on": {"runs": args.runs, "window_ids": window_ids, "time_ranges": time_ranges,
                           "n_windows": len(window_ids), "n_attack": int(y.sum()), "source": "fleet"},
            "metrics": {"train_attack": int(y.sum()), "train_benign": int((y == 0).sum())},
            "artifact": {"path": str(path), "sha256": sha},
            "active": False,
        })
    print(f"saved model {version} -> {path} (sha256 {sha[:12]})")
    print("top features:", {k: round(v, 3) for k, v in list(importances.items())[:6]})
    print(f"registered in MongoDB: {args.register}")
    return version


if __name__ == "__main__":
    main()
