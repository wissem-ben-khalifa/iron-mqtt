"""Train and evaluate the robust-feature models next to m0001 on the same test-B run.

Variants (all GradientBoostingClassifier, random_state=0, trained on train-A only):
  robust-all     the 19 MVP features + system-level/relative features
  robust-prefer  everything except the Part B "YES" (device-produced) features
  system-only    system-level features only, no per-source information at all; kept to
                 measure the attribution limit (it can tell THAT, not WHO)
m0001 is loaded unchanged from models/m0001.joblib.

Reports per model, on test-B (identical windows): P/R/F1, false alarms/hour, time from
attack start to the first flagged attack window, and the share of decision weight
(feature importance) by provenance class: YES / PARTIAL / SYSTEM.

    python -m ids.robust_model --train train-A --test test-B
Env: MONGO_URI (detector user: registers models), MONGO_ANALYST_URI (reads telemetry).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

from ids.evaluate import false_alarms_per_hour, metrics
from ids.features import FEATURES
from ids.labeling import label_run
from ids.robust_features import (FEATURE_CLASS, RELATIVE_FEATURES, ROBUST_FEATURES, SYSTEM_FEATURES,
                                 augment, capture_system_features, fleet_latency)
from services.common.db import connect, database

WINDOW_S = 5.0
VARIANTS = {
    "robust-all": ROBUST_FEATURES,
    "robust-prefer": [f for f in ROBUST_FEATURES if FEATURE_CLASS[f] != "YES"],
    "system-only": SYSTEM_FEATURES,
}


def load(run: str, root: Path, analyst_db) -> tuple[list[dict], dict]:
    run_dir = root / run
    manifest = json.loads((run_dir / "manifest.json").read_text())
    rows = label_run(run_dir, window_s=WINDOW_S)
    system = capture_system_features(run_dir / "run.pcap")
    lo = min(r["window_start"] for r in rows) - WINDOW_S
    hi = max(r["window_start"] for r in rows) + 2 * WINDOW_S
    return augment(rows, system, fleet_latency(analyst_db, lo, hi)), manifest


def matrix(rows, feats):
    X = np.array([[r[f] for f in feats] for r in rows], dtype=float)
    y = np.array([r["label"] == "attack" for r in rows], dtype=int)
    return X, y


def weight_shares(feats, importances) -> dict[str, float]:
    share = defaultdict(float)
    for f, v in zip(feats, importances):
        share[FEATURE_CLASS[f]] += float(v)
    return {k: round(share.get(k, 0.0), 4) for k in ("YES", "PARTIAL", "SYSTEM")}


def first_alert_delay(rows, pred, manifest) -> float | None:
    """Seconds from attack start until the end of the first attacker window flagged attack."""
    a = manifest["attacks"][0]
    start = datetime.fromisoformat(a["start"]).timestamp()
    hits = [r["window_start"] + WINDOW_S for r, p in zip(rows, pred)
            if p and r["client_ip"] == a["src_ip"] and r["window_start"] + WINDOW_S > start]
    return round(min(hits) - start, 2) if hits else None


def register(db, version, model, feats, train_rows, train_runs, models_dir: Path, note: str):
    """Register a model; idempotent per (variant, training runs) so re-runs do not duplicate."""
    existing = db.models.find_one({"params.variant": note, "trained_on.runs": train_runs})
    if existing:
        version = existing["_id"]
    path = models_dir / f"{version}.joblib"
    joblib.dump({"model": model, "features": feats, "algo": "gb", "window_s": WINDOW_S}, path)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if existing:
        db.models.update_one({"_id": version}, {"$set": {"artifact.sha256": sha}})
        return version
    db.models.insert_one({
        "_id": version, "created_at": datetime.now(timezone.utc), "algorithm": "gb",
        "params": {"window_s": WINDOW_S, "features": feats, "variant": note},
        "parent_version": "m0001",
        "trained_on": {"runs": train_runs, "n_windows": len(train_rows),
                       "n_attack": sum(r["label"] == "attack" for r in train_rows),
                       "window_ids": [f"{r['run']}:{r['client_ip']}:{int(r['window_start'])}" for r in train_rows],
                       "time_ranges": [{"run": train_runs[0], "min": min(r["window_start"] for r in train_rows),
                                        "max": max(r["window_start"] for r in train_rows)}],
                       "source": "fleet"},
        "metrics": {}, "artifact": {"path": str(path), "sha256": sha}, "active": False,
    })
    return version


WINDOW_VARIANTS = {
    "window: system-only": SYSTEM_FEATURES,
    "window: fleet-latency-only": ["fleet_latency_ms"],
}


def windows_of(rows):
    """One row per window: system-level features + label = any source attacking in it."""
    by = {}
    for r in rows:
        w = by.setdefault(r["window_start"], {**{f: r[f] for f in SYSTEM_FEATURES},
                                             "window_start": r["window_start"], "label": "benign",
                                             "client_ip": "*"})
        if r["label"] == "attack":
            w["label"] = "attack"
    return [by[k] for k in sorted(by)]


def window_level(db, train_rows, test_rows, manifest, train_run, models_dir) -> dict:
    """'Is an attack in progress?' from signals no single device sets, one decision per window."""
    wtr, wte = windows_of(train_rows), windows_of(test_rows)
    a = manifest["attacks"][0]
    start = datetime.fromisoformat(a["start"]).timestamp()
    print(f"\nwindow-level (attack in progress?): train {len(wtr)} windows "
          f"({sum(w['label'] == 'attack' for w in wtr)} attack), test {len(wte)} "
          f"({sum(w['label'] == 'attack' for w in wte)} attack)")
    print(f"{'model':32} {'prec':>6} {'rec':>6} {'f1':>6} {'fp':>4} {'fn':>4} {'FP/hr':>6} {'1st alert s':>11} "
          f"{'PARTIAL':>7} {'SYSTEM':>6}")
    out = {}
    for name, feats in WINDOW_VARIANTS.items():
        Xtr, ytr = matrix(wtr, feats)
        Xte, yte = matrix(wte, feats)
        model = GradientBoostingClassifier(random_state=0).fit(Xtr, ytr)
        version = register(db, f"m{db.models.count_documents({}) + 1:04d}", model, feats,
                           train_rows, [train_run], models_dir, name)
        pred = model.predict(Xte)
        m = metrics(yte, pred)
        hits = [w["window_start"] + WINDOW_S for w, p in zip(wte, pred) if p and w["window_start"] + WINDOW_S > start]
        delay = round(min(hits) - start, 2) if hits else None
        shares = weight_shares(feats, model.feature_importances_)
        lat = [w["fleet_latency_ms"] for w in wte]
        out[name] = {**m, "fp_per_hour": false_alarms_per_hour(pred, yte, WINDOW_S), "first_alert_s": delay,
                     "weight_share": shares, "version": version,
                     "top_features": {f: round(float(v), 4) for f, v in
                                      sorted(zip(feats, model.feature_importances_), key=lambda kv: -kv[1])[:4]}}
        print(f"{version + ' (' + name + ')':32} {m['precision']:6} {m['recall']:6} {m['f1']:6} {m['fp']:4} {m['fn']:4} "
              f"{out[name]['fp_per_hour']:6} {str(delay):>11} {shares['PARTIAL']:7} {shares['SYSTEM']:6}")
    for name, r in out.items():
        print(f"  {name}: {r['top_features']}")
    for lab in ("benign", "attack"):
        v = sorted(w["fleet_latency_ms"] for w in wte if w["label"] == lab)
        print(f"  test-B fleet_latency_ms in {lab} windows: min {v[0]:.2f} median {v[len(v)//2]:.2f} max {v[-1]:.2f} ms")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="train-A")
    ap.add_argument("--test", default="test-B")
    ap.add_argument("--runs-root", default="/captures/runs")
    ap.add_argument("--models-dir", default="/models")
    ap.add_argument("--baseline", default="/models/m0001.joblib")
    ap.add_argument("--json", default="/captures/runs/robust/robust-test-B.json")
    args = ap.parse_args()
    root, models_dir = Path(args.runs_root), Path(args.models_dir)
    db = database(connect())
    analyst = database(connect(os.environ["MONGO_ANALYST_URI"]))

    train_rows, _ = load(args.train, root, analyst)
    test_rows, test_manifest = load(args.test, root, analyst)
    print(f"train {args.train}: {len(train_rows)} windows | test {args.test}: {len(test_rows)} windows "
          f"({sum(r['label'] == 'attack' for r in test_rows)} attack)")

    models = {"m0001 (MVP)": (joblib.load(args.baseline)["model"], FEATURES, None)}
    for name, feats in VARIANTS.items():
        Xtr, ytr = matrix(train_rows, feats)
        model = GradientBoostingClassifier(random_state=0).fit(Xtr, ytr)
        version = register(db, f"m{db.models.count_documents({}) + 1:04d}", model, feats,
                           train_rows, [args.train], models_dir, name)
        models[f"{version} ({name})"] = (model, feats, version)

    report = {}
    print(f"\n{'model':24} {'prec':>6} {'rec':>6} {'f1':>6} {'fp':>4} {'fn':>4} {'FP/hr':>6} "
          f"{'1st alert s':>11} {'YES':>6} {'PARTIAL':>7} {'SYSTEM':>6}")
    for name, (model, feats, version) in models.items():
        Xte, yte = matrix(test_rows, feats)
        pred = model.predict(Xte)
        m = metrics(yte, pred)
        shares = weight_shares(feats, model.feature_importances_)
        delay = first_alert_delay(test_rows, pred, test_manifest)
        top = sorted(zip(feats, model.feature_importances_), key=lambda kv: -kv[1])[:5]
        report[name] = {**m, "fp_per_hour": false_alarms_per_hour(pred, yte, WINDOW_S),
                        "first_alert_s": delay, "weight_share": shares,
                        "top_features": {f: round(float(v), 4) for f, v in top}, "version": version}
        print(f"{name:24} {m['precision']:6} {m['recall']:6} {m['f1']:6} {m['fp']:4} {m['fn']:4} "
              f"{report[name]['fp_per_hour']:6} {str(delay):>11} {shares['YES']:6} {shares['PARTIAL']:7} {shares['SYSTEM']:6}")
    print("\ntop features per model:")
    for name, r in report.items():
        print(f"  {name}: {r['top_features']}")
    report["window_level"] = window_level(db, train_rows, test_rows, test_manifest, args.train, models_dir)
    Path(args.json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json).write_text(json.dumps(report, indent=2))
    print("\nROBUST MODEL: done")


if __name__ == "__main__":
    main()
