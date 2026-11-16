"""Evaluate the IDS and the threshold baseline on a held-out run, and report real numbers.

Loads a registered model, labels a TEST run (separate from training), and reports
precision / recall / F1 / confusion matrix for BOTH the ML model and the threshold rule,
fitted on the SAME training runs. Also runs a label-shuffle sanity check: a model trained
on shuffled labels must score near chance.

    python -m ids.evaluate --model m0001 --train train-A --test test-B
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from ids.baselines import ThresholdRule
from ids.labeling import label_run, to_xy
from ids.train import ALGOS, load_runs
from services.common.db import connect, database


def metrics(y, pred) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def false_alarms_per_hour(pred, y, window_s: float) -> float:
    benign = y == 0
    fp = int((pred[benign] == 1).sum())
    benign_hours = benign.sum() * window_s / 3600
    return round(fp / benign_hours, 2) if benign_hours else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--train", nargs="+", required=True, help="training run(s), to fit the threshold identically")
    ap.add_argument("--test", nargs="+", required=True)
    ap.add_argument("--runs-root", default="/captures/runs")
    args = ap.parse_args()

    db = database(connect())
    doc = db.models.find_one({"_id": args.model})
    if doc is None:
        raise SystemExit(f"no such model {args.model}")
    bundle = joblib.load(doc["artifact"]["path"])
    model, window_s = bundle["model"], bundle["window_s"]

    root = Path(args.runs_root)
    Xtr, ytr, _ = to_xy(load_runs(args.train, root, window_s))
    test_rows = load_runs(args.test, root, window_s)
    Xte, yte, _ = to_xy(test_rows)
    print(f"test runs {args.test}: {len(yte)} windows, {int(yte.sum())} attack / {int((yte==0).sum())} benign")

    ml_pred = model.predict(Xte)
    threshold = ThresholdRule().fit(Xtr, ytr)
    th_pred = threshold.predict(Xte)

    ml, th = metrics(yte, ml_pred), metrics(yte, th_pred)
    print(f"\n{'':10} {'precision':>9} {'recall':>7} {'f1':>6} {'tp':>4} {'fp':>4} {'fn':>4} {'tn':>5} {'FP/hr':>7}")
    for name, m, pred in [("ML " + bundle["algo"], ml, ml_pred), ("threshold", th, th_pred)]:
        print(f"{name:10} {m['precision']:9} {m['recall']:7} {m['f1']:6} {m['tp']:4} {m['fp']:4} "
              f"{m['fn']:4} {m['tn']:5} {false_alarms_per_hour(pred, yte, window_s):7}")
    print(f"threshold {ThresholdRule().feature} > {threshold.threshold_:.0f} bytes/window")

    # Sanity: a model trained on SHUFFLED labels must be near chance (F1 ~ attack prevalence-ish).
    rng = np.random.default_rng(0)
    shuffled = ALGOS[bundle["algo"]]()
    shuffled.fit(Xtr, rng.permutation(ytr))
    sm = metrics(yte, shuffled.predict(Xte))
    print(f"\nsanity (labels shuffled in training): f1={sm['f1']} recall={sm['recall']} "
          f"-- should be far below the real model's f1={ml['f1']}")

    print("\nEVALUATE: done")
    return {"ml": ml, "threshold": th, "shuffled_f1": sm["f1"],
            "threshold_value": threshold.threshold_,
            "fp_per_hour": {"ml": false_alarms_per_hour(ml_pred, yte, window_s),
                            "threshold": false_alarms_per_hour(th_pred, yte, window_s)}}


if __name__ == "__main__":
    main()
