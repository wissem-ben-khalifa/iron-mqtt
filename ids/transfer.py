"""M6 transfer test: does an IDS trained on one source work on the other?

Tests the hypothesis (not a claim) that published 98%+ MQTTset scores come largely from
separating its 32 KB flood from perfectly periodic benign traffic — an easy, non-transferable
split. Builds labelled window sets for both sources with the SAME extractor and compares:

  within-fleet     : train fleet runs, test a held-out fleet run
  within-mqttset   : train on half of MQTTset, test on the other half
  fleet  -> mqttset: train fleet, test MQTTset
  mqttset-> fleet  : train MQTTset, test fleet

MQTTset labelled set: benign = legitimate slice (port 1883, all clients benign);
attack = capture_flood (port 1883, the single attacker 192.168.1.100).

    python -m ids.transfer
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import precision_recall_fscore_support

from ids.features import FEATURES, extract
from ids.labeling import label_run, to_xy


def fleet_xy(runs, root):
    rows = []
    for r in runs:
        rows += label_run(root / r)
    return to_xy(rows)[:2]


def mqttset_xy(legit_pcap, flood_pcap):
    benign = extract([legit_pcap], broker_port=1883)
    attack = extract([flood_pcap], broker_port=1883)
    rows = [{**r, "label": "benign"} for r in benign] + [{**r, "label": "attack"} for r in attack]
    X = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
    y = np.array([1 if r["label"] == "attack" else 0 for r in rows], dtype=int)
    return X, y


def f1_of(Xtr, ytr, Xte, yte):
    m = GradientBoostingClassifier(random_state=0).fit(Xtr, ytr)
    p, r, f1, _ = precision_recall_fscore_support(yte, m.predict(Xte), average="binary", zero_division=0)
    return round(p, 3), round(r, 3), round(f1, 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-root", default="/captures/runs")
    ap.add_argument("--legit", default="/data/mqttset/slices/legit_first300k.pcap")
    ap.add_argument("--flood", default="/data/mqttset/pcap/capture_flood.pcap")
    args = ap.parse_args()
    root = Path(args.runs_root)

    Xf_tr, yf_tr = fleet_xy(["train-A"], root)
    Xf_te, yf_te = fleet_xy(["test-B"], root)
    Xm, ym = mqttset_xy(args.legit, args.flood)
    # split MQTTset into halves for the within-source baseline
    rng = np.random.default_rng(0)
    idx = rng.permutation(len(ym))
    half = len(idx) // 2
    Xm_tr, ym_tr = Xm[idx[:half]], ym[idx[:half]]
    Xm_te, ym_te = Xm[idx[half:]], ym[idx[half:]]

    print(f"fleet: train {len(yf_tr)} ({int(yf_tr.sum())} atk) / test {len(yf_te)} ({int(yf_te.sum())} atk)")
    print(f"mqttset: {len(ym)} windows ({int(ym.sum())} atk)")
    print(f"\n{'setting':22} {'precision':>9} {'recall':>7} {'f1':>6}")
    for name, (Xtr, ytr, Xte, yte) in {
        "within-fleet": (Xf_tr, yf_tr, Xf_te, yf_te),
        "within-mqttset": (Xm_tr, ym_tr, Xm_te, ym_te),
        "fleet -> mqttset": (Xf_tr, yf_tr, Xm, ym),
        "mqttset -> fleet": (Xm, ym, Xf_te, yf_te),
    }.items():
        p, r, f1 = f1_of(Xtr, ytr, Xte, yte)
        print(f"{name:22} {p:9} {r:7} {f1:6}")
    print("\nTRANSFER: done")


if __name__ == "__main__":
    main()
