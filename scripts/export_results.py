#!/usr/bin/env python3
"""Export the committed detector-comparison results to docs/results/summary.json.

The raw evaluation outputs live in captures/ (gitignored, regenerable). This script copies
the numbers the console shows into one committed, machine-readable file, with provenance,
so the UI never hardcodes a number and the served data is exactly what docs/RESULTS.md reports.

    python3 scripts/export_results.py          # stdlib only, runs on the host
Sources:
    captures/runs/suricata/compare-test-B.json          (./iron suricata, encryption-handling full)
    captures/runs/suricata/compare-test-B-default.json  (same, Suricata default track-only)
    captures/runs/robust/robust-test-B.json             (./iron robust)
    captures/runs/test-B/manifest.json                  (the test run itself)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "captures" / "runs"
OUT = ROOT / "docs" / "results" / "summary.json"

METRICS = ("precision", "recall", "f1", "tp", "fp", "fn", "tn", "fp_per_hour")


def pick(row: dict, *extra: str) -> dict:
    return {k: row.get(k) for k in METRICS + extra}


def main():
    full = json.loads((RUNS / "suricata" / "compare-test-B.json").read_text())["table"]
    default = json.loads((RUNS / "suricata" / "compare-test-B-default.json").read_text())["table"]
    robust = json.loads((RUNS / "robust" / "robust-test-B.json").read_text())
    window = robust.pop("window_level")
    manifest = json.loads((RUNS / "test-B" / "manifest.json").read_text())
    attack = manifest["attacks"][0]
    ml = full["ML (gradient boosting)"]
    windows = ml["tp"] + ml["fp"] + ml["fn"] + ml["tn"]
    threshold_name = next(k for k in full if k.startswith("threshold"))

    detectors = [
        {"id": "ml", "name": "ML model m0001 (gradient boosting)", "family": "ml", **pick(ml)},
        {"id": "threshold", "name": threshold_name.replace("threshold ", "Threshold rule, "), "family": "threshold",
         **pick(full[threshold_name])},
        {"id": "suricata-default", "name": "Suricata, default TLS handling (track-only)", "family": "suricata",
         **pick(default["Suricata all rules"])},
        {"id": "suricata-full", "name": "Suricata, all rules, full inspection", "family": "suricata",
         **pick(full["Suricata all rules"])},
        {"id": "suricata-rate", "name": "Suricata rate rule only, full inspection", "family": "suricata",
         **pick(full["Suricata rate rule"])},
        {"id": "suricata-fingerprint", "name": "Suricata JA4/JA3 rules only", "family": "suricata",
         **pick(full["Suricata JA4/JA3 rules"])},
    ]
    robust_rows = []
    for name, row in list(robust.items()) + list(window.items()):
        robust_rows.append({
            "id": row.get("version") or "m0001", "name": name,
            "granularity": "window" if name.startswith("window:") else "source",
            **pick(row, "first_alert_s"), "weight_share": row["weight_share"],
            "top_features": row.get("top_features", {})})

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "test_run": {"name": manifest["name"], "profile_version": manifest.get("profile_version"),
                     "attack_rate_per_s": attack["rate_per_s"], "attack_qos": attack.get("qos"),
                     "windows": windows, "attack_windows": ml["tp"] + ml["fn"], "window_s": 5,
                     "trained_on": "train-A"},
        "detectors": {"title": "Same test-B run, identical windows", "command": "./iron suricata",
                      "source": "captures/runs/suricata/compare-test-B*.json", "rows": detectors},
        "robust_models": {"title": "Robust-feature models on test-B", "command": "./iron robust",
                          "source": "captures/runs/robust/robust-test-B.json", "rows": robust_rows,
                          "weight_classes": {
                              "YES": "produced by the source device itself",
                              "PARTIAL": "shifted by the device but set elsewhere",
                              "SYSTEM": "produced by the broker, ingest or other devices"}},
        "reference": "docs/RESULTS.md (Core A and Core sections)",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(detectors)} detectors, {len(robust_rows)} robust rows")


if __name__ == "__main__":
    main()
