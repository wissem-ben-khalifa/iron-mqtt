"""Live detector (M7): watch capture chunks, score windows, write incidents to MongoDB.

Loop:
  1. Pick up completed pcap chunks from captures/live (the sensor rotates one every 5 s).
  2. Extract per-source windows (ids/features) from the previous and the current chunk
     together, and score only windows that are complete (chunks are not aligned to the
     5 s window grid, so a window always spans two chunks). Each window is scored once.
  3. Score with the active model AND the threshold rule; persist the window with its verdict.
  4. For a window flagged attack, open or extend an incident (one per ongoing attack per
     source). The triggering window is fixed at creation; merges keep the peak score.
  5. A separate simple rule flags "a device's cert identity seen from a new IP" (kept out of
     the ML evaluation): raised as its own incident kind.

Detection latency = alert raised time minus the flood start recorded in `runs` (ground
truth); see services/detector/logic.py.

Env: MONGO_URI (detector user), MODEL_VERSION (default: the active model, else newest),
CAPTURE_DIR (/captures/live), BROKER_PORT (8883).
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import joblib
import numpy as np

from ids.baselines import ThresholdRule
from ids.features import FEATURES, extract
from services.common.db import connect, database
from services.detector.logic import (WINDOW_S, chunk_start, complete_rows, contiguous, extend_incident,
                                     ground_truth, merge_target_since, new_incident, prune, utc, window_key)

log = logging.getLogger("detector")
CAPTURE_DIR = Path(os.environ.get("CAPTURE_DIR", "/captures/live"))
BROKER_PORT = int(os.environ.get("BROKER_PORT", "8883"))

class Detector:
    def __init__(self):
        self.db = database(connect())
        self.model_doc = self._load_model()
        bundle = joblib.load(self.model_doc["artifact"]["path"])
        self.model = bundle["model"]
        self.version = self.model_doc["_id"]
        self.threshold = self._fit_threshold()
        self.seen_ip_for_device: dict[str, set[str]] = {}
        # A live detector starts from "now": treat every chunk already on disk as handled,
        # so startup does not re-score the whole capture history.
        existing = sorted(CAPTURE_DIR.glob("*.pcap"))
        self.done: set[str] = {c.name for c in existing}
        self.prev: Path | None = existing[-2] if len(existing) >= 2 else None  # newest closed chunk
        self.emitted: set[tuple[str, int]] = set()
        log.info("skipping %d pre-existing chunks; watching for new ones", len(self.done))
        log.info("detector up: model %s, threshold payload_up>%.0f", self.version, self.threshold.threshold_)

    def _load_model(self):
        doc = (self.db.models.find_one({"active": True})
               or self.db.models.find_one(sort=[("created_at", -1)]))
        want = os.environ.get("MODEL_VERSION")
        if want:
            doc = self.db.models.find_one({"_id": want}) or doc
        if doc is None:
            raise SystemExit("no model registered; run ids.train first")
        return doc

    def _fit_threshold(self) -> ThresholdRule:
        # Refit the threshold from the model's own training windows would need the pcaps;
        # instead use the value the training run implied, stored on evaluation, or a default.
        rule = ThresholdRule()
        rule.threshold_ = float(os.environ.get("THRESHOLD_PAYLOAD_UP", "13737"))
        return rule

    def run_once(self) -> int:
        """Process any completed chunks (all but the newest, which the sensor may still write)."""
        chunks = sorted(CAPTURE_DIR.glob("*.pcap"))
        processed = 0
        for i, chunk in enumerate(chunks[:-1]):
            if chunk.name in self.done:
                continue
            # This chunk covers [its start, the next chunk's start).
            self._process(chunk, covered_to=chunk_start(chunks[i + 1].name))
            self.done.add(chunk.name)
            self.prev = chunk
            processed += 1
        return processed

    def _process(self, chunk: Path, covered_to: float) -> None:
        detected = utc(time.time())
        joined = self.prev is not None and contiguous(self.prev.name, chunk.name)
        files = [self.prev, chunk] if joined else [chunk]
        covered_from = chunk_start(files[0].name)
        try:
            rows = extract(files, broker_port=BROKER_PORT, window_s=WINDOW_S)
        except Exception as exc:  # a half-written chunk: skip, it will not be retried
            log.warning("skipping %s: %s", chunk.name, exc)
            return
        rows = complete_rows(rows, covered_from, covered_to, self.emitted)
        prune(self.emitted, covered_from - 60)
        for row in rows:
            self.emitted.add(window_key(row))
            x = [[row[f] for f in FEATURES]]
            ml = int(self.model.predict(x)[0])
            score = float(self.model.predict_proba(x)[0][1]) if hasattr(self.model, "predict_proba") else float(ml)
            th = int(self.threshold.predict(np.array(x))[0])
            win_end = row["window_start"] + WINDOW_S
            self.db.windows.update_one(
                {"_id": f"{row['client_ip']}:{int(row['window_start'])}"},
                {"$set": {"src_ip": row["client_ip"], "start": utc(row["window_start"]), "end": utc(win_end),
                          "features": {f: row[f] for f in FEATURES},
                          "verdict": {"model_version": self.version, "label": "attack" if ml else "benign",
                                      "score": score}}},
                upsert=True)
            self._new_ip_rule(row, detected)
            if ml or th:
                self._raise_incident(row, {"ml": bool(ml), "threshold_hit": bool(th), "score": score},
                                     chunk, detected)

    def _new_ip_rule(self, row, detected) -> None:
        """Flag a device identity appearing from a new IP. Separate from the ML evaluation."""
        ip = row["client_ip"]
        # Device IPs are 172.28.0.101-110; map by last octet to device id for the registry check.
        last = ip.rsplit(".", 1)[-1]
        if not (ip.startswith("172.28.0.1") and last.isdigit() and 101 <= int(last) <= 110):
            return
        device_id = f"device-{int(last) - 100:02d}"
        known = self.seen_ip_for_device.setdefault(device_id, set())
        if ip not in known and known:
            self.db.incidents.insert_one({
                "detected_at": detected, "kind": "new_ip_for_cert", "status": "open",
                "source": {"src_ip": ip, "device_id": device_id},
                "detector": {"name": "new_ip_rule"}, "features": {}, "run_id": None})
        known.add(ip)

    def _raise_incident(self, row, verdict, chunk, detected) -> None:
        ip = row["client_ip"]
        recent = self.db.incidents.find_one(
            {"source.src_ip": ip, "kind": {"$in": ["ml_flood", "threshold_flood"]},
             "window.end": {"$gte": merge_target_since(row)}},
            sort=[("window.end", -1)])
        if recent:
            self.db.incidents.update_one({"_id": recent["_id"]}, extend_incident(row, verdict))
            return
        win_end = utc(row["window_start"] + WINDOW_S)
        runs = list(self.db.runs.find({"attacks.src_ip": ip, "attacks.started_at": {"$lte": win_end}},
                                      {"attacks": 1}).sort("started_at", -1).limit(5))
        truth = ground_truth(runs, ip, row["window_start"], row["window_start"] + WINDOW_S)
        doc = new_incident(row, verdict, detected, self.version, self.threshold.threshold_,
                           str(chunk), truth, FEATURES)
        self.db.incidents.insert_one(doc)
        lat = doc["detection_latency_s"]
        log.info("incident: %s from %s (score %.2f, %s)", doc["kind"], ip, verdict["score"],
                 f"{lat:.1f}s after flood start" if lat is not None else "no ground-truth run")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    detector = Detector()
    poll = float(os.environ.get("POLL_S", "2"))
    while True:
        n = detector.run_once()
        time.sleep(poll if n == 0 else 0.2)


if __name__ == "__main__":
    main()
