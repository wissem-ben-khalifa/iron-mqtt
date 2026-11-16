"""Detector incident logic (round-1 UI review data bugs). Pure tests, plus one round trip
through MongoDB's real update semantics when the range is running."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from ids.features import FEATURES
from services.detector.logic import (WINDOW_S, chunk_start, complete_rows, extend_incident, ground_truth,
                                     new_incident, window_key)

T0 = datetime(2026, 10, 16, 14, 15, 40, tzinfo=timezone.utc).timestamp()  # a window start on the grid
FLOOD_START = T0 + 0.361                                                 # ground truth of the round-1 run


def row(start: float, payload: int, ip: str = "172.28.0.40") -> dict:
    r = {f: 0.0 for f in FEATURES}
    r.update({"client_ip": ip, "window_start": start, "payload_up": payload})
    return r


ATTACK = {"ml": True, "threshold_hit": True, "score": 1.0}
TAIL = {"ml": False, "threshold_hit": True, "score": 0.0131}  # the flood's last 0.36 s


def run(started: float) -> dict:
    return {"_id": "run-test", "attacks": [{"src_ip": "172.28.0.40", "started_at": datetime.fromtimestamp(started, timezone.utc),
                                            "planned_end": datetime.fromtimestamp(started + 30, timezone.utc), "rate_per_s": 2000.0}]}


# 1. merge keeps the peak score -------------------------------------------------------------
def test_merge_keeps_the_peak_score_not_the_last():
    upd = extend_incident(row(T0 + 30, 123_978), TAIL)
    assert upd["$max"]["detector.score"] == TAIL["score"]      # $max: a lower score cannot lower the peak
    assert "detector.score" not in upd["$set"]


# 2. the triggering window is kept ----------------------------------------------------------
def test_merge_never_overwrites_the_triggering_window_or_features():
    doc = new_incident(row(T0, 1_063_350), ATTACK, datetime.fromtimestamp(T0 + 7, timezone.utc), "m0001", 13737,
                       "/captures/live/x.pcap", None, FEATURES)
    assert doc["features"]["payload_up"] == 1_063_350 and doc["trigger"]["features"]["payload_up"] == 1_063_350
    upd = extend_incident(row(T0 + 30, 123_978), TAIL)
    touched = set(upd["$set"]) | set(upd["$max"]) | set(upd["$inc"])
    assert not {k for k in touched if k.startswith(("features", "trigger", "detected_at", "detection_latency_s"))}
    assert upd["$set"]["last_window"]["payload_up"] == 123_978  # the latest window is kept separately


def test_a_threshold_only_tail_does_not_demote_an_ml_incident():
    assert "kind" not in extend_incident(row(T0 + 30, 123_978), TAIL)["$set"]
    assert extend_incident(row(T0 + 5, 1_112_310), ATTACK)["$set"]["kind"] == "ml_flood"


# 3. detection latency from ground truth, never negative --------------------------------------
def test_latency_is_alert_time_minus_flood_start():
    truth = ground_truth([run(FLOOD_START)], "172.28.0.40", T0, T0 + WINDOW_S)
    detected = datetime.fromtimestamp(FLOOD_START + 7.4, timezone.utc)
    doc = new_incident(row(T0, 1_063_350), ATTACK, detected, "m0001", 13737, "x", truth, FEATURES)
    assert doc["detection_latency_s"] == pytest.approx(7.4)
    assert doc["window_close_s"] == pytest.approx(T0 + WINDOW_S - FLOOD_START)  # comparable to RESULTS first alert
    assert doc["ground_truth"]["run_id"] == "run-test"


def test_latency_is_unknown_without_a_run_and_never_negative():
    no_truth = new_incident(row(T0, 50_000, ip="172.28.0.110"), TAIL, datetime.now(timezone.utc), "m0001", 13737, "x",
                            ground_truth([run(FLOOD_START)], "172.28.0.110", T0, T0 + 5), FEATURES)
    assert no_truth["detection_latency_s"] is None and no_truth["ground_truth"] is None
    early = new_incident(row(T0, 1_063_350), ATTACK, datetime.fromtimestamp(FLOOD_START - 1.14, timezone.utc),
                         "m0001", 13737, "x", ground_truth([run(FLOOD_START)], "172.28.0.40", T0, T0 + 5), FEATURES)
    assert early["detection_latency_s"] is None and early["ground_truth"]["mismatch"] is True


# 3b. one score per window: windows merged == windows in the timeline ------------------------
def test_each_window_is_scored_once_on_complete_data():
    # Chunks start 2 s off the window grid, as in the real capture (:37, :42, :47).
    c37, c42, c47, c52 = (chunk_start(f"20261016T1415{s}.pcap") for s in ("37", "42", "47", "52"))
    emitted: set = set()
    seen = []
    for cover_from, cover_to in [(c37, c47), (c42, c52)]:  # [prev, current] joined, next chunk start = end
        rows = [row(s, 1) for s in (T0 - 5, T0, T0 + 5, T0 + 10)]
        for r in complete_rows(rows, cover_from, cover_to, emitted):
            emitted.add(window_key(r))
            seen.append(r["window_start"])
    assert seen == [T0, T0 + 5]                      # :40 then :45, each once
    assert len(seen) == len(set(seen))               # no double scoring, so counts match the timeline


@pytest.mark.skipif("MONGO_DETECTOR_URI" not in os.environ, reason="needs the running range")
def test_mongodb_round_trip_keeps_peak_score_and_trigger():
    from services.common.db import connect, database
    db = database(connect(os.environ["MONGO_DETECTOR_URI"]))
    truth = ground_truth([run(FLOOD_START)], "172.28.0.40", T0, T0 + WINDOW_S)
    doc = new_incident(row(T0, 1_063_350), ATTACK, datetime.fromtimestamp(FLOOD_START + 7.4, timezone.utc),
                       "m0001", 13737, "x", truth, FEATURES)
    doc["kind"] = "test"  # self-test incident: excluded from analytics and the console feed
    _id = db.incidents.insert_one(doc).inserted_id
    for start, verdict, payload in [(T0 + 5, ATTACK, 1_112_310), (T0 + 30, TAIL, 123_978)]:
        upd = extend_incident(row(start, payload), verdict)
        upd["$set"].pop("kind", None)
        db.incidents.update_one({"_id": _id}, upd)
    got = db.incidents.find_one({"_id": _id})
    assert got["detector"]["score"] == 1.0
    assert got["features"]["payload_up"] == 1_063_350
    assert got["last_window"]["payload_up"] == 123_978
    assert got["windows"] == 3 and got["windows_ml"] == 2 and got["windows_threshold_only"] == 1
    assert got["detection_latency_s"] == pytest.approx(7.4)
