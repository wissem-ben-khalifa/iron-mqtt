"""Attacker agent ground-truth start time (regression test for a real bug:
a second flood reported the FIRST flood's started_at, so incidents had no matching run)."""

from __future__ import annotations

import time

from services.attacker.__main__ import Flood


def test_second_flood_reports_its_own_start_time(monkeypatch):
    flood = Flood()

    def fake_run(self, rate_per_s, duration_s, qos, payload_bytes):
        time.sleep(0.2)  # the real _run spends time connecting over TLS before it records its start
        with self.lock:
            self.info = {"state": "running", "started_at": time.time()}
        with self.lock:
            self.info["state"] = "done"

    monkeypatch.setattr(Flood, "_run", fake_run)
    first = flood.start(100, 1, 0, 120)["started_at"]
    flood.thread.join()
    asked = time.time()
    second = flood.start(100, 1, 0, 120)
    flood.thread.join()
    assert second["started_at"] >= asked > first  # not the stale start of the previous flood
