"""M4 checks on the control plane, against the running range (api:8000).

Measures, not just asserts: how fast a fleet pause takes effect (from MongoDB), and how
fast an incident inserted into MongoDB reaches a WebSocket client (change stream).
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import httpx
import pytest
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect as ws_connect

from services.common.db import connect, database

pytestmark = pytest.mark.skipif("API_URL" not in os.environ, reason="needs the running range")

API = os.environ.get("API_URL", "")
TOKEN = os.environ.get("API_TOKEN", "")
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=API, timeout=10) as client:
        yield client


@pytest.fixture(scope="module")
def analyst():
    return database(connect())


def test_data_endpoints_require_token(api):
    assert api.get("/devices").status_code == 401
    assert api.get("/devices", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert api.get("/incidents").status_code == 401
    assert api.post("/fleet/commands", json={"cmd": "pause"}).status_code == 401


def test_openapi_documents_the_api(api):
    spec = api.get("/openapi.json").json()
    for path in ["/devices", "/incidents", "/incidents/timeline", "/fleet/commands", "/telemetry/latency"]:
        assert path in spec["paths"], path
    assert api.get("/docs").status_code == 200


def test_devices_lists_the_fleet(api):
    r = api.get("/devices", headers=H)
    assert r.status_code == 200
    ids = {d["_id"] for d in r.json()}
    print("devices in registry:", len(ids))
    assert {f"device-{i:02d}" for i in range(1, 11)} <= ids


def test_invalid_command_is_rejected(api):
    assert api.post("/fleet/commands", headers=H, json={"cmd": "self_destruct"}).status_code == 422
    assert api.post("/fleet/commands", headers=H, json={"cmd": "rate"}).status_code == 422


def test_pause_stops_and_resume_restarts_telemetry(api, analyst):
    r = api.post("/fleet/commands", headers=H, json={"cmd": "pause"})
    assert r.status_code == 202
    paused_at = datetime.fromisoformat(r.json()["sent_at"])
    try:
        time.sleep(12)  # longer than any periodic device's period (10 s)
        after = list(analyst.telemetry.find({"ts": {"$gt": paused_at}}, {"ts": 1, "meta": 1}))
        last_before = analyst.telemetry.find_one({"ts": {"$lte": paused_at}}, sort=[("ts", -1)])
        print(f"telemetry sent after pause: {len(after)}; last message sent "
              f"{(paused_at - last_before['ts']).total_seconds():.2f} s before the pause")
        assert after == [], after[:3]
    finally:
        r = api.post("/fleet/commands", headers=H, json={"cmd": "resume"})
    resumed_at = datetime.fromisoformat(r.json()["sent_at"])
    deadline = time.time() + 12
    first = None
    while time.time() < deadline and first is None:
        first = analyst.telemetry.find_one({"ts": {"$gt": resumed_at}}, sort=[("ts", 1)])
        time.sleep(0.5)
    assert first is not None, "telemetry did not resume within 12 s"
    print(f"first telemetry after resume: {(first['ts'] - resumed_at).total_seconds():.2f} s "
          f"({first['meta']['device_id']})")


WS_URL = API.replace("http://", "ws://") + "/ws/incidents"


def _ws_auth(ws, token: str) -> None:
    """First-message auth: the token never goes in the URL (it would reach the access log)."""
    ws.send(json.dumps({"type": "auth", "token": token}))


def test_websocket_rejects_bad_token():
    with ws_connect(WS_URL, open_timeout=5) as ws:
        _ws_auth(ws, "wrong")
        with pytest.raises(ConnectionClosed) as exc:
            ws.recv(timeout=5)
    print("bad-token websocket closed with", exc.value.rcvd.code if exc.value.rcvd else None)
    assert exc.value.rcvd is not None and exc.value.rcvd.code == 1008


def test_websocket_rejects_a_first_message_that_is_not_auth():
    with ws_connect(WS_URL, open_timeout=5) as ws:
        ws.send(json.dumps({"type": "hello"}))
        with pytest.raises(ConnectionClosed) as exc:
            ws.recv(timeout=5)
    assert exc.value.rcvd is not None and exc.value.rcvd.code == 1008


def test_websocket_ignores_a_token_in_the_query_string():
    """The old ?token= form must not authenticate any more."""
    with ws_connect(f"{WS_URL}?token={TOKEN}", open_timeout=5) as ws:
        ws.send(json.dumps({"type": "hello"}))
        with pytest.raises(ConnectionClosed) as exc:
            ws.recv(timeout=5)
    assert exc.value.rcvd is not None and exc.value.rcvd.code == 1008


def test_websocket_streams_new_incident_and_patch(api):
    detector = database(connect(os.environ["MONGO_DETECTOR_URI"]))
    with ws_connect(WS_URL, open_timeout=5) as ws:
        _ws_auth(ws, TOKEN)
        assert json.loads(ws.recv(timeout=5))["type"] == "ready"
        inserted_at = time.time()
        res = detector.incidents.insert_one({
            "detected_at": datetime.now(timezone.utc), "kind": "test", "status": "open",
            "source": {"src_ip": "172.28.0.250", "device_id": None},
            "detector": {"name": "api-selftest"}, "run_id": "selftest",
        })
        msg = json.loads(ws.recv(timeout=5))
        latency_ms = (time.time() - inserted_at) * 1000
    print(f"incident reached the WebSocket {latency_ms:.1f} ms after insert")
    assert msg["type"] == "incident" and msg["op"] == "insert" and msg["incident"]["_id"] == str(res.inserted_id)
    datetime.fromisoformat(msg["incident"]["detected_at"])  # ISO 8601, parseable by browsers

    r = api.patch(f"/incidents/{res.inserted_id}", headers=H, json={"status": "closed", "note": "self-test"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "closed" and body["enrichment"][-1]["note"] == "self-test"
    assert api.get("/incidents", headers=H, params={"kind": "test", "limit": 1}).json()[0]["_id"] == str(res.inserted_id)


def test_latency_endpoint_aggregates(api):
    r = api.get("/telemetry/latency", headers=H, params={"minutes": 5})
    assert r.status_code == 200
    rows = r.json()["by_type"]
    print("latency by type (5 min):", [(x["type"], round(x["p95_ms"], 2)) for x in rows])
    # The endpoint returns per-type aggregates with non-negative percentiles. (p95 can be 0
    # for a type dominated by attacker flood messages, which carry no send timestamp, so
    # latency computes as ~0 — a real consequence of a compromised device publishing as a device.)
    assert rows and all(x["p95_ms"] >= 0 and x["messages"] > 0 for x in rows)
    assert {"camera", "env_sensor", "smart_plug"} <= {x["type"] for x in rows}
