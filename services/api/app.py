"""IRON-MQTT control plane (FastAPI).

REST + OpenAPI over the fleet and the defense, one WebSocket that streams incidents live
from a MongoDB change stream, and the operations console as static files under /ui.

Security:
- Every data endpoint requires `Authorization: Bearer <API_TOKEN>` (constant-time compare).
  The WebSocket authenticates with its first message (see ws_incidents): browsers cannot
  set headers on a WebSocket, and a ?token= query string would land in the access log.
- The console (/ui) is static: no token is ever served; the page asks for it and keeps it
  in sessionStorage. A strict Content-Security-Policy is set on every /ui response.
- MongoDB access is the least-privilege `api` user (read most things, write runs and
  incident status only).
- Fleet commands go out over MQTT as the `api` identity (broker ACL: may write
  fleet/cmd and devices/+/cmd only). The API never mounts docker.sock.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import httpx
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pymongo import AsyncMongoClient, DESCENDING

from services.common.db import DB_NAME
from services.common.mqtt import MqttSettings, connect_blocking, make_client

API_TOKEN = os.environ["API_TOKEN"]
DEV_UI = os.environ.get("DEV_UI", "0") == "1"  # serves the break-ui worst-case toggle; never on by default
RESULTS_SUMMARY = Path(os.environ.get("RESULTS_SUMMARY", "/app/docs/results/summary.json"))
UI_DIR = Path(__file__).parent / "ui"
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("text/javascript", ".js")
UI_DEV_DIR = Path(__file__).parent / "ui_dev"
state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncMongoClient(os.environ["MONGO_URI"], tz_aware=True)
    state["db"] = client[DB_NAME]
    mqtt_settings = MqttSettings()
    mqtt_client = make_client(f"api-{os.getpid()}", mqtt_settings)
    rc = await asyncio.to_thread(connect_blocking, mqtt_client, mqtt_settings)
    if rc is None or rc.is_failure:
        raise RuntimeError(f"API could not connect to the broker: {rc}")
    state["mqtt"] = mqtt_client
    state["attacker"] = httpx.AsyncClient(base_url=os.environ.get("ATTACKER_URL", "http://attacker:8080"),
                                          timeout=15)
    yield
    await state["attacker"].aclose()
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    await client.close()


ATTACKER_SRC_IP = "172.28.0.40"  # the attacker agent's fixed IP on iot_net (ground-truth label)


app = FastAPI(
    title="IRON-MQTT control plane",
    version="0.1.0",
    description="Run the fleet, query devices/telemetry/incidents, stream incidents live. "
                "All data endpoints need `Authorization: Bearer <token>`.",
    lifespan=lifespan,
)
bearer = HTTPBearer(auto_error=False)


def require_token(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
    if creds is None or not secrets.compare_digest(creds.credentials.encode(), API_TOKEN.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing or invalid bearer token",
                            headers={"WWW-Authenticate": "Bearer"})


auth = [Depends(require_token)]


def clean(doc: dict) -> dict:
    """Make a Mongo document JSON-friendly (ObjectId -> str; datetimes are handled by FastAPI)."""
    if doc is None:
        return doc
    out = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            v = str(v)
        elif isinstance(v, dict):
            v = clean(v)
        out[k] = v
    return out


def oid(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except InvalidId:
        raise HTTPException(404, "no such incident")


# ---------------------------------------------------------------------------- health
@app.get("/health", tags=["meta"])
async def health():
    """Liveness: MongoDB reachable and broker session up. No auth (no data)."""
    await state["db"].command("ping")
    return {"mongo": "ok", "mqtt": "ok" if state["mqtt"].is_connected() else "down"}


# ---------------------------------------------------------------------------- devices
@app.get("/devices", tags=["devices"], dependencies=auth)
async def list_devices():
    """The device registry maintained by ingest (one document per certificate identity)."""
    return [clean(d) async for d in state["db"].devices.find().sort("_id")]


@app.get("/devices/{device_id}", tags=["devices"], dependencies=auth)
async def get_device(device_id: str, last: int = Query(10, ge=0, le=500)):
    """One device plus its most recent telemetry messages."""
    db = state["db"]
    device = await db.devices.find_one({"_id": device_id})
    if device is None:
        raise HTTPException(404, "no such device")
    recent = [clean(t) async for t in db.telemetry.find({"meta.device_id": device_id}, {"_id": 0})
              .sort("ts", DESCENDING).limit(last)]
    return {**clean(device), "recent_telemetry": recent}


class DeviceCommand(BaseModel):
    cmd: Literal["switch_on", "switch_off"] = Field(description="device-specific command (smart plugs)")


@app.post("/devices/{device_id}/commands", tags=["devices"], dependencies=auth, status_code=202)
async def command_device(device_id: str, body: DeviceCommand):
    """Send a command to one device over MQTT (`devices/<id>/cmd`, QoS 1)."""
    return await _publish(f"devices/{device_id}/cmd", body.model_dump())


# ---------------------------------------------------------------------------- fleet
class FleetCommand(BaseModel):
    cmd: Literal["pause", "resume", "rate"]
    scale: float | None = Field(None, gt=0, le=100, description="for cmd=rate: speed multiplier")
    targets: list[str] | None = Field(None, description="device ids; omit for the whole fleet")


@app.post("/fleet/commands", tags=["fleet"], dependencies=auth, status_code=202)
async def command_fleet(body: FleetCommand):
    """Fleet-wide command over MQTT (`fleet/cmd`, QoS 1): pause, resume, or change rate."""
    if body.cmd == "rate" and body.scale is None:
        raise HTTPException(422, "cmd=rate needs scale")
    return await _publish("fleet/cmd", body.model_dump(exclude_none=True))


async def _publish(topic: str, payload: dict) -> dict:
    sent_at = time.time()
    info = state["mqtt"].publish(topic, json.dumps({**payload, "ts": sent_at}), qos=1)
    await asyncio.to_thread(info.wait_for_publish, 5)
    if not info.is_published():
        raise HTTPException(503, "broker did not acknowledge the command")
    return {"topic": topic, "payload": payload, "sent_at": datetime.fromtimestamp(sent_at, timezone.utc)}


# ---------------------------------------------------------------------------- telemetry
@app.get("/telemetry/latency", tags=["telemetry"], dependencies=auth)
async def telemetry_latency(minutes: int = Query(10, ge=1, le=24 * 60)):
    """End-to-end latency (device send -> ingest receive) per device type, via aggregation."""
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    pipeline = [
        {"$match": {"recv_ts": {"$gte": since}}},
        {"$group": {"_id": "$meta.type", "messages": {"$sum": 1},
                    "p50_ms": {"$percentile": {"input": "$latency_ms", "p": [0.5], "method": "approximate"}},
                    "p95_ms": {"$percentile": {"input": "$latency_ms", "p": [0.95], "method": "approximate"}},
                    "max_ms": {"$max": "$latency_ms"}}},
        {"$project": {"_id": 0, "type": "$_id", "messages": 1, "max_ms": 1,
                      "p50_ms": {"$first": "$p50_ms"}, "p95_ms": {"$first": "$p95_ms"}}},
        {"$sort": {"type": 1}},
    ]
    return {"window_minutes": minutes, "by_type": await (await state["db"].telemetry.aggregate(pipeline)).to_list()}


# ---------------------------------------------------------------------------- incidents
@app.get("/incidents", tags=["incidents"], dependencies=auth)
async def list_incidents(
    kind: str | None = None, device_id: str | None = None, src_ip: str | None = None,
    status_: str | None = Query(None, alias="status"), model_version: str | None = None,
    since: datetime | None = None, until: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    """Filterable incident list, newest first."""
    q: dict = {}
    if kind:
        q["kind"] = kind
    if device_id:
        q["source.device_id"] = device_id
    if src_ip:
        q["source.src_ip"] = src_ip
    if status_:
        q["status"] = status_
    if model_version:
        q["detector.model_version"] = model_version
    if since or until:
        q["detected_at"] = {**({"$gte": since} if since else {}), **({"$lte": until} if until else {})}
    cursor = state["db"].incidents.find(q).sort("detected_at", DESCENDING).limit(limit)
    return [clean(d) async for d in cursor]


@app.get("/incidents/timeline", tags=["incidents"], dependencies=auth)
async def incident_timeline(
    since: datetime | None = None, bucket_s: int = Query(60, ge=5, le=3600),
    device_id: str | None = None, src_ip: str | None = None,
):
    """Incidents per time bucket and source, with the detectors/model versions involved
    (aggregation pipeline: reconstructs what happened when, and which model saw it)."""
    since = since or datetime.now(timezone.utc) - timedelta(hours=1)
    match: dict = {"detected_at": {"$gte": since}, "kind": {"$ne": "test"}}
    if device_id:
        match["source.device_id"] = device_id
    if src_ip:
        match["source.src_ip"] = src_ip
    pipeline = [
        {"$match": match},
        {"$group": {
            "_id": {"bucket": {"$dateTrunc": {"date": "$detected_at", "unit": "second", "binSize": bucket_s}},
                    "src_ip": "$source.src_ip"},
            "incidents": {"$sum": 1},
            "kinds": {"$addToSet": "$kind"},
            "model_versions": {"$addToSet": "$detector.model_version"},
            "max_score": {"$max": "$detector.score"},
            "device_id": {"$first": "$source.device_id"},
        }},
        {"$project": {"_id": 0, "bucket": "$_id.bucket", "src_ip": "$_id.src_ip", "device_id": 1,
                      "incidents": 1, "kinds": 1, "model_versions": 1, "max_score": 1}},
        {"$sort": {"bucket": 1, "src_ip": 1}},
    ]
    return await (await state["db"].incidents.aggregate(pipeline)).to_list()


@app.get("/incidents/{incident_id}", tags=["incidents"], dependencies=auth)
async def get_incident(incident_id: str):
    doc = await state["db"].incidents.find_one({"_id": oid(incident_id)})
    if doc is None:
        raise HTTPException(404, "no such incident")
    return clean(doc)


class IncidentUpdate(BaseModel):
    status: Literal["open", "acknowledged", "closed"]
    note: str | None = Field(None, max_length=2000)


@app.patch("/incidents/{incident_id}", tags=["incidents"], dependencies=auth)
async def update_incident(incident_id: str, body: IncidentUpdate):
    """Change an incident's status; the note is appended to its enrichment history."""
    entry = {"at": datetime.now(timezone.utc), "by": "api", "status": body.status, "note": body.note}
    res = await state["db"].incidents.find_one_and_update(
        {"_id": oid(incident_id)},
        {"$set": {"status": body.status}, "$push": {"enrichment": entry}},
        return_document=True)
    if res is None:
        raise HTTPException(404, "no such incident")
    return clean(res)


# ---------------------------------------------------------------------------- runs, models
class FloodRequest(BaseModel):
    rate_per_s: float = Field(100, gt=0, le=20000, description="target publishes per second")
    duration_s: float = Field(30, gt=0, le=600)
    qos: Literal[0, 1, 2] = 0
    payload_bytes: int = Field(120, ge=1, le=65000)
    note: str | None = Field(None, max_length=500)


@app.post("/attacks/flood", tags=["attacks"], dependencies=auth, status_code=202)
async def launch_flood(body: FloodRequest):
    """Trigger a compromised-device MQTT flood and record it as ground truth.

    The API records the run (start/stop, rate, QoS, attacker IP, fleet profile version);
    the attacker agent only floods and has no database access. The agent's target is
    hard-fixed to our broker, so this cannot be pointed anywhere else.
    """
    started = datetime.now(timezone.utc)
    run_id = "run-" + started.strftime("%Y%m%dT%H%M%S")
    sample = await state["db"].devices.find_one({}, {"profile_version": 1})
    profile_version = (sample or {}).get("profile_version")
    try:
        resp = await state["attacker"].post("/flood", json=body.model_dump(exclude={"note"}))
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"attacker agent unreachable: {exc}")
    if resp.status_code == 409:
        raise HTTPException(409, resp.json().get("error", "a flood is already running"))
    resp.raise_for_status()
    agent = resp.json()
    attack = {"kind": "mqtt_flood", "adversary": "compromised_device",
              "src_ip": ATTACKER_SRC_IP, "device_id": agent.get("device_id"),
              "rate_per_s": body.rate_per_s, "qos": body.qos, "payload_bytes": body.payload_bytes,
              "duration_s": body.duration_s, "note": body.note,
              "started_at": datetime.fromtimestamp(agent["started_at"], timezone.utc),
              "planned_end": datetime.fromtimestamp(agent["started_at"] + body.duration_s, timezone.utc)}
    await state["db"].runs.insert_one({
        "_id": run_id, "started_at": started, "kind": "attack",
        "config": {"profile_version": profile_version, "attacker_src_ip": ATTACKER_SRC_IP},
        "attacks": [attack]})
    return {"run_id": run_id, "attack": attack, "agent": agent}


@app.post("/attacks/stop", tags=["attacks"], dependencies=auth)
async def stop_flood():
    """Stop the current flood and record its actual stop time and count on the latest run."""
    resp = await state["attacker"].post("/stop")
    agent = resp.json()
    run = await state["db"].runs.find_one({"kind": "attack"}, sort=[("started_at", DESCENDING)])
    if run and agent.get("ended_at"):
        await state["db"].runs.update_one(
            {"_id": run["_id"]},
            {"$set": {"ended_at": datetime.fromtimestamp(agent["ended_at"], timezone.utc),
                      "attacks.0.ended_at": datetime.fromtimestamp(agent["ended_at"], timezone.utc),
                      "attacks.0.sent": agent.get("sent"),
                      "attacks.0.gen_seconds": agent.get("gen_seconds"),
                      "attacks.0.drain_seconds": agent.get("drain_seconds"),
                      "attacks.0.actual_rate_per_s": agent.get("actual_rate_per_s")}})
    return agent


@app.get("/attacks/status", tags=["attacks"], dependencies=auth)
async def attack_status():
    resp = await state["attacker"].get("/status")
    return resp.json()


@app.get("/runs", tags=["experiments"], dependencies=auth)
async def list_runs(limit: int = Query(50, ge=1, le=500)):
    return [clean(d) async for d in state["db"].runs.find().sort("started_at", DESCENDING).limit(limit)]


@app.get("/runs/{run_id}", tags=["experiments"], dependencies=auth)
async def get_run(run_id: str):
    doc = await state["db"].runs.find_one({"_id": run_id})
    if doc is None:
        raise HTTPException(404, "no such run")
    return clean(doc)


@app.get("/models", tags=["detector"], dependencies=auth)
async def list_models():
    """Model registry with training lineage (which windows each version was trained on)."""
    projection = {"trained_on.window_ids": 0}  # can be large; counts are in trained_on
    return [clean(d) async for d in state["db"].models.find({}, projection).sort("created_at", DESCENDING)]


# ---------------------------------------------------------------------------- console support
# Read-only views for the operations console. All use the `api` role's existing `find`
# privileges; none widens it. Telemetry queries filter on the time-series field `ts` so
# MongoDB can prune buckets, and stay short: during a 20,000 msg/s flood the collection
# grows by ~1.2 M documents a minute, and a heavy console query would itself add latency.

GENUINE = {"$ifNull": ["$boot", False]}  # a real device envelope carries a boot id; flood messages do not


@app.get("/fleet/overview", tags=["fleet"], dependencies=auth)
async def fleet_overview(seconds: int = Query(15, ge=5, le=120)):
    """Device registry plus each device's message rate over the last `seconds`, split into
    messages with a genuine device envelope and messages without one (a compromised identity
    flooding its own topic shows up in the second count)."""
    db = state["db"]
    now = datetime.now(timezone.utc)
    pipeline = [
        {"$match": {"ts": {"$gte": now - timedelta(seconds=seconds)}}},
        {"$group": {"_id": "$meta.device_id",
                    "genuine": {"$sum": {"$cond": [GENUINE, 1, 0]}},
                    "unverified": {"$sum": {"$cond": [GENUINE, 0, 1]}}}},
    ]
    rates = {r["_id"]: r async for r in await db.telemetry.aggregate(pipeline)}
    devices = []
    async for d in db.devices.find().sort("_id"):
        r = rates.get(d["_id"], {})
        devices.append({**clean(d), "rate": {
            "genuine_per_s": round(r.get("genuine", 0) / seconds, 3),
            "unverified_per_s": round(r.get("unverified", 0) / seconds, 3)}})
    return {"as_of": now, "window_s": seconds, "devices": devices}


@app.get("/telemetry/series", tags=["telemetry"], dependencies=auth)
async def telemetry_series(minutes: int = Query(10, ge=1, le=60), bucket_s: int = Query(10, ge=5, le=300),
                           since: datetime | None = None):
    """Honest-device latency over time: p50/p95 end-to-end latency and message rate per bucket,
    from messages with a genuine device envelope only. Pass `since` to fetch only new buckets."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=minutes)
    if since is not None:
        since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        start = max(start, since)
    pipeline = [
        {"$match": {"ts": {"$gte": start}, "boot": {"$ne": None}}},
        {"$group": {"_id": {"$dateTrunc": {"date": "$ts", "unit": "second", "binSize": bucket_s}},
                    "messages": {"$sum": 1},
                    "p50": {"$percentile": {"input": "$latency_ms", "p": [0.5], "method": "approximate"}},
                    "p95": {"$percentile": {"input": "$latency_ms", "p": [0.95], "method": "approximate"}}}},
        {"$sort": {"_id": 1}},
    ]
    buckets = [{"t": b["_id"], "p50_ms": b["p50"][0], "p95_ms": b["p95"][0],
                "messages": b["messages"], "rate_per_s": round(b["messages"] / bucket_s, 3)}
               async for b in await state["db"].telemetry.aggregate(pipeline)]
    return {"as_of": now, "start": start, "bucket_s": bucket_s, "buckets": buckets}


@app.get("/detector/status", tags=["detector"], dependencies=auth)
async def detector_status():
    """What the live detector is doing now, read from what it writes: the model version on its
    most recent window verdict, how many windows it scored in the last 30 s, the last incident."""
    db = state["db"]
    now = datetime.now(timezone.utc)
    last = await db.windows.find_one({}, {"verdict.model_version": 1, "end": 1}, sort=[("start", DESCENDING)])
    recent = await db.windows.count_documents({"start": {"$gte": now - timedelta(seconds=30)}})
    incident = await db.incidents.find_one({"kind": {"$ne": "test"}}, {"detected_at": 1}, sort=[("detected_at", DESCENDING)])
    return {"as_of": now,
            "model_version": (last or {}).get("verdict", {}).get("model_version"),
            "last_window_end": (last or {}).get("end"),
            "windows_last_30s": recent,
            "last_incident_at": (incident or {}).get("detected_at")}


@app.get("/incidents/{incident_id}/windows", tags=["incidents"], dependencies=auth)
async def incident_windows(incident_id: str):
    """The scored windows behind one incident: the source's windows from just before the
    incident began until it ended, with the detector's verdict for each (the incident timeline)."""
    db = state["db"]
    inc = await db.incidents.find_one({"_id": oid(incident_id)}, {"source": 1, "window": 1})
    if inc is None:
        raise HTTPException(404, "no such incident")
    w = inc.get("window") or {}
    if not w.get("start"):
        return {"incident_id": incident_id, "windows": []}
    q = {"src_ip": inc["source"]["src_ip"],
         "start": {"$gte": w["start"] - timedelta(seconds=10), "$lte": w.get("end") or w["start"]}}
    rows = [clean(d) async for d in db.windows.find(q).sort("start", 1).limit(300)]
    return {"incident_id": incident_id, "windows": rows}


@app.get("/features/catalog", tags=["detector"], dependencies=auth)
async def features_catalog():
    """Every IDS feature with a readable name, its unit, and its provenance class from
    docs/FEATURES.md: produced by the device, partly influenced by it, or set by the system."""
    from ids.features import FEATURE_INFO
    from ids.robust_features import FEATURE_CLASS
    names = {"YES": "device", "PARTIAL": "partial", "SYSTEM": "system"}
    return [{"name": name, "label": label, "unit": unit, "provenance": names[FEATURE_CLASS[name]]}
            for name, (label, unit) in FEATURE_INFO.items()]


@app.get("/results/summary", tags=["experiments"], dependencies=auth)
async def results_summary():
    """Committed detector-comparison results (docs/results/summary.json, exported from the runs
    by scripts/export_results.py). Read-only; the console renders every number from here."""
    try:
        return JSONResponse(json.loads(RESULTS_SUMMARY.read_text()))
    except FileNotFoundError:
        raise HTTPException(503, f"results summary not found at {RESULTS_SUMMARY}")


@app.get("/ui-config", tags=["meta"])
async def ui_config():
    """Console configuration. No auth (no data): whether the dev worst-case toggle is served,
    and the fixed flood-scenario choices the console offers."""
    return {"dev_ui": DEV_UI,
            "flood_scenario": {"rates_per_s": [500, 2000, 20000], "durations_s": [15, 30, 60], "qos": 0}}


# ---------------------------------------------------------------------------- live stream
WS_AUTH_TIMEOUT_S = 5.0


@app.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket):
    """Streams incident inserts and updates as JSON, from a MongoDB change stream.

    Auth is the first message. A browser cannot set an Authorization header on a WebSocket,
    and putting the token in the URL (?token=) would write it into the server's access log.
    So the client connects, then sends {"type": "auth", "token": "<API_TOKEN>"} within 5 s.
    Anything else (wrong token, other message, timeout) closes with 1008 policy violation.
    Nothing is streamed before a valid token arrives.
    """
    await websocket.accept()
    try:
        first = await asyncio.wait_for(websocket.receive_json(), WS_AUTH_TIMEOUT_S)
    except WebSocketDisconnect:
        return
    except (asyncio.TimeoutError, ValueError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="auth required")
        return
    token = first.get("token") if isinstance(first, dict) and first.get("type") == "auth" else None
    if not isinstance(token, str) or not secrets.compare_digest(token.encode(), API_TOKEN.encode()):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="invalid token")
        return
    pipeline = [{"$match": {"operationType": {"$in": ["insert", "update", "replace"]}}}]
    try:
        async with await state["db"].incidents.watch(pipeline, full_document="updateLookup") as stream:
            await websocket.send_json({"type": "ready"})
            async for change in stream:
                doc = change.get("fullDocument")
                if doc is None:
                    continue
                await websocket.send_json(jsonable_encoder(
                    {"type": "incident", "op": change["operationType"], "incident": clean(doc)}))
    except WebSocketDisconnect:
        pass


# ---------------------------------------------------------------------------- console (static)
UI_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; "
          "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@app.middleware("http")
async def console_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith(("/ui", "/ui-dev")) and request.url.path != "/ui-config":
        response.headers["Content-Security-Policy"] = UI_CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/ui", include_in_schema=False)
async def ui_root():
    return RedirectResponse("/ui/")


if DEV_UI and UI_DEV_DIR.is_dir():
    app.mount("/ui-dev", StaticFiles(directory=UI_DEV_DIR), name="ui-dev")
app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")
