"""MongoDB access and the range's document schema.

Why a document store here: incidents are nested and heterogeneous (window features,
the model's decision, model lineage, pcap references, later enrichment) and are
queried flexibly to rebuild timelines. Telemetry also lives here, in a native
time-series collection, as a secondary use; a dedicated time-series DB would be the
more natural home for pure telemetry.

`ensure_schema()` is idempotent: it creates collections with $jsonSchema validators
and indexes, or updates the validators of existing collections (collMod).
"""

from __future__ import annotations

import os

from pymongo import ASCENDING, DESCENDING, IndexModel, MongoClient
from pymongo.database import Database
from pymongo.errors import CollectionInvalid

DB_NAME = "iron"


def connect(uri: str | None = None, **kwargs) -> MongoClient:
    """Connect using MONGO_URI (each service has its own least-privilege user)."""
    uri = uri or os.environ["MONGO_URI"]
    return MongoClient(uri, tz_aware=True, serverSelectionTimeoutMS=10_000, **kwargs)


def database(client: MongoClient) -> Database:
    return client[DB_NAME]


DATE = {"bsonType": "date"}
STR = {"bsonType": "string"}
NUM = {"bsonType": ["double", "int", "long"]}

VALIDATORS: dict[str, dict] = {
    # One document per device, upserted by ingest.
    "devices": {
        "bsonType": "object",
        "required": ["_id", "type", "first_seen", "last_seen"],
        "properties": {
            "_id": {**STR, "pattern": "^device-[0-9]{2}$", "description": "device id = cert CN"},
            "type": {"enum": ["env_sensor", "smart_plug", "door_sensor", "camera"]},
            "first_seen": DATE, "last_seen": DATE,
            "state": {"enum": ["online", "offline"]},
            "last_seq": {"bsonType": ["int", "long"]},
            "messages": {"bsonType": ["int", "long"]},
            "gaps": {"bsonType": ["int", "long"], "description": "seq numbers never received"},
        },
    },
    # Feature windows: one per (source IP, time window). Model lineage points here.
    "windows": {
        "bsonType": "object",
        "required": ["_id", "src_ip", "start", "end", "features"],
        "properties": {
            "_id": STR, "src_ip": STR, "start": DATE, "end": DATE,
            "features": {"bsonType": "object"},
            "run_id": {"bsonType": ["string", "null"]},
            "label": {"enum": ["benign", "attack", None]},
            "verdict": {"bsonType": "object", "required": ["model_version", "label", "score"],
                        "properties": {"model_version": STR, "label": {"enum": ["benign", "attack"]}, "score": NUM}},
        },
    },
    # Security incidents: heterogeneous, nested; every one carries model_version.
    "incidents": {
        "bsonType": "object",
        "required": ["detected_at", "kind", "source", "detector", "status"],
        "properties": {
            "detected_at": DATE,
            # "test" = pipeline self-test (API/WebSocket tests); excluded from analytics.
            "kind": {"enum": ["ml_flood", "threshold_flood", "new_ip_for_cert", "test"]},
            "source": {"bsonType": "object", "required": ["src_ip"],
                       "properties": {"src_ip": STR, "device_id": {"bsonType": ["string", "null"]}}},
            "window": {"bsonType": "object", "properties": {"start": DATE, "end": DATE, "window_id": STR}},
            "detector": {"bsonType": "object", "required": ["name"],
                         "properties": {"name": STR, "model_version": STR, "score": NUM, "threshold": NUM}},
            "features": {"bsonType": "object"},
            "evidence": {"bsonType": "object", "properties": {"pcap": STR}},
            "status": {"enum": ["open", "acknowledged", "closed"]},
            "enrichment": {"bsonType": "array"},
            "windows": {"bsonType": ["int", "long"]},
            # Alert raised time minus the ground-truth flood start; null when no run matches.
            "detection_latency_s": {"bsonType": ["double", "int", "long", "null"]},
            "window_close_s": {"bsonType": ["double", "int", "long", "null"]},
            "ground_truth": {"bsonType": ["object", "null"]},
            "trigger": {"bsonType": "object"},
            "run_id": {"bsonType": ["string", "null"]},
        },
    },
    # Model registry with training lineage (needed to measure poisoning later).
    "models": {
        "bsonType": "object",
        "required": ["_id", "created_at", "algorithm", "trained_on", "artifact"],
        "properties": {
            "_id": {**STR, "description": "model version, e.g. m0001"},
            "created_at": DATE, "algorithm": STR, "params": {"bsonType": "object"},
            "parent_version": {"bsonType": ["string", "null"]},
            "trained_on": {"bsonType": "object", "required": ["window_ids", "time_ranges"],
                           "properties": {"window_ids": {"bsonType": "array"},
                                          "time_ranges": {"bsonType": "array"},
                                          "runs": {"bsonType": "array"},
                                          "source": STR}},
            "metrics": {"bsonType": "object"},
            "artifact": {"bsonType": "object", "required": ["path", "sha256"],
                         "properties": {"path": STR, "sha256": STR}},
            "active": {"bsonType": "bool"},
        },
    },
    # Experiment runs and their ground truth (attack start/stop, attacker IP).
    "runs": {
        "bsonType": "object",
        "required": ["_id", "started_at", "config"],
        "properties": {"_id": STR, "started_at": DATE, "ended_at": DATE,
                       "config": {"bsonType": "object"}, "attacks": {"bsonType": "array"}},
    },
}

INDEXES: dict[str, list[IndexModel]] = {
    "devices": [IndexModel([("last_seen", DESCENDING)])],
    "windows": [IndexModel([("src_ip", ASCENDING), ("start", ASCENDING)]),
                IndexModel([("start", ASCENDING)]),
                IndexModel([("run_id", ASCENDING), ("start", ASCENDING)]),
                IndexModel([("verdict.model_version", ASCENDING)])],
    "incidents": [IndexModel([("detected_at", DESCENDING)]),
                  IndexModel([("source.device_id", ASCENDING), ("detected_at", DESCENDING)]),
                  IndexModel([("source.src_ip", ASCENDING), ("detected_at", DESCENDING)]),
                  IndexModel([("kind", ASCENDING), ("status", ASCENDING)]),
                  IndexModel([("detector.model_version", ASCENDING)])],
    "models": [IndexModel([("created_at", DESCENDING)]), IndexModel([("active", ASCENDING)])],
    "runs": [IndexModel([("started_at", DESCENDING)])],
}

TELEMETRY_TTL_S = 14 * 24 * 3600


def ensure_schema(db: Database) -> list[str]:
    """Create/upgrade collections, validators and indexes. Returns a log of actions."""
    actions = []
    existing = set(db.list_collection_names())
    for name, schema in VALIDATORS.items():
        validator = {"$jsonSchema": schema}
        if name in existing:
            db.command("collMod", name, validator=validator, validationLevel="strict")
            actions.append(f"updated validator: {name}")
        else:
            db.create_collection(name, validator=validator, validationLevel="strict")
            actions.append(f"created: {name}")
        if INDEXES.get(name):
            db[name].create_indexes(INDEXES[name])
    # Telemetry: native time-series collection (bucketed storage, metaField = device).
    if "telemetry" not in existing:
        try:
            db.create_collection(
                "telemetry",
                timeseries={"timeField": "ts", "metaField": "meta", "granularity": "seconds"},
                expireAfterSeconds=TELEMETRY_TTL_S,
            )
            actions.append("created: telemetry (time-series)")
        except CollectionInvalid:
            pass
    db.telemetry.create_index([("meta.device_id", ASCENDING), ("ts", ASCENDING)])
    return actions
