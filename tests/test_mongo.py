"""M3 checks on MongoDB: replica set, schema validation, least privilege, time-series.

Needs the range up (mongo + mongo-init). Uses the read-only `analyst` user, plus the
`ingest` user to prove validation and privilege boundaries on writes.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from pymongo.errors import OperationFailure, WriteError

from services.common.db import connect, database

pytestmark = pytest.mark.skipif("MONGO_URI" not in os.environ, reason="needs the running range")


@pytest.fixture(scope="module")
def analyst_db():
    return database(connect())


@pytest.fixture(scope="module")
def ingest_db():
    return database(connect(os.environ["MONGO_INGEST_URI"]))


def test_replica_set_is_primary(analyst_db):
    hello = analyst_db.client.admin.command("hello")
    assert hello["setName"] == "rs0" and hello["isWritablePrimary"]


def test_telemetry_is_time_series(analyst_db):
    info = analyst_db.command("listCollections", filter={"name": "telemetry"})["cursor"]["firstBatch"][0]
    print("telemetry options:", info["options"].get("timeseries"))
    assert info["type"] == "timeseries"
    assert info["options"]["timeseries"]["metaField"] == "meta"


def test_validator_rejects_malformed_device(ingest_db):
    now = datetime.now(timezone.utc)
    with pytest.raises(WriteError) as exc:
        ingest_db.devices.insert_one({"_id": "not-a-device", "type": "toaster", "first_seen": now, "last_seen": now})
    print("validation error code:", exc.value.code)
    assert exc.value.code == 121  # DocumentValidationFailure


def test_ingest_cannot_read_incidents(ingest_db):
    with pytest.raises(OperationFailure) as exc:
        ingest_db.incidents.find_one()
    assert exc.value.code == 13  # Unauthorized


def test_analyst_cannot_write(analyst_db):
    with pytest.raises(OperationFailure) as exc:
        analyst_db.runs.insert_one({"_id": "x", "started_at": datetime.now(timezone.utc), "config": {}})
    assert exc.value.code == 13
