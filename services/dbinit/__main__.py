"""One-shot MongoDB bootstrap (the `mongo-init` service). Idempotent.

1. Initiate the single-node replica set `rs0` (change streams need a replica set).
2. Create one least-privilege role + user per service (no service uses root).
3. Create collections with $jsonSchema validators, indexes, and the time-series
   collection (services.common.db.ensure_schema).

Runs as root once, via MONGO_ROOT_URI; everything after this uses per-service users.
"""

from __future__ import annotations

import os
import time

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from services.common.db import DB_NAME, ensure_schema


def coll(name: str) -> dict:
    return {"db": DB_NAME, "collection": name}


# Privileges per service. Read the table as the data-flow diagram of the range.
ROLES: dict[str, list[dict]] = {
    "ingestRole": [
        {"resource": coll("telemetry"), "actions": ["insert", "find"]},
        {"resource": coll("devices"), "actions": ["find", "insert", "update"]},
    ],
    "detectorRole": [
        {"resource": coll("windows"), "actions": ["find", "insert", "update"]},
        {"resource": coll("incidents"), "actions": ["find", "insert", "update"]},
        {"resource": coll("models"), "actions": ["find", "insert", "update"]},
        {"resource": coll("runs"), "actions": ["find"]},
        {"resource": coll("devices"), "actions": ["find"]},
    ],
    "apiRole": [
        {"resource": coll("devices"), "actions": ["find"]},
        {"resource": coll("telemetry"), "actions": ["find"]},
        {"resource": coll("windows"), "actions": ["find"]},
        {"resource": coll("models"), "actions": ["find"]},
        {"resource": coll("incidents"), "actions": ["find", "update", "changeStream"]},
        {"resource": coll("runs"), "actions": ["find", "insert", "update"]},
    ],
}
USERS = {  # user -> (role, password env var)
    "ingest": ("ingestRole", "MONGO_INGEST_PASSWORD"),
    "detector": ("detectorRole", "MONGO_DETECTOR_PASSWORD"),
    "api": ("apiRole", "MONGO_API_PASSWORD"),
    "analyst": ("read", "MONGO_ANALYST_PASSWORD"),  # read-only: checks, notebooks, evidence
}


def initiate_replica_set(client: MongoClient) -> None:
    try:
        client.admin.command("replSetGetStatus")
        print("replica set already initiated")
    except OperationFailure as exc:
        if exc.code != 94:  # NotYetInitialized
            raise
        client.admin.command("replSetInitiate", {"_id": "rs0", "members": [{"_id": 0, "host": "mongo:27017"}]})
        print("replica set rs0 initiated")
    for _ in range(60):
        if client.admin.command("hello").get("isWritablePrimary"):
            print("node is PRIMARY")
            return
        time.sleep(1)
    raise SystemExit("replica set never became primary")


def ensure_roles_and_users(client: MongoClient) -> None:
    db = client[DB_NAME]
    existing_roles = {r["role"] for r in db.command("rolesInfo", 1)["roles"]}
    for role, privileges in ROLES.items():
        cmd = "updateRole" if role in existing_roles else "createRole"
        db.command(cmd, role, privileges=privileges, roles=[])
        print(f"{cmd}: {role}")
    existing_users = {u["user"] for u in db.command("usersInfo", 1)["users"]}
    for user, (role, pw_var) in USERS.items():
        password = os.environ[pw_var]
        roles = [{"role": role, "db": DB_NAME}]
        cmd = "updateUser" if user in existing_users else "createUser"
        db.command(cmd, user, pwd=password, roles=roles)
        print(f"{cmd}: {user} -> {role}")


def main():
    client = MongoClient(os.environ["MONGO_ROOT_URI"], directConnection=True, serverSelectionTimeoutMS=30_000)
    initiate_replica_set(client)
    ensure_roles_and_users(client)
    for action in ensure_schema(client[DB_NAME]):
        print(action)
    print("mongo-init done")


if __name__ == "__main__":
    main()
