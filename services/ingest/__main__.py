"""Ingest: MQTT telemetry/status -> MongoDB (time-series telemetry + device registry).

- Subscribes as the `ingest` identity with a persistent MQTT v5 session
  (clean_start=False, 1 h expiry): QoS 1 messages published while ingest is down are
  queued by the broker and delivered on reconnect.
- Writes in small batches (every 0.5 s or 500 messages) to keep up with bursts.
- Tracks per-device sequence numbers, so lost messages are counted, not guessed.
- Records end-to-end latency: ingest receive time minus the device's send timestamp
  (all containers share the host kernel clock).
"""

from __future__ import annotations

import json
import logging
import queue
import signal
import threading
import time
from datetime import datetime, timezone

from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from pymongo import UpdateOne

from services.common.db import connect, database
from services.common.mqtt import MqttSettings, make_client

BATCH_MAX = 500
BATCH_EVERY_S = 0.5
log = logging.getLogger("ingest")


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


class Ingest:
    def __init__(self):
        self.db = database(connect())
        self.inbox: queue.Queue = queue.Queue()
        self.stop = threading.Event()
        # Resume sequence tracking from the registry so an ingest restart does not invent
        # gaps. Tracking is per (device, boot): a device restart starts a new sequence.
        self.last_seq = {d["_id"]: (d.get("last_boot"), d.get("last_seq", 0))
                         for d in self.db.devices.find({}, {"last_seq": 1, "last_boot": 1})}
        self.settings = MqttSettings()
        self.client = make_client("ingest", self.settings)
        self.client.on_connect = self.on_connect
        self.client.on_message = lambda c, u, m: self.inbox.put((time.time(), m.topic, m.payload))

    def on_connect(self, client, userdata, flags, reason_code, properties):
        log.info("connected (%s), session present=%s", reason_code, flags.session_present)
        client.subscribe([("devices/+/telemetry", 1), ("devices/+/status", 1)])

    def run(self):
        props = Properties(PacketTypes.CONNECT)
        props.SessionExpiryInterval = 3600
        self.client.connect_async(self.settings.host, self.settings.port, keepalive=30,
                                  clean_start=False, properties=props)
        self.client.loop_start()
        while not self.stop.is_set():
            batch = self._drain()
            if batch:
                self._write(batch)
        self._write(self._drain())  # final flush
        self.client.disconnect()
        self.client.loop_stop()

    def _drain(self) -> list:
        """Collect up to BATCH_MAX messages, waiting at most BATCH_EVERY_S."""
        batch, deadline = [], time.time() + BATCH_EVERY_S
        while len(batch) < BATCH_MAX:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                batch.append(self.inbox.get(timeout=remaining))
            except queue.Empty:
                break
        return batch

    def _write(self, batch: list) -> None:
        telemetry, updates = [], []
        for recv_ts, topic, payload in batch:
            parts = topic.split("/")
            device_id, kind = parts[1], parts[2]
            try:
                msg = json.loads(payload)
            except ValueError:
                log.warning("non-JSON payload on %s (%d bytes) dropped", topic, len(payload))
                continue
            if kind == "status":
                if msg.get("state") in ("online", "offline") and msg.get("type"):
                    updates.append(UpdateOne(
                        {"_id": device_id},
                        {"$set": {"state": msg["state"], "type": msg["type"], "last_seen": utc(recv_ts),
                                  "last_heartbeat": utc(recv_ts), "paused": bool(msg.get("paused", False)),
                                  "profile_version": msg.get("profile_version")},
                         "$setOnInsert": {"first_seen": utc(recv_ts), "messages": 0, "gaps": 0}},
                        upsert=True))
                continue
            # The broker ACL guarantees topic device == cert identity; the payload's
            # claimed device_id is not trusted, the topic is.
            seq, sent_ts, boot = int(msg.get("seq", 0)), float(msg.get("ts", recv_ts)), msg.get("boot")
            prev_boot, prev = self.last_seq.get(device_id, (None, 0))
            if boot != prev_boot:
                prev = 0  # new device boot: its sequence restarts at 1
            gap = seq - prev - 1 if prev and seq > prev + 1 else 0
            self.last_seq[device_id] = (boot, max(prev, seq))
            telemetry.append({
                "ts": utc(sent_ts), "meta": {"device_id": device_id, "type": msg.get("type")},
                "boot": boot, "seq": seq, "recv_ts": utc(recv_ts), "latency_ms": (recv_ts - sent_ts) * 1000,
                "data": msg.get("data", {}),
            })
            updates.append(UpdateOne(
                {"_id": device_id},
                {"$set": {"last_seen": utc(recv_ts), "type": msg.get("type"), "state": "online",
                          "last_boot": boot, "last_seq": self.last_seq[device_id][1]},
                 "$inc": {"messages": 1, "gaps": gap},
                 "$setOnInsert": {"first_seen": utc(recv_ts)}},
                upsert=True))
        if telemetry:
            self.db.telemetry.insert_many(telemetry, ordered=False)
        if updates:
            self.db.devices.bulk_write(updates, ordered=False)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    ingest = Ingest()
    signal.signal(signal.SIGTERM, lambda *_: ingest.stop.set())
    log.info("ingest starting; resuming %d devices", len(ingest.last_seq))
    ingest.run()


if __name__ == "__main__":
    main()
