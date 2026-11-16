"""Attacker agent (M5): MQTT flood from a COMPROMISED DEVICE with a valid certificate.

Hard scope:
- The target is FIXED to the broker's Compose service name on iot_net (env BROKER_HOST,
  must equal ATTACK_TARGET = "broker"). Any other host/IP is refused at startup and per
  request. This is not a generic load tool and takes no target argument.
- Runs only inside the private Docker network (no published port).
- Reuses the devices' own MQTT/TLS client (services/common) with a real device
  certificate, so the attack differs from benign traffic only in BEHAVIOUR, not in TLS
  fingerprint or client library.

It exposes a tiny HTTP control surface (started by the control-plane API, which records
ground truth to MongoDB — the attacker itself has no database access):
    POST /flood  {rate_per_s, duration_s, qos, payload_bytes}  -> starts one flood
    POST /stop                                                 -> stops the current flood
    GET  /status
The flood publishes to the compromised device's own telemetry topic (allowed by the ACL
for that identity), so it is admissible traffic that the IDS must catch by rate/shape.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from services.common.mqtt import MqttSettings, connect_blocking, make_client

ATTACK_TARGET = "broker"  # the only host this agent will ever connect to
DEVICE_ID = os.environ.get("COMPROMISED_DEVICE", "device-07")


def _assert_target_is_our_broker() -> None:
    host = os.environ.get("BROKER_HOST", "broker")
    if host != ATTACK_TARGET:
        raise SystemExit(f"attacker refuses target {host!r}: only the simulated broker "
                         f"{ATTACK_TARGET!r} is allowed")


class Flood:
    """One in-progress flood. Publishes as the compromised device, as fast as rate allows."""

    def __init__(self):
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.info: dict = {"state": "idle"}

    def status(self) -> dict:
        with self.lock:
            return dict(self.info)

    def start(self, rate_per_s: float, duration_s: float, qos: int, payload_bytes: int) -> dict:
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise RuntimeError("a flood is already running")
            self.stop_event.clear()
            # Forget the previous flood first: otherwise the poll below sees its stale "done"
            # state and returns ITS started_at, and the API records wrong ground truth.
            self.info = {"state": "starting"}
            self.thread = threading.Thread(
                target=self._run, args=(rate_per_s, duration_s, qos, payload_bytes), daemon=True)
            self.thread.start()
        # Poll WITHOUT the lock: _run needs the lock to record its start, so holding it here
        # would deadlock the flood until our timeout (and push its deadline past the window).
        for _ in range(50):
            if self.status().get("state") in ("running", "done", "error"):
                break
            time.sleep(0.1)
        return self.status()

    def stop(self) -> dict:
        self.stop_event.set()
        t = self.thread
        if t:
            t.join(timeout=5)
        return self.status()

    def _run(self, rate_per_s, duration_s, qos, payload_bytes):
        settings = MqttSettings()  # BROKER_HOST is pinned to the broker; cert is the device's
        client = make_client(f"{DEVICE_ID}-compromised", settings)
        rc = connect_blocking(client, settings)
        if rc is None or rc.is_failure:
            with self.lock:
                self.info = {"state": "error", "error": f"connect failed: {rc}"}
            return
        topic = f"devices/{DEVICE_ID}/telemetry"
        payload = json.dumps({"device_id": DEVICE_ID, "type": "env_sensor", "attack": True,
                              "pad": "x" * max(0, payload_bytes - 80)})
        interval = 1.0 / rate_per_s if rate_per_s > 0 else 0.0
        started = time.time()
        with self.lock:
            self.info = {"state": "running", "device_id": DEVICE_ID, "topic": topic,
                         "rate_per_s": rate_per_s, "duration_s": duration_s, "qos": qos,
                         "payload_bytes": payload_bytes, "started_at": started, "sent": 0}
        sent = 0
        deadline = started + duration_s
        next_due = started
        while not self.stop_event.is_set() and time.time() < deadline:
            client.publish(topic, payload, qos=qos)
            sent += 1
            if sent % 200 == 0:
                with self.lock:
                    self.info["sent"] = sent
            next_due += interval
            sleep = next_due - time.time()
            if sleep > 0:
                self.stop_event.wait(sleep)
        gen_end = time.time()  # generation stopped; paho may still be draining its queue over TLS
        client.disconnect()
        client.loop_stop()      # blocks until the backlog is flushed: the traffic's true end
        drain_end = time.time()
        with self.lock:
            self.info.update({"state": "done", "sent": sent, "gen_end": gen_end, "ended_at": drain_end,
                              "gen_seconds": round(gen_end - started, 2),
                              "drain_seconds": round(drain_end - gen_end, 2),
                              "actual_rate_per_s": round(sent / (gen_end - started), 1) if gen_end > started else 0})


flood = Flood()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/status":
            self._send(200, flood.status())
        elif self.path == "/health":
            self._send(200, {"ok": True, "target": ATTACK_TARGET, "device": DEVICE_ID})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        try:
            if self.path == "/flood":
                result = flood.start(
                    rate_per_s=float(body.get("rate_per_s", 100)),
                    duration_s=float(body.get("duration_s", 30)),
                    qos=int(body.get("qos", 0)),
                    payload_bytes=int(body.get("payload_bytes", 120)))
                self._send(202, result)
            elif self.path == "/stop":
                self._send(200, flood.stop())
            else:
                self._send(404, {"error": "not found"})
        except (RuntimeError, ValueError) as exc:
            self._send(409, {"error": str(exc)})


def main():
    _assert_target_is_our_broker()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print(f"attacker agent up; target fixed to {ATTACK_TARGET!r}, identity {DEVICE_ID!r}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
