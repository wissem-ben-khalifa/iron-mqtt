"""A simulated IoT device: real MQTT v5 over mutual TLS, behaviour from a profile.

Environment:
    DEVICE_ID    e.g. device-07 (must match the CN of the mounted certificate)
    DEVICE_TYPE  env_sensor | smart_plug | door_sensor | camera
    SEED         RNG seed (reproducible behaviour)
    RATE_SCALE   >1 speeds the device up (default 1.0)

Topics (enforced by the broker ACL):
    publish  devices/<id>/telemetry   envelope {device_id, type, boot, seq, ts, data}
    publish  devices/<id>/status      retained online/offline + periodic heartbeat
    receive  devices/<id>/cmd         device-specific commands (e.g. switch_off)
    receive  fleet/cmd                fleet-wide commands: pause | resume | rate
"""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import threading
import time

from services.common.mqtt import MqttSettings, make_client
from services.device.profiles import PROFILE_VERSION, PROFILES

HEARTBEAT_S = 60.0

log = logging.getLogger("device")


class Device:
    def __init__(self, device_id: str, type_name: str, seed: int, rate_scale: float = 1.0):
        self.id = device_id
        self.profile = PROFILES[type_name](random.Random(f"{device_id}:{seed}"))
        self.rate_scale = rate_scale
        self.seq = 0                 # increments per telemetry message actually sent
        self.boot = int(time.time() * 1000)  # identifies this run; seq restarts at 1 per boot
        self.paused = threading.Event()
        self.stop = threading.Event()
        self.wake = threading.Event()  # interrupts a wait when a command arrives
        self.started = time.time()
        self.settings = MqttSettings()
        self.client = make_client(device_id, self.settings)
        self.client.will_set(self.topic("status"), self._status("offline"), qos=1, retain=True)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

    def topic(self, kind: str) -> str:
        return f"devices/{self.id}/{kind}"

    def _status(self, state: str, **extra) -> str:
        return json.dumps({"device_id": self.id, "type": self.profile.type_name,
                           "profile_version": PROFILE_VERSION, "state": state, "ts": time.time(),
                           "paused": self.paused.is_set(), **extra})

    # --- MQTT callbacks (run on paho's network thread) -------------------------
    def on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            log.error("connect refused: %s", reason_code)
            return
        log.info("connected (%s)", reason_code)
        client.subscribe([(self.topic("cmd"), 1), ("fleet/cmd", 1)])
        client.publish(self.topic("status"), self._status("online"), qos=1, retain=True)

    def on_message(self, client, userdata, msg):
        try:
            cmd = json.loads(msg.payload)
        except ValueError:
            log.warning("ignoring non-JSON command on %s", msg.topic)
            return
        name = cmd.get("cmd")
        targets = cmd.get("targets")  # optional list of device ids; absent = whole fleet
        if msg.topic == "fleet/cmd" and targets and self.id not in targets:
            return
        if name in ("pause", "resume"):
            if name == "pause":
                self.paused.set()
            else:
                self.paused.clear()
            # Report the new state at once, so the console shows the fleet's real state.
            client.publish(self.topic("status"), self._status("online"), qos=1)
        elif name == "rate":
            self.rate_scale = max(0.01, float(cmd.get("scale", 1.0)))
        else:
            update = self.profile.on_command(cmd)
            if update is not None:
                client.publish(self.topic("status"), self._status("online", **update), qos=1)
        log.info("command %s -> paused=%s rate=%.2f", name, self.paused.is_set(), self.rate_scale)
        self.wake.set()

    # --- main loop -------------------------------------------------------------
    def run(self):
        self.client.connect_async(self.settings.host, self.settings.port, keepalive=30)
        self.client.loop_start()
        next_heartbeat = time.time() + HEARTBEAT_S
        emission = self.profile.next()
        due = time.time() + emission.wait_s / self.rate_scale
        while not self.stop.is_set():
            now = time.time()
            if now >= next_heartbeat:
                self.client.publish(self.topic("status"), self._status(
                    "online", uptime_s=round(now - self.started), sent=self.seq), qos=0)
                next_heartbeat = now + HEARTBEAT_S
            if now >= due:
                if not self.paused.is_set() and self.client.is_connected():
                    self.seq += 1
                    envelope = {"device_id": self.id, "type": self.profile.type_name, "boot": self.boot,
                                "seq": self.seq, "ts": time.time(), "data": emission.data}
                    self.client.publish(self.topic("telemetry"), json.dumps(envelope), qos=emission.qos)
                emission = self.profile.next()
                due = time.time() + emission.wait_s / self.rate_scale
                continue
            self.wake.wait(min(due, next_heartbeat) - now)
            self.wake.clear()
        self.client.publish(self.topic("status"), self._status("offline"), qos=1, retain=True).wait_for_publish(2)
        self.client.disconnect()
        self.client.loop_stop()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    device = Device(
        device_id=os.environ["DEVICE_ID"],
        type_name=os.environ["DEVICE_TYPE"],
        seed=int(os.environ.get("SEED", "0")),
        rate_scale=float(os.environ.get("RATE_SCALE", "1.0")),
    )
    signal.signal(signal.SIGTERM, lambda *_: (device.stop.set(), device.wake.set()))
    log.info("%s starting as %s", device.id, device.profile.type_name)
    device.run()


if __name__ == "__main__":
    main()
