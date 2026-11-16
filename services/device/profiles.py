"""Behavioural profiles for the simulated devices.

Each profile decides WHEN the device speaks and WHAT it says. The four types are
deliberately different in rhythm (periodic, event-driven, bursty, command-driven)
so that "benign" traffic is not one uniform pattern an IDS could trivially memorise.

A profile is a small state machine: ``next()`` returns how long to wait and the
message to publish after that wait. All randomness comes from a seeded RNG, so a
run is reproducible from (device id, seed).
"""

from __future__ import annotations

import base64
import math
import random
import time
from dataclasses import dataclass

# Version of the behavioural profiles below. Bump it whenever any profile parameter
# changes; every run records it, and an attack run must be compared only with a benign
# baseline recorded on the same version.
#   p1 (2026-10-15): initial profiles. Kept after the timing-transfer check: MQTTset's
#   clients are strictly periodic (B = -1), so they are no calibration target for
#   event-driven devices (docs/RESULTS.md, "Timing transfer").
PROFILE_VERSION = "p1"


@dataclass
class Emission:
    wait_s: float          # seconds to wait before publishing
    data: dict             # device-specific payload
    qos: int


class Profile:
    type_name = "base"

    def __init__(self, rng: random.Random):
        self.rng = rng

    def next(self) -> Emission:  # pragma: no cover - abstract
        raise NotImplementedError

    def on_command(self, cmd: dict) -> dict | None:
        """React to a device-specific command; return a status update or None."""
        return None


class EnvSensor(Profile):
    """Temperature/humidity sensor: strictly periodic, small payload, QoS 0."""

    type_name = "env_sensor"
    PERIOD_S = 5.0

    def __init__(self, rng):
        super().__init__(rng)
        self.temp = rng.uniform(19, 24)
        self.hum = rng.uniform(35, 55)
        self.phase = rng.uniform(0, 2 * math.pi)

    def next(self):
        # Slow daily cycle plus a small random walk: smooth, plausible readings.
        t = time.time()
        self.temp += self.rng.gauss(0, 0.05)
        self.hum = min(90, max(20, self.hum + self.rng.gauss(0, 0.2)))
        daily = 1.5 * math.sin(2 * math.pi * t / 86400 + self.phase)
        data = {"temp_c": round(self.temp + daily, 2), "humidity_pct": round(self.hum, 1)}
        return Emission(self.PERIOD_S * self.rng.uniform(0.95, 1.05), data, qos=0)


class SmartPlug(Profile):
    """Smart plug: periodic power report (QoS 1); can be switched by command."""

    type_name = "smart_plug"
    PERIOD_S = 10.0

    def __init__(self, rng):
        super().__init__(rng)
        self.on = rng.random() < 0.7
        self.load_w = rng.choice([8, 45, 120, 900, 1800])  # lamp, TV, fridge, heater, kettle

    def next(self):
        power = self.load_w * self.rng.uniform(0.9, 1.1) if self.on else self.rng.uniform(0.2, 0.6)
        data = {"on": self.on, "power_w": round(power, 1)}
        return Emission(self.PERIOD_S * self.rng.uniform(0.98, 1.02), data, qos=1)

    def on_command(self, cmd):
        if cmd.get("cmd") in ("switch_on", "switch_off"):
            self.on = cmd["cmd"] == "switch_on"
            return {"on": self.on}
        return None


class DoorSensor(Profile):
    """Door contact: event-driven (Poisson openings), each followed by a close, QoS 1."""

    type_name = "door_sensor"
    MEAN_GAP_S = 45.0

    def __init__(self, rng):
        super().__init__(rng)
        self.open = False

    def next(self):
        if self.open:
            wait = self.rng.uniform(2, 20)         # door stays open a few seconds
        else:
            wait = self.rng.expovariate(1 / self.MEAN_GAP_S)
        self.open = not self.open
        return Emission(wait, {"event": "open" if self.open else "closed"}, qos=1)


class Camera(Profile):
    """Camera motion metadata: long idle gaps, then bursts of ~1 KB detections at 2 Hz."""

    type_name = "camera"
    MEAN_IDLE_S = 120.0
    BURST_HZ = 2.0

    def __init__(self, rng):
        super().__init__(rng)
        self.burst_left = 0

    def next(self):
        if self.burst_left == 0:
            wait = self.rng.expovariate(1 / self.MEAN_IDLE_S)
            self.burst_left = int(self.rng.uniform(10, 30) * self.BURST_HZ)
        else:
            wait = 1 / self.BURST_HZ
        self.burst_left -= 1
        boxes = [
            {"label": self.rng.choice(["person", "cat", "car"]),
             "conf": round(self.rng.uniform(0.5, 0.99), 2),
             "xywh": [self.rng.randint(0, 640) for _ in range(4)]}
            for _ in range(self.rng.randint(1, 3))
        ]
        thumb = base64.b64encode(self.rng.randbytes(self.rng.randint(600, 900))).decode()
        return Emission(wait, {"motion": True, "boxes": boxes, "thumb": thumb}, qos=0)


PROFILES: dict[str, type[Profile]] = {
    p.type_name: p for p in (EnvSensor, SmartPlug, DoorSensor, Camera)
}
