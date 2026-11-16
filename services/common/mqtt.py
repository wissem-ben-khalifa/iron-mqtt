"""The one MQTT-over-mutual-TLS client factory for the whole range.

Devices, internal services, tests AND the attacker agent all build their clients
here, so on the wire they share one TLS ClientHello and one MQTT library. Any
difference the IDS finds between them must come from behaviour, not fingerprint.

Each container mounts only its own identity at fixed paths:
    /certs/ca.crt       range CA (to verify the broker)
    /certs/client.crt   this client's certificate (CN = its MQTT identity)
    /certs/client.key   its private key
"""

from __future__ import annotations

import os
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path

import paho.mqtt.client as mqtt

# TLS keylogs decrypt every captured session, so they may only be written where
# git can never pick them up (both directories are gitignored and hook-blocked).
KEYLOG_ALLOWED_ROOTS = (Path("/captures"), Path("/secrets"))


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class MqttSettings:
    host: str = field(default_factory=lambda: _env("BROKER_HOST", "broker"))
    port: int = field(default_factory=lambda: int(_env("BROKER_PORT", "8883")))
    ca: str = field(default_factory=lambda: _env("TLS_CA", "/certs/ca.crt"))
    cert: str | None = field(default_factory=lambda: _env("TLS_CERT", "/certs/client.crt"))
    key: str | None = field(default_factory=lambda: _env("TLS_KEY", "/certs/client.key"))
    # Deliberately not SSLKEYLOGFILE: keylogging must be switched on explicitly per container.
    keylog: str | None = field(default_factory=lambda: os.environ.get("TLS_KEYLOG_FILE") or None)


def _checked_keylog(path: str) -> str:
    resolved = Path(path).resolve()
    if not any(resolved.is_relative_to(root) for root in KEYLOG_ALLOWED_ROOTS):
        raise ValueError(f"refusing to write TLS keylog outside {KEYLOG_ALLOWED_ROOTS}: {path}")
    return str(resolved)


def tls_context(settings: MqttSettings) -> ssl.SSLContext:
    """Client-side TLS: verify the broker against the range CA, present our cert."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=settings.ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if settings.cert:
        ctx.load_cert_chain(settings.cert, settings.key)
    if settings.keylog:
        ctx.keylog_filename = _checked_keylog(settings.keylog)
    return ctx


def make_client(client_id: str, settings: MqttSettings | None = None) -> mqtt.Client:
    """An MQTT v5 client configured for mutual TLS against the range broker."""
    settings = settings or MqttSettings()
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5
    )
    client.tls_set_context(tls_context(settings))
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    return client


def connect_blocking(
    client: mqtt.Client, settings: MqttSettings | None = None, timeout: float = 10.0, **connect_kwargs
) -> mqtt.ReasonCode | None:
    """Connect, start the network loop, and wait for CONNACK.

    Extra keyword arguments go to ``client.connect`` (e.g. clean_start, properties).
    Returns the CONNACK reason code (success is ``rc.is_failure == False``), or None
    if no CONNACK arrived (e.g. the TLS handshake was rejected).
    """
    settings = settings or MqttSettings()
    done = threading.Event()
    result: dict[str, mqtt.ReasonCode] = {}
    previous = client.on_connect

    def on_connect(c, userdata, flags, reason_code, properties):
        result["rc"] = reason_code
        done.set()
        if previous:
            previous(c, userdata, flags, reason_code, properties)

    client.on_connect = on_connect
    client.connect(settings.host, settings.port, keepalive=30, **connect_kwargs)
    client.loop_start()
    done.wait(timeout)
    client.on_connect = previous
    return result.get("rc")
