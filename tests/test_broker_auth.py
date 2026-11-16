"""M0 check: the broker accepts only range-issued client certs and enforces topic ACLs.

Runs inside the `tests` container on iot_net, with the whole certs/ tree mounted
read-only at /pki (the test needs several identities; real services get only one).
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
import uuid

import paho.mqtt.client as mqtt
import pytest

from services.common.mqtt import MqttSettings, connect_blocking, make_client

PKI = "/pki"
CA = f"{PKI}/ca/ca.crt"


def identity(kind: str, name: str) -> MqttSettings:
    return MqttSettings(ca=CA, cert=f"{PKI}/{kind}/{name}.crt", key=f"{PKI}/{kind}/{name}.key")


def raw_tls_attempt(cert: str | None, key: str | None) -> str:
    """Open a TLS connection and try to read; return how the server responded.

    In TLS 1.3 the client finishes its side of the handshake before the server has
    judged the client certificate, so a rejection arrives as an alert on first read.
    """
    ctx = ssl.create_default_context(cafile=CA)
    if cert:
        ctx.load_cert_chain(cert, key)
    with socket.create_connection(("broker", 8883), timeout=5) as sock:
        try:
            with ctx.wrap_socket(sock, server_hostname="broker") as tls:
                tls.sendall(b"\x10\x00")  # nonsense bytes; we only care about the alert
                data = tls.recv(1024)
                return f"accepted:{tls.version()}:{data!r}"
        except ssl.SSLError as exc:
            return f"rejected:{exc.reason}"
        except (ConnectionResetError, BrokenPipeError) as exc:
            return f"reset:{type(exc).__name__}"


def test_valid_device_cert_connects():
    settings = identity("devices", "device-01")
    client = make_client(f"test-ok-{uuid.uuid4().hex[:6]}", settings)
    try:
        rc = connect_blocking(client, settings)
        assert rc is not None and not rc.is_failure, f"CONNACK: {rc}"
    finally:
        client.loop_stop()
        client.disconnect()


def test_no_client_cert_is_rejected_by_tls():
    outcome = raw_tls_attempt(cert=None, key=None)
    print("no-cert outcome:", outcome)
    assert outcome.startswith("rejected:"), outcome
    assert "CERTIFICATE_REQUIRED" in outcome  # TLS 1.3 alert 116


def test_foreign_ca_cert_is_rejected_by_tls():
    # The rogue cert even claims CN=device-01, but is signed by a CA the broker never trusted.
    outcome = raw_tls_attempt(cert=f"{PKI}/rogue/rogue.crt", key=f"{PKI}/rogue/rogue.key")
    print("foreign-CA outcome:", outcome)
    assert outcome.startswith("rejected:"), outcome
    assert "UNKNOWN_CA" in outcome  # alert 48


def test_rogue_never_gets_connack():
    settings = MqttSettings(ca=CA, cert=f"{PKI}/rogue/rogue.crt", key=f"{PKI}/rogue/rogue.key")
    client = make_client("device-01", settings)
    try:
        assert connect_blocking(client, settings, timeout=5) is None
    finally:
        client.loop_stop()


def test_plaintext_port_1883_is_closed():
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("broker", 1883), timeout=5)


class Recorder:
    """Subscribes as the ingest service and records what arrives."""

    def __init__(self, topic: str):
        self.settings = identity("services", "ingest")
        self.client = make_client(f"test-ingest-{uuid.uuid4().hex[:6]}", self.settings)
        self.messages: list[tuple[str, bytes]] = []
        self.subscribed = threading.Event()
        self.client.on_message = lambda c, u, m: self.messages.append((m.topic, m.payload))
        self.client.on_subscribe = lambda c, u, mid, rcs, p: self.subscribed.set()
        rc = connect_blocking(self.client, self.settings)
        assert rc is not None and not rc.is_failure
        self.client.subscribe(topic, qos=1)
        assert self.subscribed.wait(5)

    def close(self):
        self.client.loop_stop()
        self.client.disconnect()


def publish_and_get_reason(client: mqtt.Client, topic: str, payload: bytes) -> mqtt.ReasonCode:
    """QoS 1 publish; MQTT v5 PUBACK carries the broker's verdict (0x87 = not authorized)."""
    done = threading.Event()
    got: dict[str, mqtt.ReasonCode] = {}

    def on_publish(c, userdata, mid, reason_code, properties):
        got["rc"] = reason_code
        done.set()

    client.on_publish = on_publish
    client.publish(topic, payload, qos=1).wait_for_publish(5)
    assert done.wait(5)
    return got["rc"]


def test_acl_device_can_publish_only_its_own_topic():
    recorder = Recorder("devices/+/telemetry")
    settings = identity("devices", "device-01")
    dev = make_client(f"test-acl-{uuid.uuid4().hex[:6]}", settings)
    # Unique marker payloads so the test is robust when the real fleet is also publishing
    # legitimate device-02 telemetry on the same topic.
    own_marker = f"own-{uuid.uuid4().hex}".encode()
    spoof_marker = f"spoof-{uuid.uuid4().hex}".encode()
    try:
        assert not connect_blocking(dev, settings).is_failure
        own = publish_and_get_reason(dev, "devices/device-01/telemetry", own_marker)
        spoof = publish_and_get_reason(dev, "devices/device-02/telemetry", spoof_marker)
        time.sleep(1.0)
        print("own topic PUBACK:", own, "| other device's topic PUBACK:", spoof)
        assert not own.is_failure
        assert spoof.value == 0x87, spoof  # Not authorized
        # device-01's own publish is delivered; its spoof onto device-02's topic never is
        # (legitimate device-02 traffic from the live fleet is irrelevant — we match the marker).
        assert ("devices/device-01/telemetry", own_marker) in recorder.messages
        assert ("devices/device-02/telemetry", spoof_marker) not in recorder.messages
    finally:
        dev.loop_stop()
        dev.disconnect()
        recorder.close()


def test_acl_device_cannot_read_other_devices():
    """device-01 subscribes to every device's telemetry; it must receive none of device-02's.

    Mosquitto grants the wildcard SUBACK and enforces the read ACL per message at
    delivery time, so the property is checked on delivery, not on the SUBACK code.
    """
    spy_settings = identity("devices", "device-01")
    spy = make_client(f"test-spy-{uuid.uuid4().hex[:6]}", spy_settings)
    received: list[str] = []
    subscribed = threading.Event()
    suback = {}

    def on_subscribe(c, userdata, mid, reason_codes, properties):
        suback["rcs"] = reason_codes
        subscribed.set()

    spy.on_subscribe = on_subscribe
    spy.on_message = lambda c, u, m: received.append(m.topic)
    victim_settings = identity("devices", "device-02")
    victim = make_client(f"test-victim-{uuid.uuid4().hex[:6]}", victim_settings)
    try:
        assert not connect_blocking(spy, spy_settings).is_failure
        spy.subscribe("devices/+/telemetry", qos=1)
        assert subscribed.wait(5)
        assert not connect_blocking(victim, victim_settings).is_failure
        rc = publish_and_get_reason(victim, "devices/device-02/telemetry", b"private")
        assert not rc.is_failure  # the victim's own publish is legitimate
        time.sleep(1.5)
        print("SUBACK for devices/+/telemetry:", suback["rcs"], "| spy received:", received)
        assert "devices/device-02/telemetry" not in received
    finally:
        for c in (spy, victim):
            c.loop_stop()
            c.disconnect()
