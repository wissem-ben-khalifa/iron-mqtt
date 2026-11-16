"""Evidence helper for attack #1 (rogue / spoofed device): produce rejected handshakes on the wire.

Attempts, from the tests container (172.28.0.250):
  1. legit   TLS 1.2, valid device-01 cert       -> accepted (cert visible in cleartext in 1.2)
  2. nocert  TLS 1.2, no client certificate      -> rejected, plaintext alert
  3. rogue   TLS 1.2, foreign-CA cert, CN=device-01 -> rejected, plaintext alert "unknown CA"
  4. rogue13 TLS 1.3, same rogue cert, keylog on -> rejected; alert is encrypted in 1.3, the
     keylog (written only under /captures/evidence) lets Wireshark decrypt it.
TLS 1.2 is used for evidence only: in 1.2 the client certificate travels in cleartext, which is
exactly what makes the rejection visible in Wireshark (and why 1.3 is better for privacy).

These are mutual-TLS evidence, never IDS detections.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import time

PKI = "/pki"


def attempt(name: str, cert: str | None, key: str | None, version: ssl.TLSVersion, keylog: str | None = None) -> str:
    ctx = ssl.create_default_context(cafile=f"{PKI}/ca/ca.crt")
    ctx.minimum_version = ctx.maximum_version = version
    if cert:
        ctx.load_cert_chain(cert, key)
    if keylog:
        assert keylog.startswith(("/captures/", "/secrets/")), keylog
        ctx.keylog_filename = keylog
    with socket.create_connection(("broker", 8883), timeout=5) as sock:
        try:
            with ctx.wrap_socket(sock, server_hostname="broker") as tls:
                # A minimal MQTT 3.1.1 CONNECT so an accepted session gets a CONNACK.
                tls.sendall(bytes.fromhex("101000044d5154540402003c0004") + b"demo")
                data = tls.recv(4)
                outcome = f"accepted ({tls.version()}), broker replied {data.hex()}"
        except ssl.SSLError as exc:
            outcome = f"rejected: {exc.reason}"
        except (ConnectionResetError, BrokenPipeError) as exc:
            outcome = f"rejected: connection {type(exc).__name__}"
    print(f"{time.strftime('%H:%M:%S')} {name:8} -> {outcome}")
    return outcome


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keylog", default="/captures/evidence/rogue-tls13.keylog")
    args = ap.parse_args()
    v12, v13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3
    attempt("legit", f"{PKI}/devices/device-01.crt", f"{PKI}/devices/device-01.key", v12)
    attempt("nocert", None, None, v12)
    attempt("rogue", f"{PKI}/rogue/rogue.crt", f"{PKI}/rogue/rogue.key", v12)
    attempt("rogue13", f"{PKI}/rogue/rogue.crt", f"{PKI}/rogue/rogue.key", v13, keylog=args.keylog)


if __name__ == "__main__":
    main()
