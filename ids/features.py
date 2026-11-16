"""The single feature extractor for the IDS: pcap -> per-client, per-window features.

Used unchanged on the live fleet's pcaps (MQTT over TLS, port 8883) AND on MQTTset's
pcaps (plaintext MQTT, port 1883). It therefore uses only what is visible on the wire
under TLS: packet/byte counts, payload sizes, timing, TCP flags and connection counts.
No MQTT fields, no payload content, and no IPs or ports as features (IPs are only
the grouping key and the join key for ground-truth labels).

A row = one client IP talking to the broker during one aligned window
[k*W, (k+1)*W). "up" = client -> broker, "down" = broker -> client.
Which features an attacker controls is documented in docs/FEATURES.md.
"""

from __future__ import annotations

import math
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

import dpkt

WINDOW_S = 5.0

FEATURES = [
    "pkts_up", "pkts_down", "bytes_up", "bytes_down",
    "data_pkts_up", "payload_up", "payload_down",
    "payload_up_mean", "payload_up_std", "payload_up_max",
    "iat_up_mean", "iat_up_std", "iat_up_min",
    "syn_up", "fin_up", "rst_any", "conns",
    "bytes_ratio_up_down", "active_s",
]


# Readable name and unit for every feature (shown next to the raw name in the console).
# Unit is (singular, plural); None means a plain ratio. Gaps are stored in seconds.
FEATURE_INFO = {
    "pkts_up": ("Packets to the broker", ("packet", "packets")),
    "pkts_down": ("Packets from the broker", ("packet", "packets")),
    "bytes_up": ("Bytes to the broker", ("B", "B")),
    "bytes_down": ("Bytes from the broker", ("B", "B")),
    "data_pkts_up": ("Packets with payload to the broker", ("packet", "packets")),
    "payload_up": ("Payload to the broker", ("B", "B")),
    "payload_down": ("Payload from the broker", ("B", "B")),
    "payload_up_mean": ("Mean payload per packet", ("B", "B")),
    "payload_up_std": ("Spread of payload sizes", ("B", "B")),
    "payload_up_max": ("Largest payload", ("B", "B")),
    "iat_up_mean": ("Mean gap between packets", ("s", "s")),
    "iat_up_std": ("Spread of gaps between packets", ("s", "s")),
    "iat_up_min": ("Shortest gap between packets", ("s", "s")),
    "syn_up": ("Connections opened", ("connection", "connections")),
    "fin_up": ("Connections closed", ("connection", "connections")),
    "rst_any": ("Connection resets", ("reset", "resets")),
    "conns": ("Parallel connections", ("connection", "connections")),
    "bytes_ratio_up_down": ("Bytes up per byte down", None),
    "active_s": ("Time active in the window", ("s", "s")),
}
assert set(FEATURE_INFO) == set(FEATURES)

@dataclass
class _Acc:
    """Accumulates one (client, window)."""
    pkts_up: int = 0
    pkts_down: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    payload_up: int = 0
    payload_down: int = 0
    syn_up: int = 0
    fin_up: int = 0
    rst_any: int = 0
    sizes_up: list = field(default_factory=list)
    times_up: list = field(default_factory=list)
    ports: set = field(default_factory=set)
    first: float = math.inf
    last: float = -math.inf

    def row(self) -> dict:
        n = len(self.sizes_up)
        mean = sum(self.sizes_up) / n if n else 0.0
        std = math.sqrt(sum((s - mean) ** 2 for s in self.sizes_up) / n) if n else 0.0
        iats = [b - a for a, b in zip(self.times_up, self.times_up[1:])]
        iat_mean = sum(iats) / len(iats) if iats else WINDOW_S
        iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats)) if iats else 0.0
        return {
            "pkts_up": self.pkts_up, "pkts_down": self.pkts_down,
            "bytes_up": self.bytes_up, "bytes_down": self.bytes_down,
            "data_pkts_up": n, "payload_up": self.payload_up, "payload_down": self.payload_down,
            "payload_up_mean": mean, "payload_up_std": std, "payload_up_max": max(self.sizes_up, default=0),
            "iat_up_mean": iat_mean, "iat_up_std": iat_std, "iat_up_min": min(iats, default=WINDOW_S),
            "syn_up": self.syn_up, "fin_up": self.fin_up, "rst_any": self.rst_any, "conns": len(self.ports),
            "bytes_ratio_up_down": self.bytes_up / (self.bytes_down + 1),
            "active_s": max(0.0, self.last - self.first),
        }


def _ip_layer(linktype: int, buf: bytes):
    """Return the IPv4/IPv6 packet for the link types we meet (Ethernet, SLL, raw, loopback)."""
    if linktype == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if linktype in (dpkt.pcap.DLT_RAW, 101, 228):
        return dpkt.ip.IP(buf) if buf[0] >> 4 == 4 else dpkt.ip6.IP6(buf)
    if linktype in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
        return dpkt.loopback.Loopback(buf).data
    raise ValueError(f"unsupported link type {linktype}")


def _addr(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


def packets(pcap_path: str | Path) -> Iterator[tuple[float, str, int, str, int, int, int, int]]:
    """Yield (ts, src, sport, dst, dport, ip_len, payload_len, tcp_flags) for TCP packets."""
    with open(pcap_path, "rb") as fh:
        try:
            reader = dpkt.pcap.Reader(fh)
        except ValueError:
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh)
        linktype = reader.datalink()
        for ts, buf in reader:
            try:
                ip = _ip_layer(linktype, buf)
            except (dpkt.UnpackError, ValueError, IndexError):
                continue
            tcp = getattr(ip, "data", None)
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            ip_len = ip.len if isinstance(ip, dpkt.ip.IP) else ip.plen + 40
            yield (float(ts), _addr(ip.src), tcp.sport, _addr(ip.dst), tcp.dport,
                   ip_len, len(tcp.data), tcp.flags)


def extract(
    pcap_paths: Iterable[str | Path],
    broker_port: int,
    broker_ip: str | None = None,
    window_s: float = WINDOW_S,
) -> list[dict]:
    """Feature rows for every (client IP, window) seen talking to the broker port."""
    acc: dict[tuple[str, float], _Acc] = defaultdict(_Acc)
    for path in pcap_paths:
        for ts, src, sport, dst, dport, ip_len, plen, flags in packets(path):
            if dport == broker_port and (broker_ip is None or dst == broker_ip):
                client, up, cport = src, True, sport
            elif sport == broker_port and (broker_ip is None or src == broker_ip):
                client, up, cport = dst, False, dport
            else:
                continue
            a = acc[(client, math.floor(ts / window_s) * window_s)]
            a.first, a.last = min(a.first, ts), max(a.last, ts)
            a.ports.add(cport)
            if flags & dpkt.tcp.TH_RST:
                a.rst_any += 1
            if up:
                a.pkts_up += 1
                a.bytes_up += ip_len
                a.payload_up += plen
                if plen:
                    a.sizes_up.append(plen)
                    a.times_up.append(ts)
                if flags & dpkt.tcp.TH_SYN and not flags & dpkt.tcp.TH_ACK:
                    a.syn_up += 1
                if flags & dpkt.tcp.TH_FIN:
                    a.fin_up += 1
            else:
                a.pkts_down += 1
                a.bytes_down += ip_len
                a.payload_down += plen
    rows = []
    for (client, start), a in sorted(acc.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        rows.append({"client_ip": client, "window_start": start, "window_s": window_s, **a.row()})
    return rows
