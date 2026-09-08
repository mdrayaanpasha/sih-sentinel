"""Generate a small synthetic pcap offline (no scapy / no root / no network).

Writes Ethernet/IPv4 + TCP|UDP packets straight to the classic pcap format so
nfstream can turn them into flows. Includes:
  * a normal TCP session (handshake + data + teardown)
  * a DNS query (UDP/53) carrying a domain name -> populates dns_query
  * a horizontal port-scan burst (one src -> many dst ports, lone SYNs)

    uv run python -m tools.make_sample_pcap data/sample.pcap
"""

from __future__ import annotations

import struct
import sys

PCAP_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET=1


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) + src_b + dst_b
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr + payload


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    offset = (5 << 4)
    hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, offset, flags, 65535, 0, 0)
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(domain: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN


def _eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload


def _rec(ts: float, frame: bytes) -> bytes:
    sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def build() -> bytes:
    out = [PCAP_GLOBAL]
    t = 1_700_000_000.0

    def add(ts, ip):
        out.append(_rec(ts, _eth(ip)))

    # 1) normal TCP session 10.0.0.5 -> 10.0.0.9:443
    SYN, SA, ACK, PA, FA = 0x02, 0x12, 0x10, 0x18, 0x11
    add(t + 0.00, _ipv4("10.0.0.5", "10.0.0.9", 6, _tcp(51000, 443, 1000, 0, SYN)))
    add(t + 0.01, _ipv4("10.0.0.9", "10.0.0.5", 6, _tcp(443, 51000, 5000, 1001, SA)))
    add(t + 0.02, _ipv4("10.0.0.5", "10.0.0.9", 6, _tcp(51000, 443, 1001, 5001, ACK)))
    add(t + 0.03, _ipv4("10.0.0.5", "10.0.0.9", 6, _tcp(51000, 443, 1001, 5001, PA, b"x" * 200)))
    add(t + 0.05, _ipv4("10.0.0.9", "10.0.0.5", 6, _tcp(443, 51000, 5001, 1201, PA, b"y" * 800)))
    add(t + 0.07, _ipv4("10.0.0.5", "10.0.0.9", 6, _tcp(51000, 443, 1201, 5801, FA)))

    # 2) DNS query 10.0.0.5 -> 8.8.8.8
    add(t + 0.10, _ipv4("10.0.0.5", "8.8.8.8", 17, _udp(53101, 53, _dns_query("example.com"))))

    # 3) horizontal port scan: 10.0.0.66 -> 10.0.0.9 across many ports, lone SYNs
    for i, port in enumerate(range(20, 20 + 60)):
        add(t + 1.0 + i * 0.002, _ipv4("10.0.0.66", "10.0.0.9", 6, _tcp(40000 + i, port, 7, 0, SYN)))

    return b"".join(out)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.pcap"
    with open(path, "wb") as f:
        f.write(build())
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
