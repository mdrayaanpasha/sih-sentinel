"""Minimal offline pcap construction (Ethernet/IPv4 + TCP/UDP), no scapy/root/network.

Enough to synthesize labeled attack + benign traffic that nfstream turns into flows.
Packets are written full-size (incl_len == orig_len) so nfstream's byte accounting is real.
"""

from __future__ import annotations

import struct

PCAP_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET

SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK, RST = 0x02, 0x12, 0x10, 0x18, 0x11, 0x04


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) + src_b + dst_b
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(domain: str, qtype: int = 1) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".") if p) + b"\x00"
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", qtype, 1)


def eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload


class PcapWriter:
    """Accumulates timestamped Ethernet frames and writes a pcap file."""

    def __init__(self) -> None:
        self._recs: list[tuple[float, bytes]] = []

    def add_ip(self, ts: float, ip_packet: bytes) -> None:
        self._recs.append((ts, eth(ip_packet)))

    def tcp_flow(self, ts: float, src: str, dst: str, sport: int, dport: int,
                 n_out: int, out_size: int, n_in: int, in_size: int, gap: float = 0.001) -> float:
        """Emit a simple TCP session: handshake + data packets. Returns the last timestamp."""
        t = ts
        self.add_ip(t, ipv4(src, dst, 6, tcp(sport, dport, 1, 0, SYN))); t += gap
        self.add_ip(t, ipv4(dst, src, 6, tcp(dport, sport, 1, 2, SYN_ACK))); t += gap
        self.add_ip(t, ipv4(src, dst, 6, tcp(sport, dport, 2, 2, ACK))); t += gap
        for i in range(n_out):
            self.add_ip(t, ipv4(src, dst, 6, tcp(sport, dport, 2 + i, 2, PSH_ACK, b"\x00" * out_size)))
            t += gap
        for i in range(n_in):
            self.add_ip(t, ipv4(dst, src, 6, tcp(dport, sport, 2 + i, 2, PSH_ACK, b"\x00" * in_size)))
            t += gap
        self.add_ip(t, ipv4(src, dst, 6, tcp(sport, dport, 99, 2, FIN_ACK))); t += gap
        return t

    def bytes(self) -> bytes:
        self._recs.sort(key=lambda r: r[0])
        out = [PCAP_GLOBAL]
        for ts, frame in self._recs:
            sec, usec = int(ts), int((ts - int(ts)) * 1_000_000)
            out.append(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        return b"".join(out)

    def write(self, path: str) -> int:
        data = self.bytes()
        with open(path, "wb") as f:
            f.write(data)
        return len(self._recs)
