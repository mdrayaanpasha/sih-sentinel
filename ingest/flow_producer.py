"""Ingest spine: pcap (or live iface) -> nfstream -> FlowRecord -> Kafka 'flows'.

This is the ONLY component that touches raw packets, and it only ever *reads*
them (pcap file or promiscuous capture). No packet is ever emitted back onto any
network — the diode/passivity invariant lives here.

    uv run python -m ingest.flow_producer --pcap data/sample.pcap
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time

from confluent_kafka import Producer
from nfstream import NFStreamer

from common.config import settings
from common.schema import FlowRecord
from common.serde import encode


def _stable_flow_id(nflow) -> str:
    """Globally stable id: 5-tuple + first-seen time. nflow.id is only a per-run counter."""
    raw = (
        f"{nflow.src_ip}:{nflow.src_port}-{nflow.dst_ip}:{nflow.dst_port}"
        f"-{nflow.protocol}-{nflow.bidirectional_first_seen_ms}"
    )
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _dns_fields(nflow) -> tuple[str | None, str | None, str | None]:
    """Return (sni, dns_query, app_protocol). nfstream exposes the queried name via
    requested_server_name for both TLS SNI and DNS."""
    app = getattr(nflow, "application_name", None) or None
    name = getattr(nflow, "requested_server_name", None) or None
    is_dns = bool(app) and "DNS" in app.upper()
    sni = None if is_dns else name
    dns_query = name if is_dns else None
    return sni, dns_query, app


def nflow_to_record(nflow) -> FlowRecord:
    sni, dns_query, app = _dns_fields(nflow)
    return FlowRecord(
        flow_id=_stable_flow_id(nflow),
        ts_start=nflow.bidirectional_first_seen_ms / 1000.0,
        ts_end=nflow.bidirectional_last_seen_ms / 1000.0,
        duration_ms=float(nflow.bidirectional_duration_ms),
        src_ip=nflow.src_ip,
        src_port=int(nflow.src_port),
        dst_ip=nflow.dst_ip,
        dst_port=int(nflow.dst_port),
        protocol=int(nflow.protocol),
        src2dst_packets=int(nflow.src2dst_packets),
        src2dst_bytes=int(nflow.src2dst_bytes),
        dst2src_packets=int(nflow.dst2src_packets),
        dst2src_bytes=int(nflow.dst2src_bytes),
        src2dst_min_ps=int(getattr(nflow, "src2dst_min_ps", 0)),
        src2dst_max_ps=int(getattr(nflow, "src2dst_max_ps", 0)),
        src2dst_mean_ps=float(getattr(nflow, "src2dst_mean_ps", 0.0)),
        dst2src_mean_ps=float(getattr(nflow, "dst2src_mean_ps", 0.0)),
        src2dst_mean_piat_ms=float(getattr(nflow, "src2dst_mean_piat_ms", 0.0)),
        bidirectional_mean_piat_ms=float(getattr(nflow, "bidirectional_mean_piat_ms", 0.0)),
        syn_count=int(getattr(nflow, "bidirectional_syn_packets", 0)),
        ack_count=int(getattr(nflow, "bidirectional_ack_packets", 0)),
        rst_count=int(getattr(nflow, "bidirectional_rst_packets", 0)),
        fin_count=int(getattr(nflow, "bidirectional_fin_packets", 0)),
        app_protocol=app,
        sni=sni,
        ja3=getattr(nflow, "client_fingerprint", None) or None,
        ja3s=getattr(nflow, "server_fingerprint", None) or None,
        ja4=None,  # nfstream exposes JA3 only; JA4 enrichment is future work
        dns_query=dns_query,
        dns_qtype=None,
    )


def make_streamer(source: str, is_live: bool) -> NFStreamer:
    # statistical_analysis -> per-direction ps/piat + TCP flag counts
    # n_dissections -> app protocol + SNI/DNS name + JA3/JA3S (metadata only, no payload)
    return NFStreamer(
        source=source,
        decode_tunnels=True,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=20,
        accounting_mode=3,
        promiscuous_mode=is_live,
    )


def run(source: str, is_live: bool, speed: float, limit: int | None) -> int:
    producer = Producer(
        {
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "linger.ms": 5,
            "compression.type": "lz4",
            "client.id": "sentinel-ingest",
        }
    )
    topic = settings.kafka_flows_topic
    streamer = make_streamer(source, is_live)

    count = 0
    prev_end: float | None = None
    t0 = time.time()
    for nflow in streamer:
        rec = nflow_to_record(nflow)

        # Optional replay pacing: reproduce inter-flow gaps (÷ speed). speed<=0 = as fast as possible.
        if speed > 0 and not is_live:
            if prev_end is not None:
                gap = (rec.ts_end - prev_end) / speed
                if gap > 0:
                    time.sleep(min(gap, 2.0))
            prev_end = rec.ts_end

        producer.produce(topic, key=rec.src_ip.encode(), value=encode(rec))
        producer.poll(0)
        count += 1
        if count % 1000 == 0:
            producer.flush()
            print(f"  produced {count} flows...", file=sys.stderr)
        if limit is not None and count >= limit:
            break

    producer.flush()
    elapsed = time.time() - t0
    rate = count / elapsed if elapsed else 0.0
    print(f"done: {count} flows -> '{topic}' in {elapsed:.1f}s ({rate:.0f} flows/s)", file=sys.stderr)
    return count


def main() -> None:
    ap = argparse.ArgumentParser(description="pcap/live -> nfstream -> Kafka 'flows'")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="path to a pcap/pcapng file to replay")
    src.add_argument("--iface", help="live interface (passive capture)")
    ap.add_argument(
        "--speed",
        type=float,
        default=0.0,
        help="replay pacing multiplier (pcap only). 0=as fast as possible, 1=realtime, 10=10x",
    )
    ap.add_argument("--limit", type=int, default=None, help="stop after N flows")
    args = ap.parse_args()

    source = args.pcap if args.pcap else args.iface
    run(source=source, is_live=bool(args.iface), speed=args.speed, limit=args.limit)


if __name__ == "__main__":
    main()
