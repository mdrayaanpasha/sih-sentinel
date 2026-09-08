"""Throughput benchmark: sustained flows/sec through the detection stack.

Generates a realistic mix of flows and runs them through the full 6-detector stack
with real Redis state (the actual per-flow work a worker does), reporting sustained
flows/sec. This is the pipeline's processing capacity — scale horizontally by running
more worker processes in the Kafka consumer group.

    uv run python -m bench.throughput --flows 50000
"""

from __future__ import annotations

import argparse
import time

from common.schema import FlowRecord
from workers.registry import build_detectors
from workers.state import client


def synth_flows(n: int):
    """A mix mirroring the lab scenarios so every detector does real work."""
    base = 1_700_000_000.0
    for i in range(n):
        kind = i % 10
        if kind < 5:  # benign web
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001 + 0.5,
                src_ip=f"10.1.0.{10 + i % 40}", src_port=40000 + i % 20000, dst_ip="10.0.0.10",
                dst_port=443, protocol=6, src2dst_packets=6, src2dst_bytes=3000,
                dst2src_packets=8, dst2src_bytes=9000, src2dst_mean_ps=500,
                app_protocol="TLS",
            )
        elif kind == 5:  # scan-ish
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001,
                src_ip="10.2.0.5", src_port=41000 + i % 5000, dst_ip="10.0.0.20",
                dst_port=i % 65535, protocol=6, src2dst_packets=1, src2dst_bytes=60, syn_count=1,
            )
        elif kind == 6:  # flood-ish
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001,
                src_ip=f"198.51.100.{1 + i % 250}", src_port=30000 + i % 20000, dst_ip="10.0.0.30",
                dst_port=80, protocol=6, src2dst_packets=1, src2dst_bytes=60, syn_count=1,
            )
        elif kind == 7:  # dns
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001,
                src_ip="10.2.0.7", src_port=51000 + i % 10000, dst_ip="10.0.0.10",
                dst_port=53, protocol=17, src2dst_packets=1, src2dst_bytes=40,
                app_protocol="DNS", dns_query=f"qz{i}xk{i*7%9973}vh.com",
            )
        elif kind == 8:  # tls small
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001 + 1,
                src_ip="10.2.0.8", src_port=46000 + i % 5000, dst_ip="203.0.113.9",
                dst_port=443, protocol=6, src2dst_packets=8, src2dst_bytes=720,
                dst2src_packets=6, dst2src_bytes=540, src2dst_mean_ps=90,
                src2dst_min_ps=88, src2dst_max_ps=92, app_protocol="TLS",
            )
        else:  # large outbound
            yield FlowRecord(
                flow_id=f"f{i}", ts_start=base + i * 0.001, ts_end=base + i * 0.001 + 2,
                src_ip=f"10.3.0.{1 + i % 200}", src_port=47000 + i % 5000, dst_ip="203.0.113.20",
                dst_port=443, protocol=6, src2dst_packets=200, src2dst_bytes=280000,
                dst2src_packets=6, dst2src_bytes=480, app_protocol="TLS",
            )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=50_000)
    ap.add_argument("--warmup", type=int, default=2000)
    args = ap.parse_args()

    detectors = build_detectors()
    client().flushall()

    flows = list(synth_flows(args.flows + args.warmup))

    # warmup (populate state, JIT caches)
    for f in flows[: args.warmup]:
        for d in detectors:
            d.score(f)

    work = flows[args.warmup:]
    alerts = 0
    t0 = time.perf_counter()
    for f in work:
        for d in detectors:
            if d.score(f) is not None:
                alerts += 1
    elapsed = time.perf_counter() - t0

    rate = len(work) / elapsed
    print(f"\nprocessed {len(work):,} flows in {elapsed:.2f}s")
    print(f"alerts: {alerts:,}")
    print(f"SUSTAINED THROUGHPUT: {rate:,.0f} flows/sec  (single worker, {len(detectors)} detectors, real Redis)")
    print(f"per-flow latency: {elapsed / len(work) * 1e6:.1f} µs")
    print("scale-out: N worker processes in the consumer group ≈ N× this (state is shared Redis).")


if __name__ == "__main__":
    main()
