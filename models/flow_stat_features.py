"""Feature vector for encrypted-flow (TLS) classification — metadata only, no payload.
Shared by the trainer and the tls_malware detector."""

from __future__ import annotations

from common.schema import FlowRecord

FEATURE_NAMES = [
    "src2dst_mean_ps",
    "ps_spread",          # max - min packet size (uniformity)
    "src2dst_packets",
    "src2dst_mean_piat_ms",
    "out_in_ratio",
    "dst2src_mean_ps",
]


def flow_stat_vector(f: FlowRecord) -> list[float]:
    return [
        float(f.src2dst_mean_ps),
        float(f.src2dst_max_ps - f.src2dst_min_ps),
        float(f.src2dst_packets),
        float(f.src2dst_mean_piat_ms),
        float(f.src2dst_bytes) / max(f.dst2src_bytes, 1),
        float(f.dst2src_mean_ps),
    ]
