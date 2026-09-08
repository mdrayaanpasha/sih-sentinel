"""Flood / DDoS detection.

Volumetric floods show up as a spike in flows/packets toward one destination from
many (often spoofed/random) sources, frequently as half-open SYNs. We track, per
destination over a short window: flow rate, distinct source-IP count, and bare-SYN
rate (SYN with no completing ACK) — the classic SYN-flood signature.

State (per dst): a rolling flow-rate counter, a sliding window of distinct source IPs,
and a bare-SYN rate counter.
"""

from __future__ import annotations

from common.schema import Alert, FlowRecord, ThreatClass
from workers.detectors.base import Detector, severity_from_confidence
from workers.features import TCP
from workers.state import SlidingWindow, incr_window_counter

WINDOW_S = 5.0
MIN_SOURCES = 40          # distinct sources toward one dst in window
MIN_FLOW_RATE = 200.0     # flows/window toward one dst
SATURATE_SOURCES = 300


class FloodDetector(Detector):
    name = "flood"

    def score(self, flow: FlowRecord) -> Alert | None:
        dst = flow.dst_ip
        # per-dst rolling flow count
        flow_rate = incr_window_counter(f"flood:flows:{dst}", WINDOW_S, flow.ts_end, 1.0)
        # distinct sources hammering this dst
        srcs = SlidingWindow(f"flood:srcs:{dst}", WINDOW_S)
        src_count = srcs.add_count(flow.src_ip, flow.ts_end)

        # bare-SYN signature (half-open connections)
        is_bare_syn = flow.protocol == TCP and flow.syn_count >= 1 and flow.ack_count == 0
        syn_rate = (
            incr_window_counter(f"flood:syn:{dst}", WINDOW_S, flow.ts_end, 1.0)
            if is_bare_syn
            else incr_window_counter(f"flood:syn:{dst}", WINDOW_S, flow.ts_end, 0.0)
        )

        volumetric = src_count >= MIN_SOURCES or flow_rate >= MIN_FLOW_RATE
        synflood = syn_rate >= MIN_FLOW_RATE
        if not (volumetric or synflood):
            return None

        # confidence driven by the strongest signal
        by_src = (src_count - MIN_SOURCES) / (SATURATE_SOURCES - MIN_SOURCES)
        by_rate = (max(flow_rate, syn_rate) - MIN_FLOW_RATE) / (MIN_FLOW_RATE * 4)
        confidence = min(1.0, 0.55 + 0.45 * max(by_src, by_rate))

        return Alert.from_flow(
            flow,
            threat_class=ThreatClass.FLOOD,
            confidence=round(confidence, 3),
            severity=severity_from_confidence(confidence),
            evidence={
                "distinct_sources": src_count,
                "flow_rate_per_window": round(flow_rate, 1),
                "bare_syn_rate_per_window": round(syn_rate, 1),
                "window_s": WINDOW_S,
                "signature": "syn_flood" if synflood else "volumetric",
            },
        )
