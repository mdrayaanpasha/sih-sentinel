"""Data exfiltration detection.

Exfil looks like an abnormal amount of data leaving a host relative to what it
normally sends — a spike in outbound bytes and in the outbound:inbound ratio versus
that host's own baseline. We learn a per-host baseline online and flag deviations,
with a cold-start rule so blatant transfers alert before a baseline exists.

State (per src host): online mean/std of outbound bytes-per-flow (baseline).
"""

from __future__ import annotations

from common.schema import Alert, FlowRecord, ThreatClass
from workers.detectors.base import Detector, severity_from_confidence
from workers.features import outbound_inbound_ratio
from workers.state import Baseline

COLD_START_BYTES = 5_000_000      # 5 MB outbound in one flow -> alert regardless of baseline
COLD_START_RATIO = 20.0
MIN_ABS_BYTES = 200_000           # ignore tiny flows even if ratio is high
Z_THRESHOLD = 4.0                 # outbound bytes this many std above host baseline
MIN_BASELINE_N = 20               # observations before trusting the baseline


class ExfilDetector(Detector):
    name = "exfil"

    def score(self, flow: FlowRecord) -> Alert | None:
        out_bytes = flow.src2dst_bytes
        ratio = outbound_inbound_ratio(flow.src2dst_bytes, flow.dst2src_bytes)

        baseline = Baseline(f"exfil:{flow.src_ip}")
        z, n = baseline.observe(float(out_bytes))  # scores against baseline, then folds in

        # cold-start: obvious bulk transfer out
        if out_bytes >= COLD_START_BYTES and ratio >= COLD_START_RATIO:
            conf = min(1.0, 0.7 + 0.3 * min(1.0, out_bytes / (COLD_START_BYTES * 5)))
            return self._alert(flow, conf, out_bytes, ratio, z, n, "cold_start_bulk")

        # baseline deviation
        if n >= MIN_BASELINE_N and z >= Z_THRESHOLD and out_bytes >= MIN_ABS_BYTES and ratio >= 3.0:
            conf = min(1.0, 0.6 + 0.1 * (z - Z_THRESHOLD))
            return self._alert(flow, conf, out_bytes, ratio, z, n, "baseline_deviation")

        return None

    def _alert(self, flow, conf, out_bytes, ratio, z, n, subtype) -> Alert:
        return Alert.from_flow(
            flow,
            threat_class=ThreatClass.EXFIL,
            confidence=round(conf, 3),
            severity=severity_from_confidence(conf),
            evidence={
                "subtype": subtype,
                "outbound_bytes": out_bytes,
                "out_in_ratio": round(ratio, 2),
                "zscore_vs_baseline": round(z, 2),
                "baseline_samples": n,
            },
        )
