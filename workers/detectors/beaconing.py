"""Botnet C2 beaconing detection.

Infected hosts phone home on a fixed cadence to a small set of destinations. The tell
is *regularity*: inter-arrival times between connections to the same destination have a
very low coefficient of variation (near-constant spacing), usually with small, similar
payloads. Humans and normal apps are bursty; beacons are metronomic.

State (per src->dst pair): a capped series of recent flow-start timestamps.
"""

from __future__ import annotations

from common.schema import Alert, FlowRecord, ThreatClass
from workers.detectors.base import Detector, severity_from_confidence
from workers.features import coefficient_of_variation, inter_arrivals
from workers.state import TimestampSeries

MIN_EVENTS = 6          # need enough beacons to trust the timing
CV_THRESHOLD = 0.15     # below this, spacing is suspiciously regular
MIN_MEAN_INTERVAL = 1.5     # sub-second regular bursts are scans/floods/tunneling, not beacons
MAX_MEAN_INTERVAL = 3600.0  # ignore ultra-slow cadences for the prototype


class BeaconingDetector(Detector):
    name = "beaconing"

    def score(self, flow: FlowRecord) -> Alert | None:
        pair = f"{flow.src_ip}->{flow.dst_ip}"
        series = TimestampSeries(f"beacon:{pair}")
        times = series.add(flow.ts_start)
        if len(times) < MIN_EVENTS:
            return None

        iats = inter_arrivals(times)
        if len(iats) < MIN_EVENTS - 1:
            return None
        cv = coefficient_of_variation(iats)
        mean_interval = sum(iats) / len(iats)
        if (
            cv > CV_THRESHOLD
            or not (MIN_MEAN_INTERVAL <= mean_interval <= MAX_MEAN_INTERVAL)
        ):
            return None

        # lower CV => higher confidence; also reward more observed beacons
        conf_cv = 1.0 - (cv / CV_THRESHOLD)
        conf_n = min(1.0, (len(times) - MIN_EVENTS) / 10.0)
        confidence = min(1.0, 0.6 + 0.3 * conf_cv + 0.1 * conf_n)

        return Alert.from_flow(
            flow,
            threat_class=ThreatClass.BEACONING,
            confidence=round(confidence, 3),
            severity=severity_from_confidence(confidence),
            evidence={
                "beacon_count": len(times),
                "mean_interval_s": round(mean_interval, 2),
                "cv": round(cv, 4),
                "mean_payload_bytes": round(flow.src2dst_mean_ps, 1),
            },
        )
