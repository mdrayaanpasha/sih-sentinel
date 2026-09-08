"""Port-scan detection.

One source touching many distinct (host, port) targets in a short window, with flows
that look like probes (few packets, little/no response), indicates scanning. We also
separate horizontal (many hosts) from vertical (many ports on one host).

State: a per-source sliding window of "dst_ip:dst_port" members over WINDOW_S seconds.
"""

from __future__ import annotations

from common.schema import Alert, FlowRecord, ThreatClass
from workers.detectors.base import Detector, severity_from_confidence
from workers.features import TCP
from workers.state import SlidingWindow

WINDOW_S = 10.0
MIN_TARGETS = 20          # distinct host:port pairs in window before we alert
STRONG_TARGETS = 100      # count at/above which confidence saturates


class PortScanDetector(Detector):
    name = "portscan"

    def score(self, flow: FlowRecord) -> Alert | None:
        # Probe-like: TCP with essentially no reply. Skip well-established, chatty flows.
        if flow.protocol != TCP:
            return None
        if flow.dst2src_packets > 0 and flow.src2dst_bytes > 512:
            return None

        win = SlidingWindow(f"scan:{flow.src_ip}", WINDOW_S)
        members = win.add_members(f"{flow.dst_ip}:{flow.dst_port}", flow.ts_end)
        n_targets = len(members)
        if n_targets < MIN_TARGETS:
            return None

        hosts = {m.rsplit(":", 1)[0] for m in members}
        ports = {m.rsplit(":", 1)[1] for m in members}
        if len(hosts) > len(ports):
            kind = "horizontal"  # many hosts (few ports)
        elif len(ports) > len(hosts):
            kind = "vertical"    # many ports on few hosts
        else:
            kind = "mixed"

        confidence = min(1.0, 0.5 + 0.5 * (n_targets - MIN_TARGETS) / (STRONG_TARGETS - MIN_TARGETS))
        return Alert.from_flow(
            flow,
            threat_class=ThreatClass.PORTSCAN,
            confidence=round(confidence, 3),
            severity=severity_from_confidence(confidence),
            evidence={
                "distinct_targets": n_targets,
                "distinct_hosts": len(hosts),
                "distinct_ports": len(ports),
                "scan_type": kind,
                "window_s": WINDOW_S,
            },
        )
