"""Assemble the active detector set. Add new detectors here to plug them into the worker."""

from __future__ import annotations

from workers.detectors.base import Detector


def build_detectors() -> list[Detector]:
    from workers.detectors.beaconing import BeaconingDetector
    from workers.detectors.dga_dns import DgaDnsDetector
    from workers.detectors.exfil import ExfilDetector
    from workers.detectors.flood import FloodDetector
    from workers.detectors.portscan import PortScanDetector
    from workers.detectors.tls_fingerprint import TlsMalwareDetector

    return [
        PortScanDetector(),
        FloodDetector(),
        BeaconingDetector(),
        DgaDnsDetector(),
        TlsMalwareDetector(),
        ExfilDetector(),
    ]
