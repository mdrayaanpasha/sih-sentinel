"""Detector smoke tests. Require Redis to be up (docker compose up -d)."""

import pytest

from common.schema import FlowRecord, ThreatClass
from workers.detectors.dga_dns import DgaDnsDetector
from workers.detectors.portscan import PortScanDetector

redis = pytest.importorskip("redis")


@pytest.fixture(autouse=True)
def _flush_redis():
    from workers.state import client

    try:
        client().flushall()
    except redis.exceptions.ConnectionError:
        pytest.skip("Redis not available")
    yield


def _syn(src, dst, dport, ts):
    return FlowRecord(
        flow_id=f"{src}-{dport}", ts_start=ts, ts_end=ts, src_ip=src, src_port=40000 + dport,
        dst_ip=dst, dst_port=dport, protocol=6, src2dst_packets=1, src2dst_bytes=60, syn_count=1,
    )


def test_portscan_fires_after_threshold():
    det = PortScanDetector()
    alert = None
    for port in range(20, 20 + 40):
        alert = det.score(_syn("10.9.9.9", "10.0.0.1", port, 1_700_000_000.0))
    assert alert is not None
    assert alert.threat_class == ThreatClass.PORTSCAN
    assert alert.evidence["scan_type"] == "vertical"


def test_portscan_quiet_on_normal_traffic():
    det = PortScanDetector()
    # a normal established flow with a response and real data must not alert
    f = FlowRecord(
        flow_id="ok", ts_start=1.0, ts_end=2.0, src_ip="10.0.0.5", src_port=51000,
        dst_ip="10.0.0.9", dst_port=443, protocol=6, src2dst_packets=5, src2dst_bytes=4000,
        dst2src_packets=6, dst2src_bytes=9000,
    )
    assert det.score(f) is None


def test_dga_detects_gibberish_domain():
    det = DgaDnsDetector()
    f = FlowRecord(
        flow_id="d", ts_start=1.0, ts_end=1.0, src_ip="10.2.0.7", src_port=51000,
        dst_ip="10.0.0.10", dst_port=53, protocol=17, src2dst_packets=1, src2dst_bytes=40,
        app_protocol="DNS", dns_query="kxqvwzptrlmnab.com",
    )
    alert = det.score(f)
    assert alert is not None
    assert alert.threat_class == ThreatClass.DGA_DNS
    assert alert.evidence["subtype"] == "dga"


def test_dga_quiet_on_benign_domain():
    det = DgaDnsDetector()
    f = FlowRecord(
        flow_id="d2", ts_start=1.0, ts_end=1.0, src_ip="10.1.0.5", src_port=51001,
        dst_ip="10.0.0.10", dst_port=53, protocol=17, src2dst_packets=1, src2dst_bytes=40,
        app_protocol="DNS", dns_query="google.com",
    )
    assert det.score(f) is None
