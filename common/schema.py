"""Wire contract shared by every stage of the pipeline.

FlowRecord  = ingest -> Kafka 'flows' -> workers
Alert       = workers -> Kafka 'alerts' + Postgres -> api -> dashboard

Keep this the single source of truth. Both models are plain pydantic so they
serialize to JSON (and msgpack via .model_dump()) without extra glue.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatClass(str, Enum):
    FLOOD = "flood"           # DDoS / volumetric floods
    BEACONING = "beaconing"   # botnet C2 beaconing
    DGA_DNS = "dga_dns"       # DGA domains + DNS tunneling
    TLS_MALWARE = "tls_malware"  # malware in encrypted sessions (metadata only)
    PORTSCAN = "portscan"     # horizontal/vertical port scanning
    EXFIL = "exfil"           # data exfiltration


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FlowRecord(BaseModel):
    """A single bidirectional flow emitted by nfstream.

    Direction convention: `src` is the flow initiator (nfstream src2dst),
    `dst` is the responder. Byte/packet counts are per direction so detectors
    can reason about outbound-vs-inbound ratios without re-deriving them.
    """

    flow_id: str                       # stable id: hash of 5-tuple + start time
    ts_start: float                    # epoch seconds, first packet
    ts_end: float                      # epoch seconds, last packet
    duration_ms: float = 0.0

    # 5-tuple
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int                      # IANA L4 proto number (6=TCP, 17=UDP)

    # volume, per direction
    src2dst_packets: int = 0
    src2dst_bytes: int = 0
    dst2src_packets: int = 0
    dst2src_bytes: int = 0

    # early / statistical features (subset of nfstream's; extended as needed)
    src2dst_min_ps: int = 0            # min packet size src->dst
    src2dst_max_ps: int = 0
    src2dst_mean_ps: float = 0.0
    dst2src_mean_ps: float = 0.0
    src2dst_mean_piat_ms: float = 0.0  # mean inter-arrival time
    bidirectional_mean_piat_ms: float = 0.0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    # application-layer metadata (no payload decryption)
    app_protocol: str | None = None    # nfstream ndpi guess, e.g. "TLS.Google"
    sni: str | None = None             # TLS server name (cleartext in handshake)
    ja3: str | None = None             # client TLS fingerprint
    ja3s: str | None = None            # server TLS fingerprint
    ja4: str | None = None
    dns_query: str | None = None       # queried domain name
    dns_qtype: str | None = None       # A, AAAA, TXT, NULL, ...

    def key_src(self) -> str:
        return self.src_ip

    def key_pair(self) -> str:
        return f"{self.src_ip}->{self.dst_ip}"


class Alert(BaseModel):
    """Standardized alert. Every detector emits exactly this shape."""

    ts: float                          # epoch seconds when the alert fired
    flow_id: str
    threat_class: ThreatClass
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_flow(
        cls,
        flow: FlowRecord,
        threat_class: ThreatClass,
        confidence: float,
        severity: Severity,
        evidence: dict[str, Any],
        ts: float | None = None,
    ) -> "Alert":
        return cls(
            ts=ts if ts is not None else flow.ts_end,
            flow_id=flow.flow_id,
            threat_class=threat_class,
            confidence=confidence,
            severity=severity,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            evidence=evidence,
        )
