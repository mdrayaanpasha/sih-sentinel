"""Malware in encrypted sessions — detected from TLS metadata only, never decrypting.

Two metadata signals:
  * JA3/JA3S fingerprint match against a known-bad list (models/artifacts/ja3_blocklist.txt).
    A JA3 hash identifies the client TLS stack; malware families have characteristic ones.
  * Robotic size/timing: even encrypted, automated C2 over TLS tends to produce small,
    uniform request payloads at regular intervals — unlike human-driven browsing.

State: reuses beaconing-style timing via the flow's own stats; JA3 list loaded once.
"""

from __future__ import annotations

import os

from common.schema import Alert, FlowRecord, ThreatClass
from models.flow_stat_features import flow_stat_vector
from workers.detectors.base import Detector, severity_from_confidence

_BLOCKLIST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "models", "artifacts", "ja3_blocklist.txt"
)
_MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "models", "artifacts", "encrypted_flow_model.joblib"
)


def _load_blocklist() -> set[str]:
    path = os.path.abspath(_BLOCKLIST_PATH)
    if not os.path.exists(path):
        return set()
    out = set()
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.add(line.lower())
    return out


def _load_model():
    path = os.path.abspath(_MODEL_PATH)
    if not os.path.exists(path):
        return None
    try:
        import joblib

        model = joblib.load(path)
        if hasattr(model, "n_jobs"):
            model.n_jobs = 1
        return model
    except Exception:  # noqa: BLE001
        return None


class TlsMalwareDetector(Detector):
    name = "tls_malware"

    def __init__(self) -> None:
        self._blocklist = _load_blocklist()
        self._model = _load_model()

    def score(self, flow: FlowRecord) -> Alert | None:
        app = (flow.app_protocol or "").upper()
        is_tls = "TLS" in app or "SSL" in app or flow.ja3 is not None
        if not is_tls:
            return None

        # 1) known-bad JA3/JA3S fingerprint
        for fp, role in ((flow.ja3, "ja3"), (flow.ja3s, "ja3s")):
            if fp and fp.lower() in self._blocklist:
                return Alert.from_flow(
                    flow,
                    threat_class=ThreatClass.TLS_MALWARE,
                    confidence=0.95,
                    severity=severity_from_confidence(0.95),
                    evidence={"subtype": "ja3_blocklist", "matched": role, "fingerprint": fp,
                              "sni": flow.sni},
                )

        # 2) robotic encrypted flow: small, uniform payloads. Scored by the trained
        #    metadata model when present, else a heuristic. Only meaningful for flows with
        #    enough packets to characterize.
        if flow.src2dst_packets < 4 or flow.src2dst_mean_ps <= 0:
            return None
        # cheap pre-filter: human/browser TLS has large mean packet size — skip the model
        # for those so per-flow RF inference only runs on plausible C2 candidates.
        if flow.src2dst_mean_ps > 400:
            return None
        spread = flow.src2dst_max_ps - flow.src2dst_min_ps

        p = None
        if self._model is not None:
            try:
                p = float(self._model.predict_proba([flow_stat_vector(flow)])[0][1])
            except Exception:  # noqa: BLE001
                p = None

        heuristic_hit = flow.src2dst_mean_ps <= 200 and spread <= 60
        if (p is not None and p >= 0.6) or (p is None and heuristic_hit):
            conf = p if p is not None else 0.55
            return Alert.from_flow(
                flow,
                threat_class=ThreatClass.TLS_MALWARE,
                confidence=round(conf, 3),
                severity=severity_from_confidence(conf),
                evidence={
                    "subtype": "robotic_size_timing",
                    "score_method": "model" if p is not None else "heuristic",
                    "mean_ps": round(flow.src2dst_mean_ps, 1),
                    "ps_spread": spread,
                    "packets": flow.src2dst_packets,
                    "sni": flow.sni,
                },
            )
        return None
