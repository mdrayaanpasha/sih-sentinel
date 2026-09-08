"""DGA + DNS-tunneling detection (from DNS query metadata only).

Two sub-signals on the DNS query name:
  * DGA: algorithmically-generated gibberish domains. Scored by a trained classifier
    (models/artifacts/dga_model.joblib) when present, else an entropy/length heuristic.
  * DNS tunneling: data smuggled inside query names — abnormally long names, high
    subdomain entropy, and/or a high volume of unique queries under one parent domain.

State: per parent-domain sliding window of distinct query names (tunneling volume).
"""

from __future__ import annotations

import os

from common.schema import Alert, FlowRecord, ThreatClass
from models.dga_features import domain_feature_vector
from workers.detectors.base import Detector, severity_from_confidence
from workers.features import domain_labels, registrable_part, shannon_entropy
from workers.state import SlidingWindow

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "models", "artifacts", "dga_model.joblib")

TUNNEL_NAME_LEN = 50          # total query-name length suggestive of tunneling
TUNNEL_SUBDOMAIN_ENTROPY = 3.6
TUNNEL_WINDOW_S = 60.0
TUNNEL_MIN_UNIQUE = 40        # distinct names under one parent domain in window
DGA_HEURISTIC_ENTROPY = 3.8


class _DgaScorer:
    """Lazy-loads the trained model; falls back to a heuristic if absent."""

    def __init__(self) -> None:
        self._model = None
        self._tried = False

    def _load(self):
        if not self._tried:
            self._tried = True
            try:
                import joblib

                path = os.path.abspath(_MODEL_PATH)
                if os.path.exists(path):
                    self._model = joblib.load(path)
                    if hasattr(self._model, "n_jobs"):
                        self._model.n_jobs = 1
            except Exception:  # noqa: BLE001
                self._model = None
        return self._model

    def probability(self, name: str) -> tuple[float, str]:
        # cheap gate: benign dictionary/pronounceable labels have low entropy — skip the
        # model for those so per-flow RF inference only runs on gibberish-looking names.
        if shannon_entropy(registrable_part(name)) < 2.8:
            return 0.0, "prefilter"
        model = self._load()
        vec = domain_feature_vector(name)
        if model is not None:
            try:
                p = float(model.predict_proba([vec])[0][1])
                return p, "model"
            except Exception:  # noqa: BLE001
                pass
        # heuristic fallback: entropy of registrable label
        ent = shannon_entropy(registrable_part(name))
        p = min(1.0, max(0.0, (ent - DGA_HEURISTIC_ENTROPY) / (4.7 - DGA_HEURISTIC_ENTROPY)))
        return p, "heuristic"


class DgaDnsDetector(Detector):
    name = "dga_dns"

    def __init__(self) -> None:
        self._dga = _DgaScorer()

    def score(self, flow: FlowRecord) -> Alert | None:
        name = (flow.dns_query or "").strip(".")
        if not name:
            return None

        # --- DNS tunneling ---
        labels = domain_labels(name)
        parent = ".".join(labels[-2:]) if len(labels) >= 2 else name
        subdomain = ".".join(labels[:-2])
        sub_entropy = shannon_entropy(subdomain) if subdomain else 0.0

        win = SlidingWindow(f"dns:{parent}", TUNNEL_WINDOW_S)
        unique_names = win.add_count(name, flow.ts_end)

        long_name = len(name) >= TUNNEL_NAME_LEN
        high_vol = unique_names >= TUNNEL_MIN_UNIQUE
        if (long_name and sub_entropy >= TUNNEL_SUBDOMAIN_ENTROPY) or high_vol:
            conf = 0.6
            if long_name:
                conf += 0.15
            if high_vol:
                conf += min(0.25, (unique_names - TUNNEL_MIN_UNIQUE) / 200.0 + 0.05)
            conf = min(1.0, conf)
            return Alert.from_flow(
                flow,
                threat_class=ThreatClass.DGA_DNS,
                confidence=round(conf, 3),
                severity=severity_from_confidence(conf),
                evidence={
                    "subtype": "dns_tunneling",
                    "query_len": len(name),
                    "subdomain_entropy": round(sub_entropy, 3),
                    "unique_names_under_parent": unique_names,
                    "parent": parent,
                },
            )

        # --- DGA ---
        p, method = self._dga.probability(name)
        if p >= 0.6:
            return Alert.from_flow(
                flow,
                threat_class=ThreatClass.DGA_DNS,
                confidence=round(p, 3),
                severity=severity_from_confidence(p),
                evidence={
                    "subtype": "dga",
                    "query": name,
                    "score_method": method,
                    "registrable": registrable_part(name),
                },
            )
        return None
