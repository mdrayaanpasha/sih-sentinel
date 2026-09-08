"""Detector interface. Each detector inspects one FlowRecord (plus its Redis state)
and returns an Alert or None. Keep the detection path passive — no sockets/probes."""

from __future__ import annotations

from abc import ABC, abstractmethod

from common.schema import Alert, FlowRecord, Severity


class Detector(ABC):
    #: threat name, for logging
    name: str = "base"

    @abstractmethod
    def score(self, flow: FlowRecord) -> Alert | None:
        """Return an Alert if this flow triggers the detector, else None."""
        raise NotImplementedError


def severity_from_confidence(conf: float) -> Severity:
    if conf >= 0.9:
        return Severity.CRITICAL
    if conf >= 0.75:
        return Severity.HIGH
    if conf >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW
