"""Shared, stateless feature helpers used across detectors."""

from __future__ import annotations

import math
from collections import Counter

TCP = 6
UDP = 17


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string. High for random/gibberish domains."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_labels(name: str) -> list[str]:
    return [p for p in name.split(".") if p]


def registrable_part(name: str) -> str:
    """The label most likely to carry DGA/tunnel randomness (2nd-level label, else longest)."""
    labels = domain_labels(name)
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def consonant_ratio(s: str) -> float:
    if not s:
        return 0.0
    vowels = set("aeiou")
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(c not in vowels for c in letters) / len(letters)


def coefficient_of_variation(values: list[float]) -> float:
    """std/mean. Low CV over inter-arrival times => very regular timing (beaconing)."""
    if len(values) < 2:
        return float("inf")
    mean = sum(values) / len(values)
    if mean == 0:
        return float("inf")
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var) / mean


def inter_arrivals(timestamps: list[float]) -> list[float]:
    ts = sorted(timestamps)
    return [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]


def outbound_inbound_ratio(src2dst_bytes: int, dst2src_bytes: int) -> float:
    """Outbound:inbound byte ratio. High => potential exfil."""
    return src2dst_bytes / max(dst2src_bytes, 1)
