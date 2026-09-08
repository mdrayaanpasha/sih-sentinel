"""Feature extraction for DGA domain classification. Shared by training and inference
so the model always sees identically-computed features.
"""

from __future__ import annotations

from workers.features import (
    consonant_ratio,
    digit_ratio,
    registrable_part,
    shannon_entropy,
)

FEATURE_NAMES = [
    "length",
    "entropy",
    "digit_ratio",
    "consonant_ratio",
    "unique_char_ratio",
    "max_consecutive_consonants",
    "vowel_ratio",
]


def _max_consecutive_consonants(s: str) -> int:
    vowels = set("aeiou")
    best = cur = 0
    for c in s.lower():
        if c.isalpha() and c not in vowels:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def domain_feature_vector(name: str) -> list[float]:
    """Feature vector from the registrable label of a domain (the part that carries
    DGA/algorithmic randomness)."""
    label = registrable_part(name.lower().strip("."))
    if not label:
        return [0.0] * len(FEATURE_NAMES)
    n = len(label)
    unique_ratio = len(set(label)) / n
    vowels = set("aeiou")
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = (sum(c in vowels for c in letters) / len(letters)) if letters else 0.0
    return [
        float(n),
        shannon_entropy(label),
        digit_ratio(label),
        consonant_ratio(label),
        unique_ratio,
        float(_max_consecutive_consonants(label)),
        vowel_ratio,
    ]
