"""Train the DGA domain classifier.

Benign vs DGA. For a self-contained prototype we *synthesize* both classes:
  * benign  — pronounceable, dictionary-like second-level labels (low entropy)
  * DGA     — algorithmically-random labels (high entropy), the way real DGAs look

Swap `benign_samples()` / `dga_samples()` for Tranco (benign) + DGArchive (malicious)
feeds to train on real data — the feature pipeline (models/dga_features.py) is unchanged.

    uv run python -m models.train_dga
"""

from __future__ import annotations

import os
import random

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from models.dga_features import FEATURE_NAMES, domain_feature_vector

SEED = 1337
ARTIFACT = os.path.join(os.path.dirname(__file__), "artifacts", "dga_model.joblib")

# small syllable set -> pronounceable benign-looking labels
_SYLL = [
    "ba", "be", "bi", "bo", "bu", "ca", "co", "cu", "da", "de", "di", "do", "fa", "fe", "fi",
    "ga", "go", "ha", "he", "hi", "ho", "ka", "ki", "la", "le", "li", "lo", "lu", "ma", "me",
    "mi", "mo", "na", "ne", "ni", "no", "pa", "pe", "pi", "po", "ra", "re", "ri", "ro", "sa",
    "se", "si", "so", "ta", "te", "ti", "to", "va", "ve", "vi", "wa", "we", "wi", "za", "ze",
]
_WORDS = [
    "cloud", "secure", "market", "portal", "login", "shop", "media", "health", "bank", "mail",
    "news", "data", "store", "group", "tech", "world", "global", "energy", "power", "grid",
    "system", "network", "service", "center", "support", "office", "digital", "smart", "home",
]
_TLDS = ["com", "net", "org", "io", "co", "in"]
_DGA_CHARS = "abcdefghijklmnopqrstuvwxyz"
_DGA_CHARS_DIGITS = _DGA_CHARS + "0123456789"


def benign_samples(n: int, rng: random.Random) -> list[str]:
    out = []
    for _ in range(n):
        if rng.random() < 0.5:
            label = rng.choice(_WORDS) + (rng.choice(_WORDS) if rng.random() < 0.4 else "")
        else:
            label = "".join(rng.choice(_SYLL) for _ in range(rng.randint(2, 4)))
        out.append(f"{label}.{rng.choice(_TLDS)}")
    return out


def dga_samples(n: int, rng: random.Random) -> list[str]:
    out = []
    for _ in range(n):
        length = rng.randint(12, 24)
        charset = _DGA_CHARS_DIGITS if rng.random() < 0.4 else _DGA_CHARS
        label = "".join(rng.choice(charset) for _ in range(length))
        out.append(f"{label}.{rng.choice(_TLDS)}")
    return out


def main() -> None:
    rng = random.Random(SEED)
    n = 8000
    benign = benign_samples(n, rng)
    dga = dga_samples(n, rng)

    X = [domain_feature_vector(d) for d in benign + dga]
    y = [0] * len(benign) + [1] * len(dga)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=SEED, stratify=y)
    clf = RandomForestClassifier(n_estimators=80, max_depth=12, random_state=SEED, n_jobs=-1)
    clf.fit(X_tr, y_tr)
    clf.n_jobs = 1  # single-sample streaming inference: avoid threadpool overhead per call

    print("features:", FEATURE_NAMES)
    print(classification_report(y_te, clf.predict(X_te), target_names=["benign", "dga"]))
    print("importances:", dict(zip(FEATURE_NAMES, [round(i, 3) for i in clf.feature_importances_])))

    os.makedirs(os.path.dirname(ARTIFACT), exist_ok=True)
    joblib.dump(clf, ARTIFACT)
    print(f"saved -> {ARTIFACT}")

    # quick spot check
    for d in ["cloudsecure.com", "kxqvwzptrlmn.net", "google.com", "a7f3k9x2vq8w1z.io"]:
        p = clf.predict_proba([domain_feature_vector(d)])[0][1]
        print(f"  {d:24s} dga_prob={p:.3f}")


if __name__ == "__main__":
    main()
