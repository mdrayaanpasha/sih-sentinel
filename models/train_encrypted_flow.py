"""Train the encrypted-session (TLS) malware classifier — metadata only, no decryption.

Synthesizes two classes of flow statistics:
  * benign  — human/browser TLS: larger, highly variable packet sizes, bursty timing
  * malware — automated C2 over TLS: small, uniform request payloads at regular intervals

Replace the synthetic generators with feature vectors extracted from labeled pcaps
(models/flow_stat_features.flow_stat_vector) to train on real captures.

    uv run python -m models.train_encrypted_flow
"""

from __future__ import annotations

import os
import random

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from models.flow_stat_features import FEATURE_NAMES

SEED = 4242
ARTIFACT = os.path.join(os.path.dirname(__file__), "artifacts", "encrypted_flow_model.joblib")


def _benign(rng: random.Random) -> list[float]:
    mean_ps = rng.uniform(400, 1400)
    spread = rng.uniform(300, 1200)
    packets = rng.randint(10, 400)
    piat = rng.uniform(5, 500)
    ratio = rng.uniform(0.05, 3.0)
    dst_ps = rng.uniform(400, 1400)
    return [mean_ps, spread, packets, piat, ratio, dst_ps]


def _malware(rng: random.Random) -> list[float]:
    mean_ps = rng.uniform(60, 200)
    spread = rng.uniform(0, 50)          # uniform sizes
    packets = rng.randint(4, 60)
    piat = rng.uniform(800, 60000)       # regular, spaced beacons
    ratio = rng.uniform(0.3, 2.0)
    dst_ps = rng.uniform(60, 220)
    return [mean_ps, spread, packets, piat, ratio, dst_ps]


def main() -> None:
    rng = random.Random(SEED)
    n = 6000
    X = [_benign(rng) for _ in range(n)] + [_malware(rng) for _ in range(n)]
    y = [0] * n + [1] * n

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=SEED, stratify=y)
    clf = RandomForestClassifier(n_estimators=80, max_depth=10, random_state=SEED, n_jobs=-1)
    clf.fit(X_tr, y_tr)
    clf.n_jobs = 1  # single-sample streaming inference: avoid threadpool overhead per call

    print("features:", FEATURE_NAMES)
    print(classification_report(y_te, clf.predict(X_te), target_names=["benign", "malware"]))
    print("importances:", dict(zip(FEATURE_NAMES, [round(i, 3) for i in clf.feature_importances_])))

    os.makedirs(os.path.dirname(ARTIFACT), exist_ok=True)
    joblib.dump(clf, ARTIFACT)
    print(f"saved -> {ARTIFACT}")


if __name__ == "__main__":
    main()
