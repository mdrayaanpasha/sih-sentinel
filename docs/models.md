# Detection models & methods

Each threat class uses the cheapest method that works: streaming statistics for rate/timing/
volume signals, and trained ML only where content structure matters (DGA, encrypted-flow shape).

| Threat | Detector | Method | State |
|--------|----------|--------|-------|
| Port scan | `portscan.py` | distinct (host,port) targets per source in a window; horizontal vs vertical | per-src sliding window |
| Flood / DDoS | `flood.py` | per-dst flow rate + distinct source-IP count + bare-SYN rate | per-dst window + counters |
| C2 beaconing | `beaconing.py` | coefficient-of-variation of inter-arrival times (regular cadence), interval floor | per-pair timestamp series |
| DGA / DNS tunnel | `dga_dns.py` | **DGA:** RandomForest on domain features. **Tunnel:** long name + subdomain entropy + query volume | per-parent-domain window |
| Encrypted malware | `tls_fingerprint.py` | JA3/JA3S blocklist + **RandomForest** on packet size/timing (metadata only) | stateless per flow |
| Data exfil | `exfil.py` | outbound:inbound ratio + z-score of outbound bytes vs per-host baseline | per-host online baseline |

## Trained models
Both are `sklearn` RandomForests, trained offline, saved to `models/artifacts/*.joblib`, and
loaded by their detectors. Inference is gated behind a cheap pre-filter (entropy / packet-size)
so the RF only runs on plausible candidates — this keeps per-flow latency low. Models are
loaded with `n_jobs=1` (single-sample streaming inference; the default threadpool adds ~10 ms/call).

### DGA classifier — `models/train_dga.py`
- Features (`models/dga_features.py`): length, Shannon entropy, digit ratio, consonant ratio,
  unique-char ratio, max consecutive consonants, vowel ratio — computed on the registrable label.
- Training data: **synthetic** — pronounceable/dictionary labels (benign) vs algorithmically-random
  labels (DGA). Swap `benign_samples()`/`dga_samples()` for **Tranco** (benign) + **DGArchive**
  (malicious) to train on real data; the feature pipeline is unchanged.
- Result on held-out synthetic set: ~0.99 F1.

### Encrypted-flow classifier — `models/train_encrypted_flow.py`
- Features (`models/flow_stat_features.py`): mean packet size, size spread (uniformity), packet
  count, mean inter-arrival, out:in ratio, response mean size — **no payload, no decryption**.
- Training data: **synthetic** — variable/bursty browser TLS (benign) vs small/uniform/regular
  C2 (malware). Replace with feature vectors from labeled pcaps for real training.

### JA3 blocklist — `models/artifacts/ja3_blocklist.txt`
Sample known-bad JA3/JA3S fingerprints; in production feed from threat intel (e.g. abuse.ch SSLBL).
JA3 matching works on real captures where nfstream extracts the fingerprint from the ClientHello.

## Confidence & severity
Each detector emits a calibrated-ish confidence in [0,1] scaled by signal strength (e.g. how far
above threshold the target count / z-score / model probability is). Severity is derived from
confidence: ≥0.9 critical, ≥0.75 high, ≥0.5 medium, else low (`workers/detectors/base.py`).
