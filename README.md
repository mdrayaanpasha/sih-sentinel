# sih-sentinel

Passive, **read-only** AI/ML network threat-detection pipeline for critical infrastructure.
Sits behind a hardware diode/tap: it only ever *watches* a copy of traffic — it never probes,
connects, decrypts, or blocks. It turns packets into flow records, detects 6 threat classes in a
streaming fashion, and raises live alerts.

## Architecture

```
pcap replay (simulates diode)  ->  nfstream  ->  Kafka 'flows'  ->  worker pool
   (per-source state in Redis)  ->  6 detectors  ->  Kafka 'alerts' + Postgres  ->  API  ->  dashboard
```

Threat classes: `flood` (DDoS), `beaconing` (botnet C2), `dga_dns` (DGA + DNS tunneling),
`tls_malware` (encrypted-session malware, metadata only), `portscan`, `exfil`.

## Prerequisites
- Docker + Docker Compose
- `uv` (Python package manager); the pipeline runs on Python 3.12

## Quickstart

```bash
# 1. install python deps (creates .venv on py3.12)
uv sync

# 2. bring up infra: Kafka (KRaft), Redis, Postgres
cp .env.example .env
docker compose up -d          # wait until `docker compose ps` shows all healthy

# 3. create Kafka topics (idempotent)
uv run python -m infra.create_topics

# 4. generate a sample pcap and ingest it
uv run python -m tools.make_sample_pcap data/sample.pcap
uv run python -m ingest.flow_producer --pcap data/sample.pcap --speed 0

# 5. verify flows landed on Kafka
uv run python -m tools.consume_flows --from-start --max 8
```

Host ports (remapped to avoid clashing with other local services):
Kafka `9092`, Redis `6380`→6379, Postgres `5434`→5432.

## Full live demo (one command)

```bash
uv sync
cp .env.example .env
./scripts/demo.sh        # infra + worker + API + dashboard + looping pcap replay
# open http://127.0.0.1:5173  — alerts stream in live; Ctrl-C tears it all down
```

`scripts/demo.sh` auto-creates topics, trains the models, and generates the lab pcap on first run.

## Evaluate & benchmark
```bash
uv run python -m labgen.generate         # labeled pcap with all 6 threats
uv run python -m evaluation.evaluate     # per-threat precision/recall vs ground truth
uv run python -m bench.throughput        # sustained flows/sec
```

## Results (see `docs/performance.md`)
- **Precision 1.00** on all six threat classes; **zero false positives** on benign traffic.
- **6/6 threat classes detected** on the labeled lab corpus.
- **~630 flows/sec sustained per worker** (laptop); scales linearly with worker count.

## Status — all steps complete
- [x] Step 0 — scaffold, docker-compose infra, `FlowRecord`/`Alert` schema contract, topics + table
- [x] Step 1 — ingest spine: pcap → nfstream → Kafka `flows`
- [x] Step 2 — worker pool + alerting + FastAPI (REST + WS) + React dashboard
- [x] Step 3 — all 6 detectors (flood, beaconing, dga_dns, tls_malware, portscan, exfil)
- [x] Step 4 — DGA + encrypted-flow RandomForest models
- [x] Step 5 — lab traffic generation + ground-truth labels
- [x] Step 6 — evaluation, throughput benchmark, docs

Docs: `docs/architecture.md`, `docs/models.md`, `docs/threat-model.md`, `docs/performance.md`,
`docs/runbook.md`.
