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

## Status
- [x] Step 0 — repo scaffold, docker-compose infra, `FlowRecord`/`Alert` schema contract, topics + table
- [x] Step 1 — ingest spine: pcap → nfstream → Kafka `flows` (verified end-to-end)
- [ ] Step 2 — worker pool + port-scan detector + alerting + API + dashboard (vertical slice)
- [ ] Step 3 — remaining 5 detectors
- [ ] Step 4 — DGA & encrypted-flow models
- [ ] Step 5 — lab traffic generation + labels
- [ ] Step 6 — evaluation, throughput benchmark, docs

See `docs/runbook.md` for operational details and the full plan for the roadmap.
