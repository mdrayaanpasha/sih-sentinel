# Architecture

```
 pcap replay ─► nfstream ─► Kafka 'flows' ─► worker pool ─► Kafka 'alerts' ─► FastAPI ─► dashboard
 (diode sim)   (flowize)   (buffer)          (6 detectors    + Postgres        (REST+WS)   (React)
                                              + Redis state)
```

## Passivity (the diode invariant)
`ingest/flow_producer.py` is the **only** component that touches packets, and it only ever
reads them (pcap file, or an interface in promiscuous mode). No component in the system opens
a socket to, probes, or writes to a monitored network. TLS/QUIC is handled from handshake
metadata (JA3/JA3S, SNI) and packet size/timing only — never decrypted.

## Components
| Component | File | Role |
|-----------|------|------|
| Ingest | `ingest/flow_producer.py` | pcap/iface → nfstream `NFlow` → `FlowRecord` → Kafka `flows` |
| Contract | `common/schema.py` | `FlowRecord` + `Alert` — the shape every stage speaks |
| Worker | `workers/consumer.py` | consumes `flows`, runs all detectors, emits alerts |
| Detectors | `workers/detectors/*.py` | one per threat class; `score(flow) -> Alert \| None` |
| State | `workers/state.py` | Redis sliding windows / baselines / timing series (pipelined) |
| Alerting | `workers/alerting.py` | writes alert → Postgres + Kafka `alerts` |
| API | `api/main.py` | REST history + `/ws/alerts` live feed (tails Kafka) |
| Dashboard | `dashboard/` | React live table with threat/severity filters + evidence drill-down |
| Models | `models/` | DGA classifier + encrypted-flow classifier (joblib) |
| Lab | `labgen/` | synthetic labeled pcap covering benign + all 6 threats |

## Streaming & scale
Each flow is scored and (if malicious) alerted within milliseconds of arriving — no batch/
end-of-run reports. Workers are **stateless** (all history is in shared Redis), so throughput
scales by adding worker processes to the Kafka consumer group; the `flows` topic has 6
partitions to allow up to 6-way parallelism out of the box.

Measured: **~630 flows/sec sustained per worker** on a laptop (macOS + Docker Desktop), the
detection stack being the bottleneck (Redis round-trips + gated model inference). See
`docs/performance.md`.

## Standardized alert schema
Every alert (see `common/schema.py:Alert`) carries: `ts`, `flow_id`, `threat_class`,
`confidence` (0–1), `severity`, `src/dst ip+port`, and an `evidence` dict of the exact signals
that fired — e.g. `{"distinct_ports": 60, "scan_type": "vertical", "window_s": 10}`.
