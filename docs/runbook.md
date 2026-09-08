# Runbook

## Services (docker compose)
| service  | container          | host port | notes |
|----------|--------------------|-----------|-------|
| kafka    | sentinel-kafka     | 9092      | apache/kafka 3.8.1, KRaft single-node |
| redis    | sentinel-redis     | 6380      | maps to container 6379; per-source detector state |
| postgres | sentinel-postgres  | 5434      | maps to container 5432; user/db/pass = sentinel; alert store |

`docker compose up -d` / `docker compose down`. Health: `docker compose ps`.
Wipe state (drops Kafka log + Postgres data): `docker compose down -v`.

> Ports 5433/6379 are used by another local project (`manaverse`) and 5432/6379 by native
> Postgres/Redis — hence the remaps above. Change them in `.env` + `docker-compose.yml` if needed.

## Common commands
```bash
# topics
uv run python -m infra.create_topics
docker exec sentinel-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

# ingest a pcap (speed 0 = as fast as possible, 1 = realtime, 10 = 10x)
uv run python -m ingest.flow_producer --pcap data/sample.pcap --speed 0
uv run python -m ingest.replay data/sample.pcap --speed 1 --loop   # demo loop

# inspect flows / alerts
uv run python -m tools.consume_flows --from-start --max 10
docker exec sentinel-postgres psql -U sentinel -d sentinel -c 'select * from alerts order by ts desc limit 10;'
```

## Passivity invariant
`ingest/flow_producer.py` is the only component that touches packets, and only reads them
(pcap file or promiscuous capture). No component ever writes to a monitored network. When
adding detectors, keep the detection path free of sockets/connect/probe calls (audited in Step 6).

## Data contract
`common/schema.py` defines `FlowRecord` and `Alert`. Change it there once; every stage imports it.
Serialization is switchable (json|msgpack) via `FLOW_SERIALIZATION` and `common/serde.py`.
