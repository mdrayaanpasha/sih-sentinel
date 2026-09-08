"""Alert sink: persist to Postgres and publish to the Kafka 'alerts' topic.

The dashboard reads live alerts from Kafka (via the API's websocket) and history
from Postgres. Both writes share the standardized Alert schema.
"""

from __future__ import annotations

from datetime import UTC, datetime

import psycopg
from confluent_kafka import Producer

from common.config import settings
from common.schema import Alert
from common.serde import encode


class AlertSink:
    def __init__(self) -> None:
        self._producer = Producer(
            {"bootstrap.servers": settings.kafka_bootstrap_servers, "client.id": "sentinel-alerts"}
        )
        self._conn = psycopg.connect(settings.postgres_dsn, autocommit=True)

    def emit(self, alert: Alert) -> None:
        self._producer.produce(settings.kafka_alerts_topic, value=encode(alert))
        self._producer.poll(0)
        self._insert(alert)

    def _insert(self, a: Alert) -> None:
        import json

        with self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts
                    (ts, flow_id, threat_class, confidence, severity,
                     src_ip, src_port, dst_ip, dst_port, evidence)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    datetime.fromtimestamp(a.ts, tz=UTC),
                    a.flow_id,
                    a.threat_class.value,
                    a.confidence,
                    a.severity.value,
                    a.src_ip,
                    a.src_port,
                    a.dst_ip,
                    a.dst_port,
                    json.dumps(a.evidence),
                ),
            )

    def flush(self) -> None:
        self._producer.flush()

    def close(self) -> None:
        self._producer.flush()
        self._conn.close()
