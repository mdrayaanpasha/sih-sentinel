"""Create the Kafka topics the pipeline needs. Idempotent — safe to re-run.

    uv run python -m infra.create_topics
"""

from __future__ import annotations

from confluent_kafka.admin import AdminClient, NewTopic

from common.config import settings

TOPICS = [
    NewTopic(settings.kafka_flows_topic, num_partitions=6, replication_factor=1),
    NewTopic(settings.kafka_alerts_topic, num_partitions=3, replication_factor=1),
]


def main() -> None:
    admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers})
    existing = set(admin.list_topics(timeout=10).topics.keys())
    to_create = [t for t in TOPICS if t.topic not in existing]
    if not to_create:
        print(f"topics already present: {[t.topic for t in TOPICS]}")
        return
    for topic, fut in admin.create_topics(to_create).items():
        try:
            fut.result()
            print(f"created topic: {topic}")
        except Exception as exc:  # noqa: BLE001
            print(f"failed to create {topic}: {exc}")


if __name__ == "__main__":
    main()
