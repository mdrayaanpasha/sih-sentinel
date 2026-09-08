"""Worker: consume 'flows', run every detector, emit alerts.

Run several of these in the same consumer group to scale throughput — Kafka spreads
the topic's partitions across them and all detector state lives in shared Redis, so
workers stay stateless and add linearly.

    uv run python -m workers.consumer
"""

from __future__ import annotations

import signal
import sys

from confluent_kafka import Consumer

from common.config import settings
from common.serde import decode_flow
from workers.alerting import AlertSink
from workers.registry import build_detectors

_running = True


def _stop(*_):
    global _running
    _running = False


def main() -> None:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    detectors = build_detectors()
    sink = AlertSink()
    consumer = Consumer(
        {
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": settings.kafka_consumer_group,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
        }
    )
    consumer.subscribe([settings.kafka_flows_topic])
    print(
        f"worker up: {len(detectors)} detectors, group={settings.kafka_consumer_group}",
        file=sys.stderr,
    )

    flows = 0
    alerts = 0
    try:
        while _running:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                print("consume error:", msg.error(), file=sys.stderr)
                continue
            flow = decode_flow(msg.value())
            flows += 1
            for det in detectors:
                try:
                    alert = det.score(flow)
                except Exception as exc:  # noqa: BLE001 — one bad detector must not kill the worker
                    print(f"detector {det.name} error: {exc}", file=sys.stderr)
                    continue
                if alert is not None:
                    sink.emit(alert)
                    alerts += 1
                    print(
                        f"ALERT {alert.threat_class.value} "
                        f"conf={alert.confidence} sev={alert.severity.value} "
                        f"{alert.src_ip}->{alert.dst_ip} {alert.evidence}",
                        file=sys.stderr,
                    )
            if flows % 5000 == 0:
                print(f"  processed {flows} flows, {alerts} alerts", file=sys.stderr)
    finally:
        sink.close()
        consumer.close()
        print(f"worker down: {flows} flows, {alerts} alerts", file=sys.stderr)


if __name__ == "__main__":
    main()
