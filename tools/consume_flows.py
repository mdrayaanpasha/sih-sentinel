"""Smoke consumer: tail the 'flows' topic and print decoded FlowRecords.

    uv run python -m tools.consume_flows --from-start --max 5
"""

from __future__ import annotations

import argparse

from confluent_kafka import Consumer

from common.config import settings
from common.serde import decode_flow


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-start", action="store_true", help="read from the beginning")
    ap.add_argument("--max", type=int, default=10, help="stop after N messages (0=forever)")
    ap.add_argument("--timeout", type=float, default=10.0, help="idle seconds before giving up")
    args = ap.parse_args()

    consumer = Consumer(
        {
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": f"smoke-{'start' if args.from_start else 'live'}",
            "auto.offset.reset": "earliest" if args.from_start else "latest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([settings.kafka_flows_topic])

    seen = 0
    idle = 0.0
    try:
        while args.max == 0 or seen < args.max:
            msg = consumer.poll(1.0)
            if msg is None:
                idle += 1.0
                if idle >= args.timeout:
                    print(f"(no more messages after {args.timeout}s idle)")
                    break
                continue
            if msg.error():
                print("error:", msg.error())
                continue
            idle = 0.0
            f = decode_flow(msg.value())
            seen += 1
            print(
                f"[{seen}] {f.flow_id} {f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port} "
                f"proto={f.protocol} app={f.app_protocol} dns={f.dns_query} "
                f"bytes={f.src2dst_bytes}/{f.dst2src_bytes}"
            )
    finally:
        consumer.close()
    print(f"consumed {seen} flow(s)")


if __name__ == "__main__":
    main()
