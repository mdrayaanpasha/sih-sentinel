"""Convenience wrapper for replaying a pcap into the pipeline (simulates the diode feed).

Thin front-end over flow_producer.run with demo ergonomics (--loop for continuous
demos). For one-shot ingest, flow_producer's CLI works directly.

    uv run python -m ingest.replay data/sample.pcap --speed 1 --loop
"""

from __future__ import annotations

import argparse

from ingest.flow_producer import run


def main() -> None:
    ap = argparse.ArgumentParser(description="replay a pcap into Kafka 'flows'")
    ap.add_argument("pcap", help="path to pcap/pcapng")
    ap.add_argument("--speed", type=float, default=1.0, help="pacing multiplier (0=max speed)")
    ap.add_argument("--limit", type=int, default=None, help="stop after N flows")
    ap.add_argument("--loop", action="store_true", help="replay forever (demo mode)")
    args = ap.parse_args()

    while True:
        total = run(source=args.pcap, is_live=False, speed=args.speed, limit=args.limit)
        if not args.loop:
            break
        print(f"loop: replayed {total} flows, restarting...")


if __name__ == "__main__":
    main()
