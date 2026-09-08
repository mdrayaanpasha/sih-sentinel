#!/usr/bin/env bash
# One-command live demo: infra + worker + API + dashboard + looping pcap replay.
# Ctrl-C tears everything down. Open http://127.0.0.1:5173 to watch alerts stream in.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[demo] ensuring infra is up..."
docker compose up -d >/dev/null
until docker compose ps --format '{{.Health}}' | grep -q healthy; do sleep 1; done

echo "[demo] ensuring topics + models + lab pcap exist..."
uv run python -m infra.create_topics >/dev/null 2>&1 || true
[ -f models/artifacts/dga_model.joblib ] || uv run python -m models.train_dga >/dev/null 2>&1
[ -f models/artifacts/encrypted_flow_model.joblib ] || uv run python -m models.train_encrypted_flow >/dev/null 2>&1
[ -f data/lab.pcap ] || uv run python -m labgen.generate >/dev/null 2>&1

PIDS=()
cleanup() { echo; echo "[demo] stopping..."; for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

echo "[demo] starting worker..."
uv run python -m workers.consumer & PIDS+=($!)

echo "[demo] starting API on :8000..."
uv run uvicorn api.main:app --host 127.0.0.1 --port 8000 & PIDS+=($!)
sleep 3

echo "[demo] starting dashboard on :5173..."
( cd dashboard && npm run dev ) & PIDS+=($!)

echo "[demo] replaying lab pcap in a loop (realtime pacing)..."
sleep 2
uv run python -m ingest.replay data/lab.pcap --speed 1 --loop & PIDS+=($!)

echo "[demo] ready -> http://127.0.0.1:5173   (Ctrl-C to stop)"
wait
