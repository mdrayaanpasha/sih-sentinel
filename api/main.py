"""FastAPI service for the dashboard.

  GET  /alerts        recent alerts (history) from Postgres, with filters
  GET  /stats         alert counts grouped by threat_class + severity
  GET  /health        liveness
  WS   /ws/alerts     live alert stream, tailed from the Kafka 'alerts' topic

Read-only over the alert store; it never touches the monitored network.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading

import psycopg
from confluent_kafka import Consumer
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from psycopg.rows import dict_row

from common.config import settings

app = FastAPI(title="sih-sentinel API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------- live fan-out
class Hub:
    """Broadcasts alerts (dicts) from the Kafka tail thread to all websocket clients."""

    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    def register(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.clients.add(q)
        return q

    def unregister(self, q: asyncio.Queue) -> None:
        self.clients.discard(q)

    def publish_threadsafe(self, alert: dict) -> None:
        if self.loop is None:
            return
        for q in list(self.clients):
            self.loop.call_soon_threadsafe(self._safe_put, q, alert)

    @staticmethod
    def _safe_put(q: asyncio.Queue, item: dict) -> None:
        with contextlib.suppress(asyncio.QueueFull):
            q.put_nowait(item)


hub = Hub()
_stop = threading.Event()


def _kafka_tail() -> None:
    consumer = Consumer(
        {
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "group.id": "sentinel-api-live",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([settings.kafka_alerts_topic])
    try:
        while not _stop.is_set():
            msg = consumer.poll(0.5)
            if msg is None or msg.error():
                continue
            with contextlib.suppress(Exception):
                hub.publish_threadsafe(json.loads(msg.value().decode()))
    finally:
        consumer.close()


@app.on_event("startup")
def _startup() -> None:
    hub.loop = asyncio.get_event_loop()
    threading.Thread(target=_kafka_tail, daemon=True).start()


@app.on_event("shutdown")
def _shutdown() -> None:
    _stop.set()


# ---------------------------------------------------------------- REST
def _pg():
    return psycopg.connect(settings.postgres_dsn, row_factory=dict_row)


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/alerts")
def alerts(
    limit: int = Query(100, ge=1, le=1000),
    threat_class: str | None = None,
    severity: str | None = None,
) -> list[dict]:
    clauses, params = [], []
    if threat_class:
        clauses.append("threat_class = %s")
        params.append(threat_class)
    if severity:
        clauses.append("severity = %s")
        params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with _pg() as conn, conn.cursor() as cur:
        cur.execute(
            f"""SELECT id, extract(epoch from ts) AS ts, flow_id, threat_class, confidence,
                       severity, src_ip, src_port, dst_ip, dst_port, evidence
                FROM alerts {where} ORDER BY ts DESC LIMIT %s""",
            params,
        )
        return cur.fetchall()


@app.get("/stats")
def stats() -> dict:
    with _pg() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT threat_class, severity, count(*) AS n FROM alerts "
            "GROUP BY threat_class, severity"
        )
        rows = cur.fetchall()
        cur.execute("SELECT count(*) AS total FROM alerts")
        total = cur.fetchone()["total"]
    by_threat: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in rows:
        by_threat[r["threat_class"]] = by_threat.get(r["threat_class"], 0) + r["n"]
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + r["n"]
    return {"total": total, "by_threat": by_threat, "by_severity": by_severity}


# ---------------------------------------------------------------- WebSocket
@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    await ws.accept()
    q = hub.register()
    try:
        while True:
            alert = await q.get()
            await ws.send_json(alert)
    except WebSocketDisconnect:
        pass
    finally:
        hub.unregister(q)
