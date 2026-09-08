"""Serialize/deserialize FlowRecord & Alert for Kafka. Honors settings.flow_serialization."""

from __future__ import annotations

import json

import msgpack

from common.config import settings
from common.schema import Alert, FlowRecord


def encode(model: FlowRecord | Alert) -> bytes:
    data = model.model_dump(mode="json")
    if settings.flow_serialization == "msgpack":
        return msgpack.packb(data, use_bin_type=True)
    return json.dumps(data).encode("utf-8")


def _decode_raw(raw: bytes) -> dict:
    if settings.flow_serialization == "msgpack":
        return msgpack.unpackb(raw, raw=False)
    return json.loads(raw.decode("utf-8"))


def decode_flow(raw: bytes) -> FlowRecord:
    return FlowRecord.model_validate(_decode_raw(raw))


def decode_alert(raw: bytes) -> Alert:
    return Alert.model_validate(_decode_raw(raw))
