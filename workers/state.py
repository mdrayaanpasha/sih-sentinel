"""Short-term per-entity state in Redis.

Detectors that need history (rate windows, beaconing timing, exfil baselines) keep
it here so worker processes stay stateless and horizontally scalable across a Kafka
consumer group. Everything is TTL'd so memory stays bounded.

Every primitive batches its Redis commands into a single pipelined round-trip — on a
macOS/Docker setup a round-trip is ~150 µs, so collapsing 3-4 ops into one is the
difference between ~15 ms/flow and sub-millisecond.

Primitives:
  * SlidingWindow  — time-ordered sorted set; distinct members in the last N seconds.
  * Baseline       — online mean/variance (Welford) per key, for deviation scoring.
  * TimestampSeries — recent event timestamps (beaconing).
  * incr_window_counter — rolling bucketed sum (flood rate).
"""

from __future__ import annotations

import math

import redis

from common.config import settings

_client: redis.Redis | None = None


def client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


class SlidingWindow:
    """Sorted set of members scored by timestamp, trimmed to a rolling window."""

    def __init__(self, key: str, window_s: float):
        self.key = key
        self.window_s = window_s
        self.r = client()

    def add_count(self, member: str, ts: float) -> int:
        """Add a member and return the distinct count in the window — one round-trip."""
        p = self.r.pipeline(transaction=False)
        p.zadd(self.key, {member: ts})
        p.zremrangebyscore(self.key, "-inf", ts - self.window_s)
        p.expire(self.key, int(self.window_s) + 5)
        p.zcard(self.key)
        return int(p.execute()[-1])

    def add_members(self, member: str, ts: float) -> list[str]:
        """Add a member and return all current members — one round-trip."""
        p = self.r.pipeline(transaction=False)
        p.zadd(self.key, {member: ts})
        p.zremrangebyscore(self.key, "-inf", ts - self.window_s)
        p.expire(self.key, int(self.window_s) + 5)
        p.zrange(self.key, 0, -1)
        return list(p.execute()[-1])


class Baseline:
    """Online mean/std per key via Welford's algorithm, stored in a Redis hash."""

    def __init__(self, key: str, ttl_s: int = 86_400):
        self.key = key
        self.ttl_s = ttl_s
        self.r = client()

    def observe(self, x: float) -> tuple[float, int]:
        """Score x against the CURRENT baseline, then fold it in. Returns (zscore_before, n_before).

        One read + one pipelined write (2 round-trips). Scoring before updating keeps a
        flow from masking its own anomaly.
        """
        h = self.r.hgetall(self.key)
        n = int(h.get("n", 0))
        mean = float(h.get("mean", 0.0))
        m2 = float(h.get("m2", 0.0))

        if n >= 2:
            std = math.sqrt(m2 / n)
            z = (x - mean) / std if std > 1e-9 else 0.0
        else:
            z = 0.0
        n_before = n

        n += 1
        delta = x - mean
        mean += delta / n
        m2 += delta * (x - mean)
        p = self.r.pipeline(transaction=False)
        p.hset(self.key, mapping={"n": n, "mean": mean, "m2": m2})
        p.expire(self.key, self.ttl_s)
        p.execute()
        return z, n_before


class TimestampSeries:
    """Recent event timestamps per key (capped). Used for beaconing timing analysis."""

    def __init__(self, key: str, maxlen: int = 64, ttl_s: int = 3_600):
        self.key = key
        self.maxlen = maxlen
        self.ttl_s = ttl_s
        self.r = client()

    def add(self, ts: float) -> list[float]:
        p = self.r.pipeline(transaction=False)
        p.rpush(self.key, ts)
        p.ltrim(self.key, -self.maxlen, -1)
        p.expire(self.key, self.ttl_s)
        p.lrange(self.key, 0, -1)
        return [float(x) for x in p.execute()[-1]]


def incr_window_counter(key: str, window_s: float, ts: float, amount: float = 1.0) -> float:
    """Rolling sum over a window using per-second bucket fields in a hash. Returns current sum.

    One round-trip to increment+read; a second (rare) round-trip only when stale buckets
    need pruning.
    """
    r = client()
    now_bucket = int(ts)
    cutoff = now_bucket - int(window_s)
    p = r.pipeline(transaction=False)
    p.hincrbyfloat(key, str(now_bucket), amount)
    p.expire(key, int(window_s) + 5)
    p.hgetall(key)
    buckets = p.execute()[-1]

    total = 0.0
    stale = []
    for field, val in buckets.items():
        if int(field) < cutoff:
            stale.append(field)
        else:
            total += float(val)
    if stale:
        r.hdel(key, *stale)
    return total
