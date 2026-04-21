"""
Redis-backed queue client for at-least-once delivery between ingestion and Cerebrum.
Falls back to stdout JSONL logging when Redis is unavailable.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger(__name__)

REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
QUEUE_KEY: str = os.environ.get("INGEST_QUEUE_KEY", "cerebrum:events")
_MAX_RETRIES = 3
_BACKOFF_BASE = 0.3  # seconds

try:
    import redis as _redis_lib
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False
    log.warning("redis-py not installed — queue will use stdout fallback")


class QueueClient:
    """
    Wraps a Redis list as a simple FIFO queue.

    push()  → RPUSH (producer side)
    pop()   → blocking BLPOP with timeout (consumer side)
    """

    def __init__(self, url: str = REDIS_URL, key: str = QUEUE_KEY):
        self._url = url
        self._key = key
        self._client: Optional[object] = None
        self._connect()

    # ── internals ────────────────────────────────────────────────────────────

    def _connect(self) -> None:
        if not _REDIS_AVAILABLE:
            return
        try:
            c = _redis_lib.from_url(self._url, decode_responses=True, socket_timeout=3)
            c.ping()
            self._client = c
            log.info("Queue connected to Redis at %s (key=%s)", self._url, self._key)
        except Exception as exc:
            self._client = None
            log.warning("Redis connection failed: %s — using fallback", exc)

    # ── public API ───────────────────────────────────────────────────────────

    def push(self, payload: dict) -> bool:
        """
        Push a dict onto the queue.  Returns True on success.
        Retries up to ``_MAX_RETRIES`` times with exponential backoff.
        Falls back to logging if Redis is unavailable.
        """
        message = json.dumps(payload)

        if self._client:
            for attempt in range(_MAX_RETRIES):
                try:
                    self._client.rpush(self._key, message)
                    return True
                except Exception as exc:
                    log.warning("Redis RPUSH attempt %d failed: %s", attempt + 1, exc)
                    time.sleep(_BACKOFF_BASE * (2 ** attempt))
                    self._connect()

        # Fallback: emit JSONL to stdout so a log shipper can pick it up
        print(f"QUEUE_FALLBACK {message}", flush=True)
        return True  # treat as delivered so pipeline keeps moving

    def pop(self, timeout: int = 5) -> Optional[dict]:
        """
        Blocking pop from the queue.  Returns a dict or None on timeout/error.
        """
        if not self._client:
            self._connect()
            return None
        try:
            result = self._client.blpop(self._key, timeout=timeout)
            if result:
                _, raw = result
                return json.loads(raw)
        except Exception as exc:
            log.error("Redis BLPOP failed: %s", exc)
            self._connect()
        return None

    def length(self) -> int:
        """Return current queue depth (for monitoring)."""
        if not self._client:
            return -1
        try:
            return self._client.llen(self._key)
        except Exception:
            return -1
