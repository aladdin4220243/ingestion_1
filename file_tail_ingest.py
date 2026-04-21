#!/usr/bin/env python3
"""
file_tail_ingest.py — tails a Honeytrap JSONL log and normalises events into Cerebrum.

Usage:
    python file_tail_ingest.py --file /var/log/honeytrap/events.jsonl

Environment variables:
    REDIS_URL           Redis connection string (default: redis://localhost:6379/0)
    INGEST_QUEUE_KEY    Redis list key        (default: cerebrum:events)
    POLL_INTERVAL       Seconds between reads  (default: 0.5)
    LOG_LEVEL           Python log level       (default: INFO)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from normalize import normalize
from queue_client import QueueClient

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("file_tail_ingest")

POLL_INTERVAL: float = float(os.environ.get("POLL_INTERVAL", "0.5"))


# ─────────────────────────────────────────────────────────────────────────────


def _tail(filepath: str):
    """Generator that yields stripped lines as they are appended to *filepath*."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # jump to EOF — we only care about new events
        log.info("Tailing %s (starting from EOF)", filepath)
        while True:
            line = fh.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    yield stripped
            else:
                time.sleep(POLL_INTERVAL)


def run(filepath: str, queue: QueueClient) -> None:
    """Consume *filepath* forever and push normalised events to *queue*."""
    counters = {"lines": 0, "queued": 0, "bad_json": 0, "bad_norm": 0}

    for line in _tail(filepath):
        counters["lines"] += 1

        # 1 — parse JSON
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("Bad JSON (skipping): %s | line=%.120s", exc, line)
            counters["bad_json"] += 1
            continue

        # Fuzz-hardening: reject suspiciously large records immediately
        if len(line) > 64_000:
            log.warning("Oversized record dropped (len=%d)", len(line))
            counters["bad_norm"] += 1
            continue

        # 2 — normalise
        event = normalize(raw)
        if event is None:
            counters["bad_norm"] += 1
            continue

        # 3 — push to queue
        if queue.push(event.dict()):
            counters["queued"] += 1
            log.debug("Queued %s session=%s", event.id, event.session_id)
        else:
            counters["bad_norm"] += 1

        # periodic progress log
        if counters["lines"] % 500 == 0:
            log.info("Progress: %s", counters)


# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Honeytrap JSONL file tail ingest")
    parser.add_argument("--file", required=True, help="Path to Honeytrap JSONL log file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        log.error("File not found: %s", args.file)
        sys.exit(1)

    queue = QueueClient()

    log.info("Starting file tail ingestion from %s", args.file)
    try:
        run(args.file, queue)
    except KeyboardInterrupt:
        log.info("Stopped by user")


if __name__ == "__main__":
    main()
