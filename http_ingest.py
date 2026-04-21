#!/usr/bin/env python3
"""
http_ingest.py — FastAPI webhook receiver for Honeytrap events.

Accepts signed POST requests from Honeytrap HTTP pushers,
normalises each event, and pushes to the Redis queue.

Endpoints:
    POST /ingest/event          single event
    POST /ingest/batch          array of events
    GET  /healthz               liveness probe
    GET  /metrics               queue depth + counters
"""
from __future__ import annotations

import logging
import os
import time
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from hmac_utils import verify_signature
from normalize import normalize
from queue_client import QueueClient

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
REQUIRE_HMAC: bool = os.environ.get("REQUIRE_HMAC", "true").lower() == "true"
PORT: int = int(os.environ.get("PORT", "8001"))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("http_ingest")

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Honeytrap HTTP Ingestion", version="1.0.0", docs_url="/docs")
queue = QueueClient()

_counters: dict = {"received": 0, "accepted": 0, "rejected": 0, "started_at": time.time()}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Auth helper
# ─────────────────────────────────────────────────────────────────────────────


def _check_hmac(payload: dict, sig: Optional[str]) -> None:
    if not REQUIRE_HMAC:
        return
    if not sig:
        raise HTTPException(status_code=401, detail="Missing X-HMAC-Signature header")
    if not verify_signature(payload, sig):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/healthz", tags=["ops"])
def healthz():
    return {"status": "ok", "queue_depth": queue.length()}


@app.get("/metrics", tags=["ops"])
def metrics():
    uptime = time.time() - _counters["started_at"]
    return {**_counters, "uptime_seconds": round(uptime, 1)}


@app.post("/ingest/event", tags=["ingest"])
async def ingest_event(
    request: Request,
    x_hmac_signature: Optional[str] = Header(None, alias="X-HMAC-Signature"),
):
    """Receive a single Honeytrap event and push it normalised to the queue."""
    _counters["received"] += 1

    try:
        body: dict = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    _check_hmac(body, x_hmac_signature)

    event = normalize(body)
    if event is None:
        _counters["rejected"] += 1
        raise HTTPException(status_code=422, detail="Event normalisation failed")

    ok = queue.push(event.dict())
    if not ok:
        raise HTTPException(status_code=503, detail="Queue unavailable — retry later")

    _counters["accepted"] += 1
    log.info("Ingested %s session=%s proto=%s", event.id, event.session_id, event.protocol)
    return {"ok": True, "event_id": event.id, "session_id": event.session_id}


@app.post("/ingest/batch", tags=["ingest"])
async def ingest_batch(
    request: Request,
    x_hmac_signature: Optional[str] = Header(None, alias="X-HMAC-Signature"),
):
    """Receive an array of Honeytrap events (max 500 per batch)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be a valid JSON array")

    if not isinstance(body, list):
        raise HTTPException(status_code=422, detail="Expected a JSON array")

    if len(body) > 500:
        raise HTTPException(status_code=413, detail="Batch too large (max 500 events)")

    # Verify HMAC over the entire list as a unit
    _check_hmac({"batch": body}, x_hmac_signature)

    accepted = rejected = 0
    for raw in body:
        _counters["received"] += 1
        event = normalize(raw)
        if event:
            queue.push(event.dict())
            accepted += 1
            _counters["accepted"] += 1
        else:
            rejected += 1
            _counters["rejected"] += 1

    log.info("Batch: accepted=%d rejected=%d", accepted, rejected)
    return {"ok": True, "accepted": accepted, "rejected": rejected}


# ─────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level=LOG_LEVEL.lower())
