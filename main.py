#!/usr/bin/env python3
"""
dashboard/backend/main.py — Dashboard API server.

Provides read endpoints over the shared SQLite DB (written by Cerebrum)
and proxies certain calls to Cerebrum (explain, rules CRUD).

Endpoints:
    GET  /api/sessions                     paginated session list
    GET  /api/sessions/{id}                session detail
    GET  /api/sessions/{id}/events         session event timeline
    GET  /api/sessions/{id}/explain        proxy → Cerebrum /explain/{id}
    GET  /api/sessions/{id}/kg             proxy → Cerebrum KG
    GET  /api/decisions                    recent decisions
    GET  /api/rules                        rule list
    POST /api/rules                        create rule
    PUT  /api/rules/{rule_id}             update rule
    GET  /api/metrics                      aggregated analytics
    GET  /api/metrics/timeseries           hourly event counts
    GET  /api/suggestions                  discovery suggestions
    GET  /healthz
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
PORT = int(os.environ.get("PORT", "8003"))
DB_PATH = os.environ.get("DB_PATH", "../cerebrum/cerebrum.db")
CEREBRUM_URL = os.environ.get("CEREBRUM_URL", "http://cerebrum:8002")
API_TOKEN = os.environ.get("API_TOKEN", "dashboard-secret-token")
DECISIONS_JSONL = os.environ.get("DECISIONS_JSONL", "../cerebrum/decisions.jsonl")
SUGGESTIONS_JSONL = os.environ.get("SUGGESTIONS_JSONL", "../discovery/suggestions.jsonl")

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("dashboard-backend")

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Dynamic Labyrinth Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer = HTTPBearer(auto_error=False)


def require_auth(creds: Optional[HTTPAuthorizationCredentials] = Security(bearer)):
    if creds is None or creds.credentials != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return creds


# ─────────────────────────────────────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────────────────────────────────────


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()


def _rows(conn, sql: str, params=()) -> List[Dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _scalar(conn, sql: str, params=(), default=None):
    row = conn.execute(sql, params).fetchone()
    return row[0] if row else default


# ─────────────────────────────────────────────────────────────────────────────
# Cerebrum proxy
# ─────────────────────────────────────────────────────────────────────────────


async def _cerebrum_get(path: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(f"{CEREBRUM_URL}{path}")
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Cerebrum GET %s failed: %s", path, exc)
        raise HTTPException(status_code=502, detail=f"Cerebrum unavailable: {exc}")


async def _cerebrum_post(path: str, payload: dict) -> dict:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.post(f"{CEREBRUM_URL}{path}", json=payload)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Cerebrum POST %s failed: %s", path, exc)
        raise HTTPException(status_code=502, detail=f"Cerebrum unavailable: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Sessions
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/sessions", tags=["sessions"])
def api_sessions(
    limit: int = Query(50, le=500),
    offset: int = 0,
    level: Optional[int] = None,
    protocol: Optional[str] = None,
    min_score: Optional[int] = None,
    _=Depends(require_auth),
):
    q = "SELECT * FROM sessions WHERE 1=1"
    params: list = []
    if level:
        q += " AND current_level=?"
        params.append(level)
    if protocol:
        q += " AND protocol=?"
        params.append(protocol)
    if min_score is not None:
        q += " AND skill_score>=?"
        params.append(min_score)
    q += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    with get_db() as conn:
        sessions = _rows(conn, q, params)
        total = _scalar(conn, "SELECT COUNT(*) FROM sessions")
    return {"sessions": sessions, "total": total, "limit": limit, "offset": offset}


@app.get("/api/sessions/{session_id}", tags=["sessions"])
def api_session_detail(session_id: str, _=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(row)


@app.get("/api/sessions/{session_id}/events", tags=["sessions"])
def api_session_events(
    session_id: str,
    limit: int = Query(200, le=1000),
    _=Depends(require_auth),
):
    with get_db() as conn:
        rows = _rows(
            conn,
            "SELECT * FROM events WHERE session_id=? ORDER BY timestamp ASC LIMIT ?",
            (session_id, limit),
        )
    for r in rows:
        r["indicators"] = json.loads(r.get("indicators") or "[]")
    return rows


@app.get("/api/sessions/{session_id}/explain", tags=["sessions"])
async def api_explain(session_id: str, _=Depends(require_auth)):
    return await _cerebrum_get(f"/explain/{session_id}")


@app.get("/api/sessions/{session_id}/kg", tags=["sessions"])
async def api_kg(session_id: str, _=Depends(require_auth)):
    return await _cerebrum_get(f"/sessions/{session_id}/kg")


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Decisions
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/decisions", tags=["decisions"])
def api_decisions(
    limit: int = Query(100, le=1000),
    session_id: Optional[str] = None,
    action: Optional[str] = None,
    _=Depends(require_auth),
):
    q = "SELECT * FROM decisions WHERE 1=1"
    params: list = []
    if session_id:
        q += " AND session_id=?"
        params.append(session_id)
    if action:
        q += " AND action=?"
        params.append(action)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = _rows(conn, q, params)
    for r in rows:
        r["evidence"] = json.loads(r.get("evidence") or "[]")
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Rules (proxy to Cerebrum)
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/rules", tags=["rules"])
async def api_rules(_=Depends(require_auth)):
    return await _cerebrum_get("/rules")


@app.post("/api/rules", tags=["rules"], status_code=201)
async def api_create_rule(request: Request, _=Depends(require_auth)):
    body = await request.json()
    return await _cerebrum_post("/rules", body)


@app.put("/api/rules/{rule_id}", tags=["rules"])
async def api_update_rule(rule_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.put(f"{CEREBRUM_URL}/rules/{rule_id}", json=body)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Analytics / Metrics
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/metrics", tags=["metrics"])
def api_metrics(_=Depends(require_auth)):
    with get_db() as conn:
        session_count = _scalar(conn, "SELECT COUNT(*) FROM sessions", default=0)
        event_count = _scalar(conn, "SELECT COUNT(*) FROM events", default=0)
        decision_count = _scalar(conn, "SELECT COUNT(*) FROM decisions", default=0)
        avg_score = _scalar(
            conn, "SELECT ROUND(AVG(skill_score),2) FROM sessions", default=0.0
        )
        level_dist = _rows(
            conn,
            "SELECT current_level, COUNT(*) as count FROM sessions GROUP BY current_level",
        )
        top_rules = _rows(
            conn,
            """SELECT rule_id, COUNT(*) as triggers
               FROM rule_matches GROUP BY rule_id ORDER BY triggers DESC LIMIT 10""",
        )
        top_ips = _rows(
            conn,
            """SELECT source_ip, COUNT(*) as sessions, MAX(skill_score) as max_score
               FROM sessions GROUP BY source_ip ORDER BY sessions DESC LIMIT 10""",
        )
        escalation_rate = _rows(
            conn,
            """SELECT action, COUNT(*) as count FROM decisions
               GROUP BY action ORDER BY count DESC""",
        )
        recent_decisions_per_hour = _rows(
            conn,
            """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
               COUNT(*) as count FROM decisions
               WHERE timestamp >= datetime('now', '-24 hours')
               GROUP BY hour ORDER BY hour""",
        )

    return {
        "session_count": session_count,
        "event_count": event_count,
        "decision_count": decision_count,
        "avg_skill_score": avg_score,
        "level_distribution": level_dist,
        "top_rules": top_rules,
        "top_source_ips": top_ips,
        "escalation_actions": escalation_rate,
        "decisions_per_hour_last_24h": recent_decisions_per_hour,
    }


@app.get("/api/metrics/timeseries", tags=["metrics"])
def api_timeseries(
    hours: int = Query(24, le=168),
    granularity: str = Query("hour", regex="^(hour|day)$"),
    _=Depends(require_auth),
):
    fmt = "%Y-%m-%dT%H:00:00" if granularity == "hour" else "%Y-%m-%d"
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with get_db() as conn:
        events_ts = _rows(
            conn,
            f"""SELECT strftime('{fmt}', timestamp) as bucket, COUNT(*) as events
                FROM events WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket""",
            (cutoff,),
        )
        decisions_ts = _rows(
            conn,
            f"""SELECT strftime('{fmt}', timestamp) as bucket, COUNT(*) as decisions
                FROM decisions WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket""",
            (cutoff,),
        )

    return {"events": events_ts, "decisions": decisions_ts}


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Export
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/export/sessions", tags=["export"])
def export_sessions(_=Depends(require_auth)):
    """Download all sessions as CSV."""
    import csv
    import io

    with get_db() as conn:
        rows = _rows(conn, "SELECT * FROM sessions ORDER BY last_seen DESC")

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sessions.csv"},
    )


@app.get("/api/export/decisions", tags=["export"])
def export_decisions(_=Depends(require_auth)):
    """Download all decisions as JSONL."""
    with get_db() as conn:
        rows = _rows(conn, "SELECT * FROM decisions ORDER BY timestamp DESC")
    for r in rows:
        r["evidence"] = json.loads(r.get("evidence") or "[]")
    lines = "\n".join(json.dumps(r) for r in rows)
    return StreamingResponse(
        iter([lines]),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=decisions.jsonl"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Discovery suggestions
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/api/suggestions", tags=["discovery"])
def api_suggestions(limit: int = Query(50, le=500), _=Depends(require_auth)):
    suggestions = []
    try:
        with open(SUGGESTIONS_JSONL) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    suggestions.append(json.loads(line))
    except FileNotFoundError:
        pass  # discovery pipeline not run yet
    return suggestions[-limit:]


# ─────────────────────────────────────────────────────────────────────────────
# Ops
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/healthz", tags=["ops"])
def healthz():
    return {"status": "ok"}


# ─────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level=LOG_LEVEL.lower())
