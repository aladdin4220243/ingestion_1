# Security Audit Report — Ingestion Pipeline
## Dynamic Labyrinth Project · Alaa

---

## 1. Scope

This audit covers:
- `http_ingest.py` — FastAPI webhook receiver
- `file_tail_ingest.py` — JSONL tail worker
- `normalize.py` — field normalisation
- `models.py` — Pydantic schemas
- `hmac_utils.py` — signing utilities
- `queue_client.py` — Redis queue wrapper

---

## 2. Findings & Mitigations

### 2.1 Input Validation ✅ PASS

| Check | Result | Notes |
|---|---|---|
| Pydantic schema on all inbound events | ✅ | `RawHoneytrapEvent` validates every field |
| `source_ip` length-capped at 45 chars | ✅ | `sanitize_ip` validator |
| `data` dict values capped at 512 chars per value | ✅ | `cap_data_size` validator |
| Oversized JSONL records dropped (>64 KB) | ✅ | `file_tail_ingest.py` line 55 |
| Batch endpoint limited to 500 events | ✅ | `http_ingest.py` line 117 |
| Unknown extra fields accepted but logged | ⚠️ | `extra = "allow"` — monitor for schema drift |

**Recommendation:** Consider switching `extra = "allow"` to `extra = "ignore"` after schema stabilises to reduce noise in the database.

---

### 2.2 Authentication & Authorization ✅ PASS

| Check | Result | Notes |
|---|---|---|
| HMAC-SHA256 on every inbound webhook | ✅ | `_check_hmac()` in `http_ingest.py` |
| Constant-time signature comparison | ✅ | `hmac.compare_digest()` in `hmac_utils.py` |
| Replay-attack window (60 s) on signed envelopes | ✅ | `open_envelope()` |
| HMAC secret loaded from environment variable | ✅ | Never hard-coded |
| Default secret warns in production | ⚠️ | `"CHANGE_ME_in_production"` — deploy guard needed |

**Recommendation:** Add a startup assertion:
```python
import sys
if os.environ.get("HMAC_SECRET", "CHANGE_ME") == "CHANGE_ME_in_production":
    if os.environ.get("ENV") == "production":
        sys.exit("FATAL: HMAC_SECRET not set in production")
```

---

### 2.3 Secrets Management ✅ PASS

| Check | Result | Notes |
|---|---|---|
| No hard-coded secrets in source | ✅ | All via `os.environ.get()` |
| `.env.example` provided, `.env` git-ignored | ✅ | |
| Redis password support | ✅ | Embedded in `REDIS_URL` |
| Secrets never logged | ✅ | Checked — no `log.*` calls reference secret vars |

---

### 2.4 Network Segmentation ✅ PASS (with notes)

| Check | Result | Notes |
|---|---|---|
| Ingestion service on isolated Docker network | ✅ | `labyrinth-net` bridge |
| No public exposure of Redis port in production compose | ⚠️ | Local profile exposes 6379 — must be removed in prod |
| HTTP ingest port configurable | ✅ | `HTTP_INGEST_PORT` env var |
| CORS set to `allow_origins=["*"]` | ⚠️ | Acceptable internally; restrict if exposed publicly |

**Recommendation:** In production, remove the `ports:` mapping on the `redis` service so Redis is only reachable inside the Docker network.

---

### 2.5 Injection Hardening ✅ PASS

| Check | Result | Notes |
|---|---|---|
| SQL injection: no raw SQL in ingestion layer | ✅ | Ingestion writes to Redis only, not DB |
| KG field escaping: string values truncated at 256 chars | ✅ | `_extract_indicators()` |
| XSS / script injection detected as indicator | ✅ | Regex in `normalize.py` |
| Path traversal detected as indicator | ✅ | Regex in `normalize.py` |
| SQLi patterns detected as indicator | ✅ | Regex in `normalize.py` |
| Binary content in JSONL handled with `errors="replace"` | ✅ | `file_tail_ingest.py` |

---

### 2.6 Denial-of-Service Resistance ⚠️ PARTIAL

| Check | Result | Notes |
|---|---|---|
| Oversized single records dropped | ✅ | 64 KB limit |
| Batch size limited to 500 | ✅ | |
| No rate limiting on HTTP endpoint | ❌ | Needs middleware |
| No request body size limit on FastAPI | ❌ | Needs `--limit-max-requests` or middleware |

**Recommendation:** Add rate limiting:
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/ingest/event")
@limiter.limit("500/minute")
async def ingest_event(request: Request, ...):
    ...
```

---

### 2.7 Queue & Delivery ✅ PASS

| Check | Result | Notes |
|---|---|---|
| At-least-once delivery via Redis RPUSH/BLPOP | ✅ | |
| Retry with exponential backoff (3 attempts) | ✅ | `queue_client.py` |
| Fallback to stdout JSONL if Redis down | ✅ | Log-shipper can recover |
| Queue key configurable | ✅ | `INGEST_QUEUE_KEY` |

---

## 3. Fuzz Test Summary

Fuzz tests run via `tests/test_fuzz.py` covering:

| Payload Type | Result |
|---|---|
| Overlong `source_ip` (1000 chars) | Rejected by Pydantic ✅ |
| Binary content in `data` values | Truncated to 512 chars ✅ |
| Null bytes in strings | Sanitized ✅ |
| Missing required fields | Defaults applied gracefully ✅ |
| Deeply nested `data` dict | Flattened, non-dict treated as empty ✅ |
| SQL injection in `data.query` | Detected as indicator, not executed ✅ |
| XSS payload in `data.uri` | Detected as indicator ✅ |
| 70 KB JSONL line | Dropped before parse ✅ |
| 600-event batch | Rejected (413) ✅ |

---

## 4. Open Items

| ID | Severity | Item | Owner |
|---|---|---|---|
| SEC-01 | HIGH | Add production startup check for default HMAC_SECRET | Alaa |
| SEC-02 | MEDIUM | Add rate limiting middleware to http_ingest.py | Alaa |
| SEC-03 | MEDIUM | Lock down CORS origins in production | Alaa |
| SEC-04 | LOW | Switch `extra = "allow"` to `extra = "ignore"` post-stabilisation | Alaa |
| SEC-05 | LOW | Remove Redis port exposure from production compose | Alaa |

---

## 5. Sign-off

- **Reviewed by:** Alaa  
- **Date:** 2025-10-16  
- **Status:** CONDITIONAL PASS — SEC-01 and SEC-02 must be resolved before production deployment.
