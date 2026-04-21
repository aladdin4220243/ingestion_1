# Ingestion Service — Dynamic Labyrinth

**Owner:** Alaa · Role: Security & Integration

Robust Honeytrap event ingestion pipeline that normalises raw events into the Cerebrum format, signs them with HMAC, and delivers them via Redis queue.

---

## Architecture

```
Honeytrap (file pusher)
        │  JSONL lines
        ▼
file_tail_ingest.py ──┐
                      ├──► normalize.py ──► queue_client.py ──► Redis ──► Cerebrum
http_ingest.py ───────┘
  (FastAPI /ingest/event
         /ingest/batch)
```

---

## Quick Start

```bash
# 1. Clone and enter this directory
cd ingestion/

# 2. Configure environment
cp .env.example .env
$EDITOR .env   # set REDIS_URL and HMAC_SECRET

# 3. Start with local Redis
docker compose --profile local up -d

# 4. Or, start without local Redis (use cloud Redis URL in .env)
docker compose up -d
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `INGEST_QUEUE_KEY` | `cerebrum:events` | Redis list key |
| `HMAC_SECRET` | `CHANGE_ME_in_production` | Shared HMAC secret (must match Cerebrum) |
| `REQUIRE_HMAC` | `true` | Enforce HMAC on incoming webhooks |
| `HONEYTRAP_LOG_PATH` | `/var/log/honeytrap/events.jsonl` | Log file for file-tail mode |
| `POLL_INTERVAL` | `0.5` | File-tail polling interval (seconds) |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `PORT` | `8001` | HTTP server port |

---

## Endpoints (http_ingest)

| Method | Path | Description |
|---|---|---|
| `POST` | `/ingest/event` | Single event (signed) |
| `POST` | `/ingest/batch` | Up to 500 events (signed) |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/metrics` | Counters + queue depth |
| `GET` | `/docs` | Interactive Swagger UI |

### Authentication

All `POST` endpoints require an `X-HMAC-Signature` header when `REQUIRE_HMAC=true`:

```bash
PAYLOAD='{"id":"evt-001","protocol":"ssh","event_type":"auth_failed"}'
SIG=$(python3 -c "
import hmac, hashlib, json, os
secret = os.environ['HMAC_SECRET'].encode()
body = json.dumps(json.loads('$PAYLOAD'), sort_keys=True, separators=(',',':')).encode()
print(hmac.new(secret, body, hashlib.sha256).hexdigest())
")
curl -X POST http://localhost:8001/ingest/event \
     -H "Content-Type: application/json" \
     -H "X-HMAC-Signature: $SIG" \
     -d "$PAYLOAD"
```

---

## File Tail Mode

```bash
# Run the file-tail worker directly
python file_tail_ingest.py --file /var/log/honeytrap/events.jsonl

# Or via Docker Compose (already configured)
docker compose up file-ingest
```

The worker seeks to EOF on startup and tails new lines as they arrive. It tolerates malformed JSON lines and oversized records (>64 KB) without crashing.

---

## Adapters (ingest-adapters/)

| Adapter | Description |
|---|---|
| `FileAdapter` | Async file reader (alternative to file_tail_ingest) |
| `HTTPAdapter` | aiohttp webhook receiver |
| `KafkaAdapter` | Kafka consumer (requires `aiokafka`) |
| `ElasticsearchAdapter` | ES scroll reader (requires `elasticsearch[async]`) |

Usage:

```python
from ingest_adapters import FileAdapter
from normalize import normalize
from queue_client import QueueClient

queue = QueueClient()

async def on_event(raw: dict):
    event = normalize(raw)
    if event:
        queue.push(event.dict())

adapter = FileAdapter("/var/log/honeytrap/events.jsonl", callback=on_event)
await adapter.start()
```

---

## Testing

```bash
# Install deps
pip install -r requirements.txt

# Run all tests
pytest tests/ -v --tb=short

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing

# Run only fuzz tests
pytest tests/ -v -k "Fuzz"
```

---

## Sample JSON Event (Honeytrap format)

```json
{
  "id": "evt-abc123",
  "timestamp": "2025-10-16T19:00:00Z",
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "destination_ip": "10.0.0.1",
  "destination_port": 22,
  "protocol": "ssh",
  "event_type": "authentication_failed",
  "data": {
    "username": "root",
    "password": "password123"
  },
  "sensor_id": "sensor-egypt-01"
}
```

Normalised output pushed to Redis:

```json
{
  "id": "evt-abc123",
  "session_id": "ssh_1_2_3_4",
  "timestamp": "2025-10-16T19:00:00+00:00",
  "protocol": "ssh",
  "event_type": "authentication_failed",
  "indicators": ["root", "password123", "port_22", "privileged_user_attempt"],
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "destination_port": 22,
  "raw_data": {"username": "root", "password": "password123"},
  "sensor_id": "sensor-egypt-01"
}
```

---

## Integration with Cerebrum

Cerebrum consumes events by calling `QueueClient().pop()` in a loop. Both services must share:
- The same `REDIS_URL` and `INGEST_QUEUE_KEY`
- The same `HMAC_SECRET` for internal API calls

See `hmac_utils.py` → `auth_headers()` for how to attach HMAC to outgoing requests.

---

## Repo Layout

```
ingestion/
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── requirements.txt
├── models.py              # Pydantic schemas
├── normalize.py           # Raw → NormalizedEvent
├── queue_client.py        # Redis FIFO queue
├── hmac_utils.py          # HMAC signing utilities
├── http_ingest.py         # FastAPI webhook server
├── file_tail_ingest.py    # JSONL file tail worker
├── ingest-adapters/       # Pluggable source adapters
│   ├── __init__.py
│   ├── file_adapter.py
│   ├── http_adapter.py
│   ├── kafka_adapter.py
│   └── elasticsearch_adapter.py
├── tests/
│   ├── conftest.py
│   └── test_ingestion.py  # Unit + fuzz + integration tests
├── SECURITY_AUDIT.md
└── README.md
```
