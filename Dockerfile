FROM python:3.11-slim

LABEL maintainer="Alaa"
LABEL description="Dynamic Labyrinth — Honeytrap Event Ingestion Service"

WORKDIR /app

# System deps (gcc for any C-extension wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY models.py normalize.py queue_client.py hmac_utils.py ./
COPY http_ingest.py file_tail_ingest.py ./
COPY ingest-adapters/ ./ingest-adapters/

# Honeytrap log directory (bind-mounted at runtime)
RUN mkdir -p /var/log/honeytrap /app/data

# Non-root user
RUN useradd -m -u 1000 ingestion \
    && chown -R ingestion:ingestion /app /var/log/honeytrap
USER ingestion

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/healthz || exit 1

# Default: run the HTTP ingest server.
# Override CMD in docker-compose for file_tail_ingest mode.
CMD ["uvicorn", "http_ingest:app", "--host", "0.0.0.0", "--port", "8001", "--log-level", "info"]
