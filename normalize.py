"""
Event normalisation: raw Honeytrap dict → NormalizedEvent.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from models import NormalizedEvent, RawHoneytrapEvent

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Field extraction helpers
# ─────────────────────────────────────────────────────────────────────────────

_INDICATOR_FIELDS = (
    "username", "password", "payload", "uri", "url",
    "user_agent", "command", "query", "host", "path",
)

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
)


def _coerce_timestamp(ts: Optional[str]) -> str:
    """Normalise any timestamp string to ISO-8601 UTC."""
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return ts  # best-effort passthrough


def _make_session_id(source_ip: str, protocol: str) -> str:
    """Stable, readable session ID derived from attacker IP + protocol."""
    clean_ip = re.sub(r"[^a-zA-Z0-9]", "_", source_ip)
    return f"{protocol}_{clean_ip}"


def _extract_indicators(raw: RawHoneytrapEvent) -> List[str]:
    """Pull security-relevant strings from the raw event data dict."""
    indicators: List[str] = []
    data: Dict = raw.data or {}

    for field in _INDICATOR_FIELDS:
        val = data.get(field)
        if val and isinstance(val, str) and val.strip():
            indicators.append(val.strip()[:256])

    if raw.destination_port:
        indicators.append(f"port_{raw.destination_port}")

    # Detect common attack patterns in the data blob
    blob = " ".join(str(v) for v in data.values())
    if re.search(r"(?:root|admin|administrator)", blob, re.I):
        indicators.append("privileged_user_attempt")
    if re.search(r"(?:\.\.\/|%2e%2e|directory\s+traversal)", blob, re.I):
        indicators.append("path_traversal")
    if re.search(r"(?:<script|javascript:|onerror=)", blob, re.I):
        indicators.append("xss_attempt")
    if re.search(r"(?:union\s+select|drop\s+table|--|;--)", blob, re.I):
        indicators.append("sql_injection")

    return list(dict.fromkeys(indicators))  # deduplicate, preserve order


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def normalize(honeytrap_event: dict) -> Optional[NormalizedEvent]:
    """
    Normalise *honeytrap_event* into a ``NormalizedEvent``.

    Returns ``None`` if the event is invalid and should be dropped;
    errors are logged but never raised so the caller can continue.
    """
    try:
        raw = RawHoneytrapEvent(**honeytrap_event)

        source_ip: str = (raw.source_ip or "0.0.0.0").strip()
        protocol: str = (raw.protocol or "unknown").lower().strip()
        event_type: str = (raw.event_type or "unknown").lower().strip()

        return NormalizedEvent(
            id=raw.id or str(uuid.uuid4()),
            session_id=_make_session_id(source_ip, protocol),
            timestamp=_coerce_timestamp(raw.timestamp),
            protocol=protocol,
            event_type=event_type,
            indicators=_extract_indicators(raw),
            source_ip=source_ip,
            source_port=raw.source_port,
            destination_port=raw.destination_port,
            raw_data=raw.data,
            sensor_id=raw.sensor_id,
        )

    except Exception as exc:
        log.error("Normalization failed: %s | raw=%s", exc, str(honeytrap_event)[:200])
        return None
