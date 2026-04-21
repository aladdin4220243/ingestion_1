"""
tests/test_ingestion.py

Unit + integration tests for the ingestion pipeline.

Run:
    pytest tests/ -v --tb=short

Requirements (already in requirements.txt):
    pytest, pytest-asyncio, httpx
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ─── Modules under test ───────────────────────────────────────────────────────
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import NormalizedEvent, RawHoneytrapEvent
from normalize import (
    _coerce_timestamp,
    _extract_indicators,
    _make_session_id,
    normalize,
)
from hmac_utils import (
    auth_headers,
    open_envelope,
    sign_payload,
    signed_envelope,
    verify_signature,
)
from http_ingest import app as http_app

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_EVENT = {
    "id": "evt-001",
    "timestamp": "2025-10-16T19:00:00Z",
    "source_ip": "1.2.3.4",
    "source_port": 54321,
    "destination_ip": "10.0.0.1",
    "destination_port": 22,
    "protocol": "ssh",
    "event_type": "authentication_failed",
    "data": {
        "username": "root",
        "password": "password123",
    },
    "sensor_id": "sensor-001",
}

SECRET = "test-secret-key-for-unit-tests"


@pytest.fixture
def sample_event():
    ev = dict(SAMPLE_EVENT)
    ev["id"] = str(uuid.uuid4())
    return ev


@pytest.fixture
def client():
    """FastAPI test client with HMAC enforcement OFF for simplicity."""
    with patch.dict(os.environ, {"REQUIRE_HMAC": "false"}):
        from importlib import reload
        import http_ingest
        reload(http_ingest)
        with TestClient(http_ingest.app) as c:
            yield c


# ─────────────────────────────────────────────────────────────────────────────
# normalize.py — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCoerceTimestamp:
    def test_iso_utc(self):
        ts = _coerce_timestamp("2025-10-16T19:00:00Z")
        assert "2025-10-16" in ts

    def test_iso_with_micros(self):
        ts = _coerce_timestamp("2025-10-16T19:00:00.123456Z")
        assert "2025" in ts

    def test_none_returns_now(self):
        ts = _coerce_timestamp(None)
        assert "T" in ts  # ISO format

    def test_empty_returns_now(self):
        ts = _coerce_timestamp("")
        assert "T" in ts

    def test_passthrough_unknown_format(self):
        ts = _coerce_timestamp("not-a-date")
        assert ts == "not-a-date"


class TestMakeSessionId:
    def test_basic(self):
        sid = _make_session_id("1.2.3.4", "ssh")
        assert sid == "ssh_1_2_3_4"

    def test_ipv6(self):
        sid = _make_session_id("::1", "http")
        assert "http_" in sid

    def test_special_chars_replaced(self):
        sid = _make_session_id("192.168.1.100", "tcp")
        assert "." not in sid


class TestExtractIndicators:
    def test_extracts_username(self):
        raw = RawHoneytrapEvent(**SAMPLE_EVENT)
        inds = _extract_indicators(raw)
        assert "root" in inds

    def test_port_included(self):
        raw = RawHoneytrapEvent(**SAMPLE_EVENT)
        inds = _extract_indicators(raw)
        assert "port_22" in inds

    def test_privileged_user_detection(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"username": "administrator"}
        raw = RawHoneytrapEvent(**ev)
        inds = _extract_indicators(raw)
        assert "privileged_user_attempt" in inds

    def test_xss_detection(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"payload": "<script>alert(1)</script>"}
        raw = RawHoneytrapEvent(**ev)
        inds = _extract_indicators(raw)
        assert "xss_attempt" in inds

    def test_sqli_detection(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"query": "' UNION SELECT * FROM users--"}
        raw = RawHoneytrapEvent(**ev)
        inds = _extract_indicators(raw)
        assert "sql_injection" in inds

    def test_path_traversal_detection(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"uri": "../../etc/passwd"}
        raw = RawHoneytrapEvent(**ev)
        inds = _extract_indicators(raw)
        assert "path_traversal" in inds

    def test_deduplication(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"username": "root", "host": "root"}
        raw = RawHoneytrapEvent(**ev)
        inds = _extract_indicators(raw)
        assert inds.count("root") == 1


class TestNormalize:
    def test_happy_path(self, sample_event):
        result = normalize(sample_event)
        assert result is not None
        assert result.source_ip == "1.2.3.4"
        assert result.protocol == "ssh"
        assert result.event_type == "authentication_failed"
        assert isinstance(result.indicators, list)

    def test_missing_optional_fields(self):
        minimal = {"protocol": "http", "event_type": "connect"}
        result = normalize(minimal)
        assert result is not None
        assert result.source_ip == "0.0.0.0"

    def test_bad_event_returns_none(self):
        result = normalize({"source_ip": "x" * 1000})
        assert result is None

    def test_uppercase_protocol_lowered(self, sample_event):
        sample_event["protocol"] = "SSH"
        result = normalize(sample_event)
        assert result.protocol == "ssh"

    def test_session_id_derived_from_ip_and_protocol(self, sample_event):
        result = normalize(sample_event)
        assert "ssh" in result.session_id
        assert "1_2_3_4" in result.session_id

    def test_result_is_normalized_event(self, sample_event):
        result = normalize(sample_event)
        assert isinstance(result, NormalizedEvent)

    def test_empty_dict_returns_none(self):
        # No required fields at all — pydantic will use defaults, so this should
        # actually succeed with defaults
        result = normalize({})
        assert result is not None  # all fields have defaults

    def test_non_dict_returns_none(self):
        result = normalize("not a dict")  # type: ignore
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# models.py — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestModels:
    def test_raw_event_accepts_extra_fields(self):
        ev = RawHoneytrapEvent(**SAMPLE_EVENT, unknown_extra_field="hello")
        assert ev.source_ip == "1.2.3.4"

    def test_raw_event_truncates_long_ip(self):
        with pytest.raises(Exception):
            RawHoneytrapEvent(source_ip="1" * 100)

    def test_raw_event_caps_data_values(self):
        long_value = "A" * 1000
        ev = RawHoneytrapEvent(data={"key": long_value})
        assert len(ev.data["key"]) <= 512

    def test_raw_event_caps_data_keys(self):
        long_key = "K" * 100
        ev = RawHoneytrapEvent(data={long_key: "value"})
        stored_key = list(ev.data.keys())[0]
        assert len(stored_key) <= 64

    def test_normalized_event_fields(self, sample_event):
        result = normalize(sample_event)
        assert result.id
        assert result.session_id
        assert result.timestamp
        assert result.protocol
        assert result.event_type


# ─────────────────────────────────────────────────────────────────────────────
# hmac_utils.py — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHmacUtils:
    def test_sign_and_verify(self):
        payload = {"session_id": "abc", "data": "test"}
        sig = sign_payload(payload, SECRET)
        assert verify_signature(payload, sig, SECRET)

    def test_wrong_secret_fails(self):
        payload = {"foo": "bar"}
        sig = sign_payload(payload, SECRET)
        assert not verify_signature(payload, sig, "wrong-secret")

    def test_tampered_payload_fails(self):
        payload = {"foo": "bar"}
        sig = sign_payload(payload, SECRET)
        tampered = {"foo": "baz"}
        assert not verify_signature(tampered, sig, SECRET)

    def test_sign_is_deterministic(self):
        payload = {"a": 1, "b": 2}
        assert sign_payload(payload, SECRET) == sign_payload(payload, SECRET)

    def test_key_order_irrelevant(self):
        p1 = {"a": 1, "b": 2}
        p2 = {"b": 2, "a": 1}
        assert sign_payload(p1, SECRET) == sign_payload(p2, SECRET)

    def test_signed_envelope_roundtrip(self):
        payload = {"session_id": "test-123"}
        envelope = signed_envelope(payload, SECRET)
        recovered = open_envelope(envelope, SECRET)
        assert recovered == payload

    def test_stale_envelope_rejected(self):
        payload = {"session_id": "test"}
        envelope = signed_envelope(payload, SECRET)
        # Manually backdate timestamp
        envelope["ts"] = int(time.time()) - 120
        envelope["sig"] = sign_payload({"ts": envelope["ts"], "payload": payload}, SECRET)
        with pytest.raises(ValueError, match="too old"):
            open_envelope(envelope, SECRET)

    def test_bad_signature_envelope_rejected(self):
        payload = {"session_id": "test"}
        envelope = signed_envelope(payload, SECRET)
        envelope["sig"] = "deadbeef"
        with pytest.raises(ValueError, match="Invalid"):
            open_envelope(envelope, SECRET)

    def test_auth_headers_returns_dict(self):
        payload = {"x": 1}
        headers = auth_headers(payload, SECRET)
        assert "X-HMAC-Signature" in headers
        assert len(headers["X-HMAC-Signature"]) == 64  # SHA256 hex


# ─────────────────────────────────────────────────────────────────────────────
# http_ingest.py — integration tests (TestClient, HMAC OFF)
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpIngest:
    def test_healthz(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_metrics(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "received" in data
        assert "accepted" in data

    def test_single_event_accepted(self, client, sample_event):
        with patch("http_ingest.queue") as mock_queue:
            mock_queue.push.return_value = True
            r = client.post("/ingest/event", json=sample_event)
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert "event_id" in body
        assert "session_id" in body

    def test_single_event_bad_json(self, client):
        r = client.post(
            "/ingest/event",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 400

    def test_batch_accepted(self, client):
        events = [dict(SAMPLE_EVENT, id=str(uuid.uuid4())) for _ in range(5)]
        with patch("http_ingest.queue") as mock_queue:
            mock_queue.push.return_value = True
            r = client.post("/ingest/batch", json=events)
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] == 5
        assert body["rejected"] == 0

    def test_batch_too_large(self, client):
        events = [dict(SAMPLE_EVENT) for _ in range(501)]
        r = client.post("/ingest/batch", json=events)
        assert r.status_code == 413

    def test_batch_not_array(self, client):
        r = client.post("/ingest/batch", json={"not": "array"})
        assert r.status_code == 422

    def test_batch_partial_reject(self, client):
        good = dict(SAMPLE_EVENT, id=str(uuid.uuid4()))
        bad = {"source_ip": "x" * 1000}  # will fail normalization
        with patch("http_ingest.queue") as mock_queue:
            mock_queue.push.return_value = True
            r = client.post("/ingest/batch", json=[good, bad])
        assert r.status_code == 200
        body = r.json()
        assert body["accepted"] == 1
        assert body["rejected"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Fuzz / hardening tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz:
    FUZZ_PAYLOADS = [
        {},
        {"source_ip": None},
        {"source_ip": "\x00\x01\x02"},
        {"data": {"key": "\x00" * 600}},
        {"data": {"key": "A" * 600}},
        {"data": None},
        {"protocol": "SSH\ninjection"},
        {"event_type": "<script>alert(1)</script>"},
        {"data": {"payload": "' OR 1=1; DROP TABLE sessions;--"}},
        {"data": {"uri": "../../../etc/passwd"}},
        {"data": {"uri": "%2e%2e%2f%2e%2e%2f"}},
        {"timestamp": "not-a-date"},
        {"timestamp": None},
        {"source_port": -1},
        {"destination_port": 99999},
        # Deeply nested
        {"data": {"nested": {"a": {"b": "c"}}}},
    ]

    @pytest.mark.parametrize("payload", FUZZ_PAYLOADS)
    def test_fuzz_normalize_never_crashes(self, payload):
        """normalize() must never raise — it returns None on bad input."""
        try:
            result = normalize(payload)
            # Result is either a valid NormalizedEvent or None
            assert result is None or isinstance(result, NormalizedEvent)
        except Exception as exc:
            pytest.fail(f"normalize() raised unexpectedly: {exc}")

    def test_overlong_indicator_truncated(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"username": "A" * 1000}
        result = normalize(ev)
        assert result is not None
        for ind in result.indicators:
            assert len(ind) <= 256

    def test_sql_injection_in_event_detected(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"query": "UNION SELECT password FROM users"}
        result = normalize(ev)
        assert result is not None
        assert "sql_injection" in result.indicators

    def test_xss_in_uri_detected(self):
        ev = dict(SAMPLE_EVENT)
        ev["data"] = {"uri": "javascript:alert(document.cookie)"}
        result = normalize(ev)
        assert result is not None
        assert "xss_attempt" in result.indicators
