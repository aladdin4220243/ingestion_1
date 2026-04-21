"""
HMAC-SHA256 signing and verification utilities.
All internal service-to-service calls are authenticated with these helpers.
Secret is loaded from env; never hard-coded.
"""
import hashlib
import hmac
import json
import os
import time
from typing import Dict

HMAC_SECRET: str = os.environ.get("HMAC_SECRET", "CHANGE_ME_in_production")


# ─────────────────────────────────────────────────────────────────────────────
# Core helpers
# ─────────────────────────────────────────────────────────────────────────────


def _canonical(payload: Dict) -> bytes:
    """Stable JSON serialisation of a dict for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_payload(payload: Dict, secret: str = HMAC_SECRET) -> str:
    """Return hex-encoded HMAC-SHA256 digest for *payload*."""
    return hmac.new(secret.encode(), _canonical(payload), hashlib.sha256).hexdigest()


def verify_signature(payload: Dict, signature: str, secret: str = HMAC_SECRET) -> bool:
    """Constant-time comparison of expected vs. provided signature."""
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(expected, signature)


# ─────────────────────────────────────────────────────────────────────────────
# Timestamped envelopes (replay-attack protection)
# ─────────────────────────────────────────────────────────────────────────────

_REPLAY_WINDOW_SECONDS = 60


def signed_envelope(payload: Dict, secret: str = HMAC_SECRET) -> Dict:
    """Wrap *payload* with a timestamp and HMAC signature."""
    ts = int(time.time())
    envelope = {"ts": ts, "payload": payload}
    envelope["sig"] = sign_payload(envelope, secret)
    return envelope


def open_envelope(envelope: Dict, secret: str = HMAC_SECRET) -> Dict:
    """
    Verify and unwrap a signed envelope.
    Raises ValueError on bad signature or stale timestamp.
    """
    sig = envelope.get("sig", "")
    ts = envelope.get("ts", 0)
    check = {"ts": ts, "payload": envelope.get("payload", {})}
    if not verify_signature(check, sig, secret):
        raise ValueError("Invalid HMAC signature")
    age = abs(time.time() - ts)
    if age > _REPLAY_WINDOW_SECONDS:
        raise ValueError(f"Envelope timestamp too old ({age:.0f}s)")
    return envelope["payload"]


def auth_headers(payload: Dict, secret: str = HMAC_SECRET) -> Dict[str, str]:
    """Return HTTP headers dict containing HMAC signature for *payload*."""
    return {"X-HMAC-Signature": sign_payload(payload, secret)}
