"""
Pydantic schemas for Honeytrap raw events and normalized Cerebrum events.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator, Field


class RawHoneytrapEvent(BaseModel):
    """Raw event schema accepted from Honeytrap pushers."""

    id: Optional[str] = None
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    sensor_id: Optional[str] = None

    class Config:
        extra = "allow"  # accept unknown fields from various pusher versions

    @validator("source_ip", pre=True)
    def sanitize_ip(cls, v):
        if v is None:
            return None
        v = str(v).strip()
        # Basic IP sanity — accept IPv4 and IPv6
        if len(v) > 45:
            raise ValueError("source_ip too long")
        return v

    @validator("data", pre=True)
    def cap_data_size(cls, v):
        if v is None:
            return None
        # Prevent huge payloads from flooding the DB
        truncated = {}
        for k, val in (v if isinstance(v, dict) else {}).items():
            s = str(val)
            truncated[str(k)[:64]] = s[:512]
        return truncated


class NormalizedEvent(BaseModel):
    """Canonical event format consumed by Cerebrum."""

    id: str
    session_id: str
    timestamp: str
    protocol: str
    event_type: str
    indicators: List[str] = Field(default_factory=list)
    source_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    raw_data: Optional[Dict[str, Any]] = None
    sensor_id: Optional[str] = None
