"""Authenticated sensor client for a verified SENTINEL monitoring session."""
from __future__ import annotations

import os

import httpx

BACKEND = os.getenv("SENTINEL_BACKEND", "http://127.0.0.1:8000").rstrip("/")
SESSION_ID = os.getenv("SENTINEL_SESSION_ID", "").strip()
GATEWAY_TOKEN = os.getenv("SENTINEL_GATEWAY_TOKEN", "").strip()


def configured() -> bool:
    return bool(SESSION_ID and GATEWAY_TOKEN)


def headers() -> dict[str, str]:
    if not configured():
        raise RuntimeError("Run Setup first, then set SENTINEL_SESSION_ID and SENTINEL_GATEWAY_TOKEN.")
    return {"X-Sentinel-Session": SESSION_ID, "X-Sentinel-Token": GATEWAY_TOKEN}


def send_event(event: dict) -> bool:
    """Post one normalized event. Fail closed in the caller's accounting: a
    failed delivery is reported, never treated as a clean observation."""
    event = {**event, "session_id": SESSION_ID}
    try:
        r = httpx.post(f"{BACKEND}/api/events", json=event, headers=headers(), timeout=8)
        r.raise_for_status()
        return True
    except Exception as exc:
        print(f"[sensor] monitoring delivery failed (state degraded): {exc}")
        return False


def heartbeat() -> bool:
    try:
        r = httpx.post(f"{BACKEND}/api/sessions/{SESSION_ID}/heartbeat", headers=headers(), timeout=5)
        r.raise_for_status()
        return True
    except Exception as exc:
        print(f"[sensor] heartbeat failed (monitoring unavailable until restored): {exc}")
        return False
