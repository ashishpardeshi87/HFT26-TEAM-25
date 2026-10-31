"""Monitoring-state tracker (Questionable-Points E3 / B5).

Absence of evidence is not evidence of safety. We track the freshness of sensor
telemetry via a heartbeat and report an overall state — active / degraded /
unavailable. The one hard rule: a monitoring failure must never be interpreted
as a safe system.
"""
from __future__ import annotations

import time

ACTIVE_WINDOW_S = 30
DEGRADED_WINDOW_S = 120

_last_heartbeat: float = 0.0
_events_seen: int = 0


def heartbeat() -> None:
    global _last_heartbeat, _events_seen
    _last_heartbeat = time.time()
    _events_seen += 1


def state(now: float | None = None) -> str:
    gap = (now or time.time()) - _last_heartbeat
    if gap <= ACTIVE_WINDOW_S:
        return "active"
    if gap <= DEGRADED_WINDOW_S:
        return "degraded"
    return "unavailable"


def safe_to_conclude_clean(now: float | None = None) -> bool:
    """Never conclude 'safe' from incomplete telemetry."""
    return state(now) == "active"


def report(now: float | None = None) -> dict:
    st = state(now)
    return {
        "monitoring_state": st,
        "events_seen": _events_seen,
        "last_heartbeat_age_s": round((now or time.time()) - _last_heartbeat, 1),
        "safe_to_conclude_clean": st == "active",
        "note": ("Telemetry fresh — detection active." if st == "active"
                 else "Telemetry stale/absent — degrade conservatively; the system is NOT concluded safe."),
    }
