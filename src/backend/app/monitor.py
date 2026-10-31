"""Automatic target-health monitor started after verified Setup.

This confirms the declared URL remains reachable and reports degradation. It does
not pretend URL polling alone can observe agent internals: agent actions require
the enrolled sensor/Gateway integrations issued during Setup.
"""
from __future__ import annotations

import asyncio
import os
import time

import httpx

_TASKS: dict[str, asyncio.Task] = {}


def start(session_id: str, target: str, on_health) -> None:
    old = _TASKS.get(session_id)
    if old and not old.done():
        return
    _TASKS[session_id] = asyncio.create_task(_loop(session_id, target, on_health))


def stop(session_id: str) -> None:
    task = _TASKS.pop(session_id, None)
    if task:
        task.cancel()


async def _loop(session_id: str, target: str, on_health) -> None:
    interval = max(15, min(300, int(os.getenv("SENTINEL_TARGET_POLL_SECONDS", "30"))))
    while True:
        started = time.perf_counter()
        report = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "target": target, "reachable": False, "status_code": None,
                  "latency_ms": None, "error": None}
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False,
                                         headers={"User-Agent": "SENTINEL-APEX-Monitor/1.0"}) as client:
                r = await client.head(target)
                if r.status_code in (405, 501):
                    r = await client.get(target, headers={"Range": "bytes=0-0"})
                report.update(reachable=r.status_code < 500, status_code=r.status_code,
                              latency_ms=round((time.perf_counter() - started) * 1000, 1))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            report["error"] = type(exc).__name__
            report["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        on_health(session_id, report)
        await asyncio.sleep(interval)
