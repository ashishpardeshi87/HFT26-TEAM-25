"""SENTINEL APEX public sample API.

This runnable slice demonstrates service wiring with a benign heartbeat only.
Production security engines are not included in this public sample.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .contracts import Heartbeat, HeartbeatReceipt

app = FastAPI(
    title="SENTINEL APEX",
    description="AI security monitoring prototype — public heartbeat slice",
    version="0.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:4173", "http://localhost:4173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Return readiness without exposing configuration details."""
    return {"status": "ok", "service": "sentinel-apex", "slice": "public-sample"}


@app.post("/sample/heartbeat", response_model=HeartbeatReceipt, tags=["sample"])
async def receive_heartbeat(heartbeat: Heartbeat) -> HeartbeatReceipt:
    """Acknowledge a benign sample heartbeat without storing it."""
    return HeartbeatReceipt(
        accepted=True,
        agent_name=heartbeat.agent_name,
        status=heartbeat.status,
    )
