"""Public sample contracts used by the repository heartbeat slice."""

from typing import Literal

from pydantic import BaseModel, Field


class Heartbeat(BaseModel):
    """Small, non-sensitive service heartbeat."""

    agent_name: str = Field(min_length=1, max_length=80)
    status: Literal["online", "degraded"] = "online"


class HeartbeatReceipt(BaseModel):
    accepted: bool
    agent_name: str
    status: str
