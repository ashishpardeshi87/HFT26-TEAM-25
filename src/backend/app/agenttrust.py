"""APEX AGENT TRUST (problem 7) — authenticate inter-agent messages and scope delegation.

An agent does NOT inherit another agent's permissions or trust. A message whose chain
traces back to tainted content arrives tainted, and Guardian evaluates it like any other
untrusted input before the receiving agent acts.
"""
from __future__ import annotations

from .models import Behavior

# agent_id -> trust level (an org would manage identities/keys here)
_AGENTS: dict[str, str] = {}


def register(agent_id: str, trust: str = "known") -> None:
    _AGENTS[agent_id] = trust


def check_message(from_agent: str, to_agent: str, provenance_tainted: bool, spoofed: bool = False) -> dict:
    """Return {tainted, taint, behavior|None} for an A->B message."""
    if spoofed:
        return {"tainted": True, "taint": 80,
                "behavior": Behavior(type="untrusted_agent_message", severity="critical", target=f"{from_agent}->{to_agent}",
                                     detail=f"Unauthenticated/spoofed message claiming to be from '{from_agent}'")}
    if provenance_tainted or _AGENTS.get(from_agent) == "untrusted":
        return {"tainted": True, "taint": 70,
                "behavior": Behavior(type="untrusted_agent_message", severity="high", target=f"{from_agent}->{to_agent}",
                                     detail=f"Message from '{from_agent}' traces back to tainted content — "
                                            f"'{to_agent}' must not inherit its trust")}
    return {"tainted": False, "taint": 0, "behavior": None}
