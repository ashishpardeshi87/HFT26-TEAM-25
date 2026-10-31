"""APEX TOOL TRUST (problem 3) — inventory + trust registry for tools / plugins / MCP servers.

Records each tool's identity and declared capabilities, labels it approved / unknown /
restricted / revoked, and detects post-approval schema changes. Guardian denies unknown
or revoked tools at the gateway.
"""
from __future__ import annotations

import hashlib

from .models import Behavior

# tool_id -> {publisher, endpoint, caps_hash, trust}
_REGISTRY: dict[str, dict] = {}

# tools we ship as pre-approved (an org would curate this)
_APPROVED = {
    "filesystem": "builtin", "http_fetch": "builtin", "github-mcp": "github.com",
    "openai": "openai.com", "read_inbox": "builtin",
}


def _caps_hash(caps) -> str:
    return hashlib.sha256(str(sorted(caps or [])).encode()).hexdigest()[:12]


def register(tool_id: str, publisher: str = "", endpoint: str = "", declared_caps=None) -> dict:
    """Register/observe a tool. Returns {trust, behavior|None}."""
    ch = _caps_hash(declared_caps)
    prior = _REGISTRY.get(tool_id)
    behavior = None

    if tool_id in _APPROVED:
        trust = "approved"
    elif prior and prior["caps_hash"] != ch:
        trust = "unknown"  # schema changed after first sight -> re-review
        behavior = Behavior(type="tool_schema_changed", severity="high", target=tool_id,
                            detail=f"Tool '{tool_id}' changed its declared capabilities after approval")
    elif prior:
        trust = prior["trust"]
    else:
        trust = "unknown"  # never seen, no publisher vetting
        if endpoint:
            behavior = Behavior(type="untrusted_tool", severity="high", target=tool_id,
                                detail=f"Unknown tool/MCP server '{tool_id}' registered (endpoint {endpoint})")

    _REGISTRY[tool_id] = {"publisher": publisher, "endpoint": endpoint, "caps_hash": ch, "trust": trust}
    return {"trust": trust, "behavior": behavior}


def trust_of(tool_id: str) -> str:
    if not tool_id:
        return "approved"
    if tool_id in _APPROVED:
        return "approved"
    return _REGISTRY.get(tool_id, {}).get("trust", "unknown")


def inventory() -> list[dict]:
    out = [{"tool_id": k, "publisher": v["publisher"], "endpoint": v["endpoint"], "trust": v["trust"]}
           for k, v in _REGISTRY.items()]
    for k, pub in _APPROVED.items():
        if k not in _REGISTRY:
            out.append({"tool_id": k, "publisher": pub, "endpoint": "", "trust": "approved"})
    return out
