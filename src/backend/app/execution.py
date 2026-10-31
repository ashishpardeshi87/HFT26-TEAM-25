"""Short-lived, action-bound execution capabilities (TOCTOU narrowing).

Guardian approval alone is not execution authority. ALLOW/WARN returns a signed,
single-use capability bound to exact normalized inputs, policy version, resource
hash and resolved destination IPs. The managed adapter commits it immediately
before execution. Any change, redirect outside the allowlist, DNS change, expiry,
or replay denies the commit.

This narrows the race window; it cannot eliminate every OS/filesystem race because
SENTINEL does not execute the external tool atomically itself.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import time
from urllib.parse import urlparse

from . import manifest, policy

_KEY = os.getenv("SENTINEL_EXECUTION_HMAC_KEY", "").encode() or secrets.token_bytes(32)
_USED: set[str] = set()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_action(data: dict) -> dict:
    return {
        "session_id": str(data.get("session_id") or ""),
        "agent_id": str(data.get("agent_id") or ""),
        "tool": str(data.get("tool") or ""),
        "args": str(data.get("args") or ""),
        "scope": str(data.get("scope") or ""),
        "destination": str(data.get("destination") or "").lower().rstrip("."),
        "resource_hash": str(data.get("resource_hash") or ""),
    }


def _host(value: str) -> str:
    raw = value or ""
    if "@" in raw and "://" not in raw:
        raw = raw.rsplit("@", 1)[-1]
    if "://" not in raw:
        raw = "https://" + raw
    return (urlparse(raw).hostname or "").lower().rstrip(".")


def resolve_ips(destination: str) -> list[str]:
    host = _host(destination)
    if not host:
        return []
    try:
        return sorted({row[4][0] for row in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def issue(action: dict, capability_epoch: int | None = None, ttl_seconds: int = 20) -> dict:
    exact = canonical_action(action)
    epoch = int(capability_epoch if capability_epoch is not None else action.get("capability_epoch", 0))
    payload = {
        "action": exact,
        "capability_epoch": epoch,
        "policy_version": policy.version(),
        "resolved_ips": resolve_ips(exact["destination"]),
        "iat": int(time.time()),
        "exp": int(time.time()) + max(5, min(60, ttl_seconds)),
        "jti": secrets.token_urlsafe(12),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(_KEY, raw, hashlib.sha256).digest()
    return {
        "token": _b64(raw) + "." + _b64(sig),
        "expires_at": payload["exp"],
        "resolved_ips": payload["resolved_ips"],
        "binding": exact,
        "capability_epoch": epoch,
        "single_use": True,
    }


def commit(token: str, action: dict, redirect_chain: list[str] | None = None, *,
           agent_state: dict | None = None, session_status: str = "monitoring") -> dict:
    try:
        p, s = token.split(".", 1)
        raw = _unb64(p); supplied = _unb64(s)
        expected = hmac.new(_KEY, raw, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("signature mismatch")
        payload = json.loads(raw)
    except Exception:
        return {"ok": False, "execute": False, "reason": "invalid execution capability"}
    if session_status != "monitoring":
        return {"ok": False, "execute": False, "reason": f"session is {session_status}; execution denied"}
    if not isinstance(agent_state, dict):
        return {"ok": False, "execute": False, "reason": "registered agent capability state unavailable"}
    if agent_state.get("quarantined"):
        return {"ok": False, "execute": False, "reason": "agent is quarantined; execution denied"}
    if agent_state.get("reground_required"):
        return {"ok": False, "execute": False, "reason": "agent must acknowledge trusted re-ground context"}
    try:
        signed_epoch = int(payload.get("capability_epoch"))
        current_epoch = int(agent_state.get("capability_epoch"))
    except (TypeError, ValueError):
        return {"ok": False, "execute": False, "reason": "execution capability has no valid epoch"}
    if signed_epoch != current_epoch:
        return {"ok": False, "execute": False, "reason": "stale capability epoch; re-evaluation required",
                "capability_epoch": signed_epoch, "current_epoch": current_epoch}
    if payload.get("jti") in _USED:
        return {"ok": False, "execute": False, "reason": "execution capability replay denied"}
    if int(payload.get("exp", 0)) < int(time.time()):
        return {"ok": False, "execute": False, "reason": "execution capability expired"}
    if payload.get("policy_version") != policy.version():
        return {"ok": False, "execute": False, "reason": "policy version changed; re-evaluation required"}
    exact = canonical_action(action)
    if exact != payload.get("action"):
        return {"ok": False, "execute": False, "reason": "tool/arguments/destination/resource changed; re-evaluation required"}

    mf = manifest.get(exact["session_id"])
    chain = list(redirect_chain or [])
    for dest in [exact["destination"], *chain]:
        if dest and not manifest.host_allowed(mf, dest):
            return {"ok": False, "execute": False, "reason": f"resolved/redirect destination '{dest}' is not allowlisted"}
    now_ips = resolve_ips(chain[-1] if chain else exact["destination"])
    prior_ips = payload.get("resolved_ips") or []
    if prior_ips and now_ips != prior_ips:
        return {"ok": False, "execute": False, "reason": "resolved IP set changed; re-evaluation required",
                "before": prior_ips, "now": now_ips}
    if exact["destination"] and not now_ips:
        return {"ok": False, "execute": False, "reason": "final destination could not be resolved"}

    _USED.add(payload["jti"])
    return {"ok": True, "execute": True, "committed_at": int(time.time()),
            "resolved_ips": now_ips,
            "note": "Exact action binding validated immediately before execution; this narrows but does not eliminate every race."}
