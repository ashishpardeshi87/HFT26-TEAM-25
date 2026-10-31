"""APEX final-flow engine: setup sessions (ownership proof), forensic footprint
extraction, editable wordlist, OSINT overweb, DarkGuard darkweb hand-off, analyst
console, and the landscape/gaps data.

Implements APEX_FINAL_FLOW.md (stages 1, 6, 7, 8, 9 and the console) and
APEX_EXISTING_SOLUTIONS_AND_GAPS.md.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from . import classification, darkguard, manifest, ownership, policy
from .store import store

# ---- durable local state (self-hosted, single-tenant per deployment) -------
_DEFAULT_STATE_PATH = Path(__file__).resolve().parents[1] / ".sentinel" / "state.json"
_STATE_PATH = Path(os.getenv("SENTINEL_STATE_PATH") or str(_DEFAULT_STATE_PATH)).expanduser().resolve()
_STATE_BACKUP_PATH = _STATE_PATH.with_name(_STATE_PATH.name + ".bak")
_LOG = logging.getLogger(__name__)
_LOCK = threading.RLock()
SESSIONS: dict[str, dict] = {}
WORDLISTS: dict[str, list[str]] = {}
INVESTIGATIONS: dict[str, dict] = {}
APPROVALS: dict[str, dict] = {}
PENDING_TOKENS: dict[str, dict] = {}   # challenge_id -> token hash + target + expiry (never plaintext)
_INVESTIGATION_TASKS: dict[str, asyncio.Task] = {}
_STATE_VERSION = 2


def _state_snapshot() -> dict:
    return {
        "schema_version": _STATE_VERSION,
        "sessions": SESSIONS,
        "wordlists": WORDLISTS,
        "investigations": INVESTIGATIONS,
        "approvals": APPROVALS,
        "pending_tokens": PENDING_TOKENS,
    }


def _validated_state(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("state root must be a JSON object")
    for key in ("sessions", "wordlists", "investigations", "approvals", "pending_tokens"):
        value = raw.get(key, {})
        if not isinstance(value, dict):
            raise ValueError(f"state field {key!r} must be an object")
    return raw


def _persist() -> None:
    """Atomically persist non-secret state and retain a last-known-good copy."""
    with _LOCK:
        if _STATE_PATH.exists() and _STATE_PATH.is_dir():
            raise RuntimeError(f"SENTINEL_STATE_PATH points to a directory: {_STATE_PATH}")
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATE_PATH.with_name(
            f".{_STATE_PATH.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as fh:
                json.dump(_state_snapshot(), fh, indent=2, ensure_ascii=False)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())

            if _STATE_PATH.exists():
                try:
                    _validated_state(json.loads(_STATE_PATH.read_text(encoding="utf-8")))
                    shutil.copy2(_STATE_PATH, _STATE_BACKUP_PATH)
                except Exception as exc:
                    _LOG.error("Existing Sentinel state is invalid; preserving backup: %s", exc)
            os.replace(tmp, _STATE_PATH)
            if not _STATE_BACKUP_PATH.exists():
                shutil.copy2(_STATE_PATH, _STATE_BACKUP_PATH)
        finally:
            tmp.unlink(missing_ok=True)


def _new_agent_state() -> dict:
    return {
        "capability_epoch": 1,
        "reground_required": False,
        "reground_context": None,
        "last_reground_ack": None,
        "quarantined": False,
        "quarantine": None,
        "history": [],
    }


def _migrate_agent_states(session: dict) -> None:
    raw_states = session.get("agent_state")
    states = raw_states if isinstance(raw_states, dict) else {}
    quarantined = session.get("quarantined_agents")
    quarantined = quarantined if isinstance(quarantined, dict) else {}
    migrated: dict[str, dict] = {}
    for agent in (session.get("manifest") or {}).get("agents", session.get("agents") or []):
        agent_id = str(agent.get("id") or "")
        if not agent_id:
            continue
        state = states.get(agent_id) if isinstance(states.get(agent_id), dict) else _new_agent_state()
        base = _new_agent_state()
        base.update(state)
        try:
            base["capability_epoch"] = max(1, int(base.get("capability_epoch", 1)))
        except (TypeError, ValueError):
            base["capability_epoch"] = 1
        if agent_id in quarantined:
            base["quarantined"] = True
            base["quarantine"] = copy.deepcopy(quarantined[agent_id])
        if not isinstance(base.get("history"), list):
            base["history"] = []
        migrated[agent_id] = base
    session["agent_state"] = migrated
    session["quarantined_agents"] = {
        agent_id: copy.deepcopy(state.get("quarantine") or {})
        for agent_id, state in migrated.items() if state.get("quarantined")
    }


def _apply_loaded_state(raw: dict) -> None:
    sessions = dict(raw.get("sessions") or {})
    wordlists = dict(raw.get("wordlists") or {})
    investigations = dict(raw.get("investigations") or {})
    approvals = dict(raw.get("approvals") or {})
    now = time.time()
    pending = {
        cid: value for cid, value in (raw.get("pending_tokens") or {}).items()
        if isinstance(value, dict)
        and value.get("token_hash")
        and value.get("target")
        and float(value.get("exp", 0)) > now
    }

    compiled_policies: dict[str, dict] = {}
    for sid, session in sessions.items():
        if not isinstance(session, dict) or session.get("session_id") != sid:
            raise ValueError(f"invalid persisted session {sid!r}")
        compiled = policy.compile_policy(session.get("custom_rules") or [], session.get("scenario", "production"))
        if not compiled["ok"]:
            raise ValueError(f"persisted policy for {sid} is invalid: {'; '.join(compiled['errors'])}")
        # These are backend capabilities, not operator-selectable setup options.
        session["auto_investigate"] = True
        session["auto_isolate"] = True
        _migrate_agent_states(session)
        compiled_policies[sid] = compiled

    SESSIONS.clear(); SESSIONS.update(sessions)
    WORDLISTS.clear(); WORDLISTS.update(wordlists)
    INVESTIGATIONS.clear(); INVESTIGATIONS.update(investigations)
    APPROVALS.clear(); APPROVALS.update(approvals)
    PENDING_TOKENS.clear(); PENDING_TOKENS.update(pending)
    for sid, session in sessions.items():
        if session.get("manifest") and session.get("status") == "monitoring":
            manifest.register(sid, session["manifest"])
        policy.register_session(sid, compiled_policies[sid])


def _load() -> None:
    if _STATE_PATH.exists() and _STATE_PATH.is_dir():
        raise RuntimeError(f"SENTINEL_STATE_PATH points to a directory: {_STATE_PATH}")

    failures: list[str] = []
    for candidate in (_STATE_PATH, _STATE_BACKUP_PATH):
        try:
            raw = _validated_state(json.loads(candidate.read_text(encoding="utf-8")))
            _apply_loaded_state(raw)
            if candidate == _STATE_BACKUP_PATH:
                _LOG.warning("Recovered Sentinel state from backup %s", candidate)
                _persist()
            return
        except FileNotFoundError:
            continue
        except Exception as exc:
            failures.append(f"{candidate}: {exc}")
            _LOG.error("Could not load Sentinel state from %s: %s", candidate, exc)

    if failures:
        raise RuntimeError("Sentinel state could not be loaded; refusing to start empty. " + " | ".join(failures))


_load()


# ---- Stage 1: setup + real ownership proof --------------------------------

def issue_token(target: str) -> dict:
    """Issue a single-use token. Only its SHA-256 digest is retained server-side."""
    normalized = ownership.normalize_target(target)
    now = time.time()
    # Expire old challenges opportunistically.
    for cid in list(PENDING_TOKENS):
        if PENDING_TOKENS[cid]["exp"] <= now:
            PENDING_TOKENS.pop(cid, None)
    cid = "chal_" + secrets.token_urlsafe(9)
    token = "sentinel-" + secrets.token_urlsafe(24)
    PENDING_TOKENS[cid] = {
        "token_hash": ownership.digest(token),
        "target": normalized["origin"],
        "host": normalized["host"],
        "exp": now + 600,
    }
    # Persist only the digest, target and expiry so an in-flight ownership proof
    # survives a backend restart without storing the one-time plaintext token.
    _persist()
    return {
        "challenge_id": cid,
        "token": token,  # shown once; never persisted
        "target": normalized["origin"],
        "locations": ownership.challenge_locations(normalized),
        "expires_in_s": 600,
        "stored_server_side": "sha256 digest only",
    }


async def register_session(body: dict) -> dict:
    """Verify ownership, compile policy + manifest, issue an enrollment token,
    and transition the session to monitoring. Supplied credentials are consumed
    inside this call and never copied into SESSIONS or logs."""
    try:
        target = ownership.normalize_target(body.get("target", ""))
    except ownership.VerificationError as exc:
        return {"ok": False, "error": str(exc)}

    scenario = str(body.get("scenario") or "production").lower()
    if scenario not in ("testing", "production"):
        return {"ok": False, "error": "Scenario must be testing or production."}
    if not body.get("agents"):
        return {"ok": False, "error": "Register at least one agent identity/process."}

    cid = str(body.get("challenge_id") or "")
    challenge = PENDING_TOKENS.get(cid)
    if not challenge or challenge["exp"] <= time.time() or challenge["target"] != target["origin"]:
        return {"ok": False, "error": "Ownership challenge is missing, expired, or belongs to another target."}

    try:
        attestation = await ownership.verify(challenge, body.get("proof") or {})
    except ownership.VerificationError as exc:
        return {"ok": False, "error": "Ownership proof failed.", "detail": str(exc)}

    compiled = policy.compile_policy(body.get("custom_rules") or [], scenario)
    if not compiled["ok"]:
        return {"ok": False, "error": "Security policy rejected.", "detail": "; ".join(compiled["errors"]),
                "policy_errors": compiled["errors"]}

    sid = "sess_" + secrets.token_urlsafe(10)
    gateway_token = "sgw_" + secrets.token_urlsafe(32)
    mf = manifest.compile_manifest(body, target["host"])
    manifest.register(sid, mf)
    policy.register_session(sid, compiled)

    session = {
        "session_id": sid,
        "target": target["origin"],
        "target_host": target["host"],
        "agents": mf["agents"],
        "scenario": scenario,
        "objective": mf["task"],
        "manifest": mf,
        "custom_rules": body.get("custom_rules") or [],
        "policy": {
            "version": compiled["policy_version"],
            "total": compiled["summary"]["total"],
            "enabled": compiled["summary"]["enabled"],
            "floor": compiled["summary"]["floor"],
            "custom_applied": compiled["applied"],
            "invariant": compiled["invariant"],
        },
        "proof": attestation,
        "gateway_token_hash": hashlib.sha256(gateway_token.encode()).hexdigest(),
        # Seven days supports multi-day monitoring while keeping this bearer
        # credential bounded. Operators can choose a shorter TTL through env.
        "gateway_token_expires_at": time.time() + max(900, min(604800, int(os.getenv("SENTINEL_GATEWAY_TOKEN_TTL") or "604800"))),
        "opened": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_heartbeat": None,
        "coverage_mode": "gateway",
        "status": "monitoring",
        "agent_state": {agent["id"]: _new_agent_state() for agent in mf["agents"]},
        "quarantined_agents": {},
        "denial_counts": {},
        # Automatic investigation and isolation are backend capabilities. They
        # are intentionally not operator-disableable from the Setup client.
        "auto_investigate": True,
        "auto_isolate": True,
    }
    SESSIONS[sid] = session
    PENDING_TOKENS.pop(cid, None)  # challenge is consumed only after success
    _persist()

    public = public_session(session)
    return {
        "ok": True,
        "session": public,
        "gateway_token": gateway_token,  # returned exactly once; store in the local sensor secret store
        "enrollment": {
            "event_endpoint": "/api/events",
            "gateway_endpoint": "/api/gateway/action",
            "header": "X-Sentinel-Token",
            "session_id": sid,
        },
        "credentials_stored": False,
    }


def public_session(session: dict) -> dict:
    public = copy.deepcopy({k: v for k, v in session.items() if k != "gateway_token_hash"})
    for state in public.get("agent_state", {}).values():
        context = state.get("reground_context")
        if isinstance(context, dict):
            context.pop("nonce", None)
    return public


def list_sessions() -> list[dict]:
    return [public_session(s) for s in SESSIONS.values()]


def get_session(session_id: str) -> dict | None:
    s = SESSIONS.get(session_id)
    return public_session(s) if s else None


def token_valid(session_id: str, token: str) -> bool:
    sess = SESSIONS.get(session_id)
    if not sess or not token:
        return False
    return secrets.compare_digest(sess.get("gateway_token_hash", ""), hashlib.sha256(token.encode()).hexdigest())


def require_monitoring(session_id: str) -> dict:
    sess = SESSIONS.get(session_id)
    if not sess:
        raise ValueError("Unknown monitoring session. Complete Setup first.")
    if sess.get("status") != "monitoring":
        raise ValueError(f"Session is {sess.get('status', 'inactive')}; monitoring actions are denied.")
    if float(sess.get("gateway_token_expires_at", 0)) <= time.time():
        sess["status"] = "credential_expired"
        _persist()
        raise ValueError("Session Gateway token expired; re-enroll the sensor from Setup.")
    return sess


def update_target_health(session_id: str, report: dict) -> None:
    sess = SESSIONS.get(session_id)
    if not sess or sess.get("status") != "monitoring":
        return
    sess["target_health"] = report
    _persist()


def touch_heartbeat(session_id: str) -> None:
    if session_id in SESSIONS:
        SESSIONS[session_id]["last_heartbeat"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def get_agent_state(session_id: str, agent_id: str) -> dict | None:
    sess = SESSIONS.get(session_id)
    state = (sess or {}).get("agent_state", {}).get(agent_id)
    return copy.deepcopy(state) if isinstance(state, dict) else None


def require_reground(session_id: str, agent_id: str, reason: str,
                     rule_ids: list[str], event_id: str) -> dict:
    """Durably revoke the current epoch and issue server-authored context."""
    with _LOCK:
        sess = SESSIONS.get(session_id)
        state = (sess or {}).get("agent_state", {}).get(agent_id)
        if not sess or not isinstance(state, dict):
            return {"ok": False, "error": "session or registered agent not found"}
        existing_context = state.get("reground_context")
        if isinstance(existing_context, dict) and existing_context.get("reason_event_id") == event_id:
            # Replaying orchestration for an already handled evidence event must
            # not revoke a fresh epoch or undo a durable acknowledgment.
            return {"ok": True, "agent_id": agent_id,
                    "capability_epoch": state["capability_epoch"],
                    "context": copy.deepcopy(existing_context), "reused": True,
                    "acknowledged": bool(existing_context.get("acknowledged_at"))}
        if state.get("reground_required") and isinstance(existing_context, dict):
            return {"ok": True, "agent_id": agent_id,
                    "capability_epoch": state["capability_epoch"],
                    "context": copy.deepcopy(existing_context), "reused": True}

        state["capability_epoch"] = int(state.get("capability_epoch", 1)) + 1
        mf = sess.get("manifest") or {}
        context = {
            "type": "trusted_security_context",
            "session_id": session_id,
            "agent_id": agent_id,
            "version": state["capability_epoch"],
            "nonce": secrets.token_urlsafe(18),
            "capability_epoch": state["capability_epoch"],
            "objective": sess.get("objective") or mf.get("task", ""),
            "manifest_restrictions": {
                "allowed_tools": copy.deepcopy(mf.get("allowed_tools", [])),
                "allowed_files": copy.deepcopy(mf.get("allowed_files", [])),
                "allowed_hosts": copy.deepcopy(mf.get("allowed_hosts", [])),
                "allowed_scopes": copy.deepcopy(mf.get("allowed_scopes", {})),
            },
            "reason": reason,
            "rule_ids": list(dict.fromkeys(str(r) for r in rule_ids if str(r))),
            "reason_event_id": event_id,
            "policy_version": (sess.get("policy") or {}).get("version") or policy.version(),
            "issued_at": _utc(),
            "acknowledged_at": None,
            "instruction": (
                "Return to the declared objective and manifest. Do not retry the denied action, "
                "reuse untrusted memory to bypass policy, add tools, or change destinations."
            ),
        }
        state["reground_required"] = True
        state["reground_context"] = context
        state.setdefault("history", []).append({
            "type": "reground_required", "at": context["issued_at"],
            "event_id": event_id, "context_version": context["version"],
            "capability_epoch": state["capability_epoch"], "rule_ids": context["rule_ids"],
        })
        _persist()
        return {"ok": True, "agent_id": agent_id,
                "capability_epoch": state["capability_epoch"],
                "context": copy.deepcopy(context), "reused": False}


def acknowledge_reground(session_id: str, agent_id: str, context_version: object) -> dict:
    with _LOCK:
        sess = SESSIONS.get(session_id)
        state = (sess or {}).get("agent_state", {}).get(agent_id)
        if not sess or not isinstance(state, dict):
            return {"ok": False, "error": "session or registered agent not found"}
        context = state.get("reground_context")
        if not state.get("reground_required") or not isinstance(context, dict):
            return {"ok": False, "error": "re-ground acknowledgment is not required"}
        if str(context.get("version")) != str(context_version):
            return {"ok": False, "error": "stale or invalid re-ground context version"}
        acknowledged_at = _utc()
        state["reground_required"] = False
        context["acknowledged_at"] = acknowledged_at
        state["last_reground_ack"] = {
            "context_version": context["version"], "acknowledged_at": acknowledged_at,
            "capability_epoch": state["capability_epoch"],
        }
        state.setdefault("history", []).append({
            "type": "reground_acknowledged", "at": acknowledged_at,
            "context_version": context["version"],
            "capability_epoch": state["capability_epoch"],
        })
        _persist()
        return {
            "ok": True, "agent_id": agent_id,
            "acknowledged_context_version": context["version"],
            "acknowledged_at": acknowledged_at,
            "reground_required": False,
            "quarantined": bool(state.get("quarantined")),
            "capability_epoch": state["capability_epoch"],
        }


def quarantine(session_id: str, agent_id: str, reason: str, event_id: str = "") -> dict:
    with _LOCK:
        sess = SESSIONS.get(session_id)
        state = (sess or {}).get("agent_state", {}).get(agent_id)
        if not sess or not isinstance(state, dict):
            return {"ok": False, "error": "session or registered agent not found"}
        if not state.get("quarantined"):
            state["capability_epoch"] = int(state.get("capability_epoch", 1)) + 1
            at = _utc()
            state["quarantined"] = True
            state["quarantine"] = {"reason": reason, "event_id": event_id, "at": at}
            state.setdefault("history", []).append({
                "type": "quarantined", "at": at, "event_id": event_id,
                "reason": reason, "capability_epoch": state["capability_epoch"],
            })
        sess.setdefault("quarantined_agents", {})[agent_id] = copy.deepcopy(state["quarantine"])
        _persist()
        return {
            "ok": True, "agent_id": agent_id, "quarantined": True,
            "effect": "gateway tool and egress access revoked", "reason": state["quarantine"]["reason"],
            "capability_epoch": state["capability_epoch"],
        }


def record_denial(session_id: str, agent_id: str, action_key: str, event_id: str,
                  external_intervention: bool, sensitive_egress: bool,
                  direct_linkage: bool = False) -> dict:
    """Track retries separately from stateless authorization. Prior approval is
    never cached; retry state exists only to detect AG-35/AG-44 evasion."""
    sess = SESSIONS.get(session_id)
    if not sess:
        return {"count": 0, "quarantined": False}
    counts = sess.setdefault("denial_counts", {})
    key = hashlib.sha256(f"{agent_id}|{action_key}".encode()).hexdigest()[:16]
    counts[key] = int(counts.get(key, 0)) + 1
    scenario = sess.get("scenario", "production")
    if scenario == "testing":
        trigger = counts[key] >= 2 or (external_intervention and sensitive_egress)
    else:
        # Production D3: critical policy denial + direct linkage + active harm.
        # A repeated retry is an AG-35/AG-44 monitoring-bypass attempt and also isolates.
        trigger = counts[key] >= 2 or (external_intervention and sensitive_egress and direct_linkage)
    should_isolate = bool(sess.get("auto_isolate")) and trigger
    result = {"count": counts[key], "quarantined": False}
    if should_isolate:
        q = quarantine(session_id, agent_id,
                       "repeated Guardian denial" if counts[key] >= 2 else "external intervention with active sensitive egress",
                       event_id)
        result.update(quarantined=q.get("ok", False), isolation=q)
    _persist()
    return result


def release_agent(session_id: str, agent_id: str) -> dict:
    with _LOCK:
        sess = SESSIONS.get(session_id)
        state = (sess or {}).get("agent_state", {}).get(agent_id)
        if not sess or not isinstance(state, dict):
            return {"ok": False, "error": "session or registered agent not found"}
        existed = bool(state.get("quarantined"))
        state["quarantined"] = False
        state["quarantine"] = None
        sess.setdefault("quarantined_agents", {}).pop(agent_id, None)
        if existed:
            state.setdefault("history", []).append({
                "type": "quarantine_released", "at": _utc(),
                "capability_epoch": state["capability_epoch"],
            })
        _persist()
        return {"ok": True, "agent_id": agent_id, "released": existed,
                "reground_required": bool(state.get("reground_required")),
                "capability_epoch": state["capability_epoch"]}


def action_binding(session_id: str, agent_id: str, tool: str, args: str, scope: str, destination: str,
                   resource_hash: str = "", capability_epoch: int | None = None) -> str:
    value = {"session": session_id, "agent": agent_id, "tool": tool,
             "args": args, "scope": scope, "destination": destination,
             "resource_hash": resource_hash}
    if capability_epoch is not None:
        value["capability_epoch"] = int(capability_epoch)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def request_approval(session_id: str, event_id: str, agent_id: str, binding: str,
                     summary: str, rule_ids: list[str]) -> dict:
    aid = "apr_" + secrets.token_urlsafe(9)
    rec = {"id": aid, "session_id": session_id, "event_id": event_id, "agent_id": agent_id,
           "binding": binding, "summary": summary, "rule_ids": rule_ids,
           "status": "pending", "created_at": _utc(), "expires_at": time.time() + 600,
           "approval_token_hash": None}
    APPROVALS[aid] = rec; _persist()
    return {k: v for k, v in rec.items() if k not in ("binding", "approval_token_hash")}


def decide_approval(session_id: str, approval_id: str, approve: bool) -> dict:
    rec = APPROVALS.get(approval_id)
    if not rec or rec.get("session_id") != session_id:
        return {"ok": False, "error": "approval not found"}
    if rec["status"] != "pending" or rec["expires_at"] <= time.time():
        return {"ok": False, "error": "approval is expired or already decided"}
    rec["status"] = "approved" if approve else "rejected"
    rec["decided_at"] = _utc()
    token = None
    if approve:
        token = "aex_" + secrets.token_urlsafe(24)
        rec["approval_token_hash"] = hashlib.sha256(token.encode()).hexdigest()
    _persist()
    return {"ok": True, "approval": {k: v for k, v in rec.items() if k not in ("binding", "approval_token_hash")},
            "execution_token": token}


def consume_approval(session_id: str, approval_id: str, token: str, binding: str) -> bool:
    rec = APPROVALS.get(approval_id)
    if not rec or rec.get("session_id") != session_id or rec.get("status") != "approved":
        return False
    if rec.get("expires_at", 0) <= time.time() or not secrets.compare_digest(rec.get("binding", ""), binding):
        return False
    if not token or not secrets.compare_digest(rec.get("approval_token_hash") or "", hashlib.sha256(token.encode()).hexdigest()):
        return False
    rec["status"] = "consumed"; rec["consumed_at"] = _utc(); rec["approval_token_hash"] = None
    _persist(); return True


def list_approvals(session_id: str) -> list[dict]:
    return [{k: v for k, v in r.items() if k not in ("binding", "approval_token_hash")}
            for r in APPROVALS.values() if r.get("session_id") == session_id]


def end_session(session_id: str, reason: str = "operator_requested") -> dict:
    """Idempotently revoke future execution and make the session terminal."""
    with _LOCK:
        sess = SESSIONS.get(session_id)
        if not sess:
            return {"ok": False, "error": "session not found"}
        if sess.get("status") == "ended":
            return {"ok": True, "session": public_session(sess), "already_ended": True}
        if sess.get("status") != "monitoring":
            return {"ok": False, "error": f"session is {sess.get('status', 'inactive')}"}

        ended_at = _utc()
        for agent_id, state in sess.get("agent_state", {}).items():
            state["capability_epoch"] = int(state.get("capability_epoch", 1)) + 1
            state.setdefault("history", []).append({
                "type": "session_ended", "at": ended_at,
                "capability_epoch": state["capability_epoch"],
            })
        for approval in APPROVALS.values():
            if approval.get("session_id") == session_id and approval.get("status") in ("pending", "approved"):
                approval["status"] = "cancelled"
                approval["cancelled_at"] = ended_at
                approval["approval_token_hash"] = None
        incident_ids = {incident.incident_id for incident in store.session_incidents(session_id)}
        for job_id, job in INVESTIGATIONS.items():
            if job.get("session_id") == session_id or job.get("incident_id") in incident_ids:
                if job.get("status") in ("queued", "running"):
                    job["status"] = "cancelled"
                    job["error"] = "session ended"
                    job["completed_at"] = ended_at
                    task = _INVESTIGATION_TASKS.get(job_id)
                    if task and not task.done():
                        task.cancel()
        sess["status"] = "ended"
        sess["ended_at"] = ended_at
        sess["end_reason"] = reason
        manifest.unregister(session_id)
        _persist()
        return {"ok": True, "session": public_session(sess), "already_ended": False}


def stop_session(session_id: str) -> dict:
    """Compatibility alias for the terminal end transition."""
    return end_session(session_id, reason="stop_compatibility_route")


def record_final_report(session_id: str, snapshot: dict) -> None:
    with _LOCK:
        sess = SESSIONS.get(session_id)
        if not sess:
            return
        sess["final_report"] = {
            "stored": bool(snapshot.get("stored")),
            "report_hash": snapshot.get("report_hash"),
            "generated_at": _utc(),
        }
        _persist()


# ---- Stage 6/7: forensic footprint -> wordlist ----------------------------
# A small, analyst-reviewable set is more useful than a noisy keyword dump and
# matches the maximum indicator batch sent to DarkGuard.
MAX_WORDLIST_TERMS = 6

_RX = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.I),
    "url": re.compile(r"https?://[^\s<>'\"]+", re.I),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "eth_wallet": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "btc_wallet": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "handle": re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,}\b"),
}

# Plain, demonstration-friendly keywords surfaced in Tor Finder (no emails,
# domains, URLs or handles). Only theme words actually present in the incident
# evidence are shown, and these plain words are what return live onion results.
_THEME_KEYWORDS = [
    "education", "student", "students", "data", "records", "record",
    "database", "admissions", "grades", "exam", "exams", "enrollment",
    "university", "campus", "academic", "transcript", "scholarship",
    "leaked", "breach",
]


def _plain_keywords(blob: str) -> list[str]:
    low = (blob or "").lower()
    out: list[str] = []
    for w in _THEME_KEYWORDS:
        if re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", low) and w not in out:
            out.append(w)
        if len(out) >= 6:
            break
    return out


def _incident_events(inc: dict) -> list:
    return store.events_by_ids_durable(
        inc.get("event_ids", []), str((inc.get("signals") or {}).get("session_id") or "")
    )


def footprint(incident_id: str) -> dict:
    inc = store.get_incident(incident_id)
    if not inc:
        return {"ok": False, "error": "incident not found"}
    inc_d = inc.model_dump()
    evs = _incident_events(inc_d)

    params: dict[str, list[str]] = {k: [] for k in _RX}
    params["destination"] = []
    params["source_ip"] = []
    params["connection_channel"] = []
    params["user_agent"] = []
    params["tooling_signature"] = []
    params["payload_hash"] = []
    vectors: list[str] = []
    injection_evidence: list[dict] = []
    all_text_parts: list[str] = []

    for e in evs:
        if e.destination and e.destination.host:
            if e.destination.host not in params["destination"]:
                params["destination"].append(e.destination.host)
        for key, meta_key in (("source_ip", "source_ip"), ("connection_channel", "channel"), ("user_agent", "user_agent")):
            value = str(e.meta.get(meta_key) or "").strip()
            if value and value not in params[key]:
                params[key].append(value)
        sig = " ".join(x for x in (e.process.name, e.process.parent, e.process.cmdline) if x).strip()
        if sig and sig not in params["tooling_signature"]:
            params["tooling_signature"].append(sig[:240])
        if e.payload_excerpt:
            ph = hashlib.sha256(e.payload_excerpt.encode()).hexdigest()
            if ph not in params["payload_hash"]:
                params["payload_hash"].append(ph)
        # Scan every field an indicator might hide in: payload, tool args, behaviour detail.
        texts = [e.payload_excerpt or "", e.tool or "", e.tool_args or ""]
        for b in e.behavior:
            texts.append(b.detail or "")
            texts.append(b.target or "")
            if b.type == "injection_suspected":
                vectors.append("prompt-injection in untrusted content")
                injection_evidence.append({
                    "event_id": e.id,
                    "delivery_vector": e.event_type,
                    "source": e.source,
                    "content_hash": hashlib.sha256((e.payload_excerpt or "").encode()).hexdigest(),
                    "prompt_excerpt": (e.payload_excerpt or "")[:240],
                    "trust_level": e.trust_level,
                })
            if b.type == "memory_write_suspected":
                vectors.append("memory poisoning")
            if b.type == "untrusted_agent_message":
                vectors.append("multi-agent message")
        blob = " ".join(texts)
        all_text_parts.append(blob)
        for key, rx in _RX.items():
            for m in rx.findall(blob):
                v = m if isinstance(m, str) else m[0]
                if v and v not in params[key]:
                    params[key].append(v)

    keywords = _plain_keywords(" ".join(all_text_parts))

    # Build at most six high-value, non-sensitive identifiers in priority order.
    wl: list[str] = []
    for key in ("domain", "url", "email", "ip", "source_ip", "eth_wallet", "btc_wallet", "handle", "destination"):
        for v in params[key]:
            if v not in wl:
                wl.append(v)
                if len(wl) >= MAX_WORDLIST_TERMS:
                    break
        if len(wl) >= MAX_WORDLIST_TERMS:
            break
    WORDLISTS[incident_id] = wl
    _persist()

    return {
        "ok": True, "incident_id": incident_id,
        "title": inc_d.get("title"), "cause": inc_d.get("cause"),
        "parameters": {k: v for k, v in params.items() if v},
        "vectors": sorted(set(vectors)),
        "injection_evidence": injection_evidence,
        "wordlist": wl,
        "keywords": keywords,
        "evidence_event_ids": [e.id for e in evs],
    }


def edit_wordlist(incident_id: str, add: list[str], remove: list[str]) -> dict:
    if not store.get_incident(incident_id):
        return {"ok": False, "error": "incident not found", "wordlist": [], "limit": MAX_WORDLIST_TERMS}
    wl = list(WORDLISTS.get(incident_id, []))[:MAX_WORDLIST_TERMS]
    for value in remove or []:
        value = str(value).strip()
        if value in wl:
            wl.remove(value)
    rejected: list[str] = []
    for value in add or []:
        value = str(value).strip()
        if not value or len(value) > 200 or value in wl:
            continue
        if len(wl) >= MAX_WORDLIST_TERMS:
            rejected.append(value)
            continue
        wl.append(value)
    WORDLISTS[incident_id] = wl
    _persist()
    return {
        "ok": not rejected,
        "error": (f"Wordlist is limited to {MAX_WORDLIST_TERMS} terms; remove one before adding another."
                  if rejected else None),
        "wordlist": wl,
        "limit": MAX_WORDLIST_TERMS,
        "rejected": rejected,
    }


# ---- Stage 8a: passive, evidence-producing overweb OSINT ------------------

def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _finding(tool: str, detail: str, source_url: str, evidence_type: str = "direct observation",
             confidence: str = "high") -> dict:
    return {
        "tool": tool,
        "detail": detail,
        "source_url": source_url,
        "retrieved_at": _utc(),
        "evidence_type": evidence_type,
        "confidence": confidence,
        "verification_status": "unverified",
    }


def _kind(value: str) -> tuple[str, str]:
    v = (value or "").strip()
    if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", v):
        return "email", v.lower()
    try:
        ipaddress.ip_address(v)
        return "ip", v
    except Exception:
        pass
    raw = v
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", raw, re.I):
        return "domain", raw.lower().rstrip(".")
    if v.startswith("@") and re.fullmatch(r"@[A-Za-z0-9_-]{1,39}", v):
        return "handle", v[1:]
    return "keyword", v


async def _json_get(client: httpx.AsyncClient, url: str, **kwargs):
    r = await client.get(url, **kwargs)
    r.raise_for_status()
    return r.json()


async def _lookup_one(client: httpx.AsyncClient, keyword: str) -> dict:
    kind, value = _kind(keyword)
    hit = {"keyword": keyword, "kind": kind, "findings": [], "errors": []}

    if kind == "domain":
        # RDAP is the standards-based successor to free-form WHOIS.
        rdap_url = f"https://rdap.org/domain/{quote(value, safe='')}"
        try:
            d = await _json_get(client, rdap_url)
            registrar = next((e.get("vcardArray", [None, []])[1][1][3]
                              for e in d.get("entities", [])
                              if "registrar" in e.get("roles", []) and len(e.get("vcardArray", [None, []])[1]) > 1), None)
            events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
            nameservers = [n.get("ldhName") for n in d.get("nameservers", []) if n.get("ldhName")]
            detail = f"RDAP domain record"
            if registrar:
                detail += f" · registrar {registrar}"
            if events.get("registration"):
                detail += f" · registered {events['registration']}"
            if nameservers:
                detail += f" · nameservers {', '.join(nameservers[:4])}"
            hit["findings"].append(_finding("RDAP/WHOIS", detail, rdap_url, "source report"))
        except Exception:
            hit["errors"].append("RDAP domain lookup unavailable")

        crt_url = "https://crt.sh/"
        try:
            rows = await _json_get(client, crt_url, params={"q": value, "output": "json"})
            names = sorted({n.strip().lower().lstrip("*.")
                            for row in rows[:5000]
                            for n in str(row.get("name_value") or "").split("\n")
                            if n.strip()})
            hit["findings"].append(_finding(
                "crt.sh", f"{len(rows)} certificate row(s) · {len(names)} unique DNS name(s)" +
                (f" · sample {', '.join(names[:5])}" if names else ""),
                f"https://crt.sh/?q={quote(value)}", "direct observation"))
        except Exception:
            hit["errors"].append("Certificate-transparency lookup unavailable")

        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, value, None)
            ips = sorted({x[4][0] for x in infos})
            if ips:
                hit["findings"].append(_finding("DNS", f"Resolved address(es): {', '.join(ips)}",
                                                        f"dns://{value}", "direct observation"))
        except Exception:
            hit["errors"].append("DNS resolution failed")

    elif kind == "ip":
        url = f"https://rdap.org/ip/{quote(value, safe=':')}"
        try:
            d = await _json_get(client, url)
            detail = f"{d.get('name') or 'IP allocation'} · {d.get('country') or 'country unavailable'}"
            if d.get("startAddress") and d.get("endAddress"):
                detail += f" · range {d['startAddress']}–{d['endAddress']}"
            hit["findings"].append(_finding("RDAP", detail, url, "source report"))
        except Exception:
            hit["errors"].append("RDAP IP lookup unavailable")

    elif kind == "email":
        url = f"https://api.xposedornot.com/v1/check-email/{quote(value, safe='@')}"
        try:
            d = await _json_get(client, url)
            breaches = (d.get("breaches") or [[]])[0] or []
            detail = (f"Address appears in {len(breaches)} public breach record(s)"
                      + (f" · {', '.join(breaches[:8])}" if breaches else ""))
            hit["findings"].append(_finding("XposedOrNot", detail, url, "source report",
                                                    "high" if breaches else "medium"))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                hit["findings"].append(_finding("XposedOrNot", "No public breach record returned for this address",
                                                        url, "source report", "medium"))
            else:
                hit["errors"].append("Email breach lookup unavailable")
        except Exception:
            hit["errors"].append("Email breach lookup unavailable")

    elif kind == "handle":
        url = f"https://api.github.com/users/{quote(value, safe='')}"
        try:
            d = await _json_get(client, url)
            detail = f"Exact GitHub handle exists · account created {d.get('created_at') or 'unknown'} · public repos {d.get('public_repos', 0)}"
            hit["findings"].append(_finding("GitHub public API", detail, d.get("html_url") or url,
                                                    "identifier match", "low"))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                hit["errors"].append("GitHub handle lookup unavailable")
        except Exception:
            hit["errors"].append("GitHub handle lookup unavailable")
    else:
        hit["errors"].append("No configured passive overweb connector supports this free-form keyword")

    return hit


async def osint(keywords: list[str]) -> dict:
    """Run only passive, real lookups. OWASP ZAP active scanning is deliberately
    not launched against attacker-linked infrastructure without separate written
    authorization. If configured, the response reports its availability instead
    of inventing findings."""
    clean = list(dict.fromkeys(str(k).strip() for k in keywords if str(k).strip()))[:12]
    if not clean:
        return {"ok": False, "error": "at least one keyword required", "results": []}
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"User-Agent": "SENTINEL-APEX-IR/1.0"}) as client:
        results = await asyncio.gather(*(_lookup_one(client, kw) for kw in clean))
    return {
        "ok": True,
        "source": "overweb passive OSINT",
        "live": True,
        "results": results,
        "connectors": {
            "rdap_whois": "live", "certificate_transparency": "live",
            "dns": "live", "xposedornot": "live", "github_exact_handle": "live",
            "owasp_zap": ("configured; active scan still requires per-target authorization"
                           if os.getenv("ZAP_API_URL") else "unconfigured — no result fabricated"),
        },
        "scope_note": "Evidence types, confidence, and verification status are separate. Identifier matches never confirm a person.",
    }


# ---- Stage 8b: real DarkGuard hand-off (no fallback intelligence) ---------

async def darkweb(keywords: list[str]) -> dict:
    result = await darkguard.lookup(keywords)
    if not result:
        return {"ok": False, "status": "unavailable", "source": "DarkGuard",
                "error": "DarkGuard is disabled or no indicators were supplied.",
                "results": [], "personas": [], "live": False}
    # Persona rows are returned only when DarkGuard itself supplied evidence.
    return {
        "ok": result.get("status") == "completed",
        "status": result.get("status", "unavailable"),
        "source": "DarkGuard",
        "exposure_score": result.get("exposure_score"),
        "sources": result.get("sources", []),
        "results": result.get("results", []),
        "personas": result.get("personas", []),
        "provenance": result.get("provenance", {}),
        "error": result.get("error"),
        "live": bool(result.get("live")),
    }


# ---- Stage 6-9 autonomous investigation orchestration --------------------

def _classification_payload(incident) -> dict:
    payload = incident.signals.get("classification") or {}
    return payload if isinstance(payload, dict) else {}


def external_investigation_eligibility(incident_id: str, *, require_active: bool = True) -> dict:
    incident = store.get_incident(incident_id)
    if not incident:
        return {"eligible": False, "classification": "unresolved", "reason": "incident_not_found"}
    value = classification.value(incident)
    basis = _classification_payload(incident)
    eligible = classification.is_external_sufficient(incident)
    sid = incident.signals.get("session_id") or ""
    if eligible and require_active:
        session = SESSIONS.get(sid)
        if not session or session.get("status") != "monitoring":
            eligible = False
            reason = "session_not_active"
        else:
            reason = "external_parent_id_lineage_sufficient"
    else:
        reason = "external_parent_id_lineage_sufficient" if eligible else "external_classification_required"
    return {
        "eligible": eligible,
        "incident_id": incident_id,
        "session_id": sid,
        "classification": value,
        "classification_basis": basis,
        "reason": reason,
    }


def _link_key(value: str) -> str:
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{host}{port}{parsed.path or ''}" + (f"?{parsed.query}" if parsed.query else "")
    except (ValueError, TypeError):
        return str(value or "").strip()


def _working_links(dark: dict, hunt: dict) -> list[dict]:
    """Normalize only URLs returned by successful live DarkGuard collection."""
    links: dict[str, dict] = {}

    def add(row: dict) -> None:
        url = str(row.get("url") or "").strip()
        if not url:
            return
        key = _link_key(url)
        if not key:
            return
        candidate = {
            "url": url,
            "market": row.get("market"),
            "source": row.get("source") or "DarkGuard",
            "status": row.get("status"),
            "reachability": row.get("reachability"),
            "severity": row.get("severity"),
            "category": row.get("category"),
            "confidence": row.get("confidence"),
            "snippet": row.get("snippet"),
            "matched": row.get("matched") or [],
            "prices": row.get("prices") or [],
        }
        existing = links.get(key)
        if existing:
            for field, value in candidate.items():
                if not existing.get(field) and value:
                    existing[field] = value
            if candidate.get("reachability") == "reachable":
                existing["reachability"] = "reachable"
                existing["status"] = candidate.get("status") or existing.get("status")
            source = candidate.get("source")
            if source and source not in str(existing.get("source") or ""):
                existing["source"] = f"{existing.get('source')}, {source}".strip(", ")
            return
        links[key] = candidate

    if dark.get("live"):
        for finding in dark.get("results") or []:
            if isinstance(finding, dict) and finding.get("url"):
                add({
                    **finding,
                    "source": finding.get("source") or "DarkGuard scan",
                    "status": finding.get("status") or "returned_live",
                    "reachability": finding.get("reachability"),
                    "market": finding.get("market"),
                })
    if hunt.get("live"):
        for hit in hunt.get("hits") or []:
            if isinstance(hit, dict) and hit.get("url"):
                add({
                    **hit,
                    "source": hit.get("engine") or "DarkGuard hunt",
                    "status": "reachable",
                    "reachability": "reachable",
                })
    return list(links.values())


async def _run_investigation(job_id: str) -> None:
    job = INVESTIGATIONS.get(job_id)
    if not job:
        return
    eligibility = external_investigation_eligibility(job["incident_id"])
    if not eligibility["eligible"]:
        job["status"] = "failed"
        job["error"] = f"investigation denied: {eligibility['reason']}"
        job["completed_at"] = _utc()
        _persist()
        return
    job["status"] = "running"; job["started_at"] = _utc(); _persist()
    try:
        fp = footprint(job["incident_id"])
        if not fp.get("ok"):
            raise ValueError(fp.get("error", "footprint extraction failed"))
        words = fp.get("wordlist") or []
        job["footprint"] = fp
        job["wordlist"] = words
        job["keywords"] = fp.get("keywords") or []
        defaults = [
            {"ok": True, "results": [], "live": True},
            {"ok": False, "status": "no_indicators", "results": [], "live": False},
            {"status": "no_indicators", "live": False, "job_ids": [], "events": [], "hits": [], "errors": []},
        ]
        if words:
            raw_results = await asyncio.gather(
                osint(words), darkweb(words), darkguard.hunt(words), return_exceptions=True
            )
            resolved = [
                ({**default, "ok": False, "status": "failed", "error": str(value)}
                 if isinstance(value, Exception) else value)
                for value, default in zip(raw_results, defaults)
            ]
        else:
            resolved = defaults
        over, dark, hunt = resolved
        working_links = _working_links(dark, hunt)
        job["overweb"] = over
        job["darkweb"] = dark
        job["darkguard_hunt"] = hunt
        job["hunt_job_ids"] = hunt.get("job_ids") or []
        job["hunt_events"] = hunt.get("events") or []
        job["hunt_errors"] = hunt.get("errors") or []
        job["working_links"] = working_links
        job["status"] = "completed"
        job["completed_at"] = _utc()
        incident = store.get_incident(job["incident_id"])
        if incident:
            incident.darkguard = {
                "scan": dark, "hunt": hunt, "working_links": working_links,
                "updated_at": job["completed_at"],
            }
            store.upsert_incident(incident)
    except asyncio.CancelledError:
        if job.get("status") not in ("cancelled", "completed"):
            job["status"] = "cancelled"
            job["error"] = "investigation task cancelled"
            job["completed_at"] = _utc()
            _persist()
        raise
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = str(exc)
        job["completed_at"] = _utc()
    _persist()


def _schedule_investigation(job_id: str) -> bool:
    current = _INVESTIGATION_TASKS.get(job_id)
    if current and not current.done():
        return False
    try:
        task = asyncio.get_running_loop().create_task(_run_investigation(job_id))
    except RuntimeError:
        return False
    _INVESTIGATION_TASKS[job_id] = task
    task.add_done_callback(lambda _task, jid=job_id: _INVESTIGATION_TASKS.pop(jid, None))
    return True


def start_investigation(incident_id: str, requested_by: str = "automation") -> dict:
    incident = store.get_incident(incident_id)
    if not incident:
        return {"ok": False, "eligible": False, "classification": "unresolved",
                "reason": "incident_not_found", "error": "incident not found"}
    eligibility = external_investigation_eligibility(incident_id)
    if not eligibility["eligible"]:
        return {"ok": False, **eligibility,
                "error": "external_intervention_suspected with sufficient parent_id lineage is required"}
    event_count = len(incident.event_ids)
    basis_digest = hashlib.sha256(json.dumps(
        eligibility["classification_basis"], sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    existing = next((j for j in INVESTIGATIONS.values()
                     if j.get("incident_id") == incident_id and j.get("event_count") == event_count
                     and j.get("classification_digest") in (None, basis_digest)
                     and j.get("status") in ("queued", "running", "completed")), None)
    if existing:
        if not existing.get("classification_digest"):
            existing.update(
                session_id=eligibility["session_id"], classification=eligibility["classification"],
                classification_basis=eligibility["classification_basis"],
                classification_digest=basis_digest,
            )
            _persist()
        if existing.get("status") in ("queued", "running"):
            _schedule_investigation(existing["id"])
        return {"ok": True, "eligible": True, "job": existing, "reused": True}
    jid = "ir_" + secrets.token_urlsafe(9)
    job = {
        "id": jid, "incident_id": incident_id, "session_id": eligibility["session_id"],
        "event_count": event_count, "classification": eligibility["classification"],
        "classification_basis": eligibility["classification_basis"],
        "classification_digest": basis_digest, "status": "queued",
        "requested_by": requested_by, "created_at": _utc(), "created_epoch": time.time(),
        "footprint": None, "wordlist": [], "overweb": None, "darkweb": None,
        "darkguard_hunt": None, "hunt_job_ids": [], "hunt_events": [], "hunt_errors": [],
        "working_links": [], "error": None,
    }
    INVESTIGATIONS[jid] = job
    _persist()
    _schedule_investigation(jid)
    return {"ok": True, "eligible": True, "job": job, "reused": False}


async def resume_investigations() -> dict:
    """Idempotently reschedule persisted eligible queued/running jobs."""
    resumed: list[str] = []
    rejected: list[str] = []
    changed = False
    for job_id, job in list(INVESTIGATIONS.items()):
        if job.get("status") not in ("queued", "running"):
            continue
        eligibility = external_investigation_eligibility(job.get("incident_id", ""))
        if not eligibility["eligible"]:
            job["status"] = "failed"
            job["error"] = f"startup recovery denied: {eligibility['reason']}"
            job["completed_at"] = _utc()
            rejected.append(job_id); changed = True
            continue
        job["status"] = "queued"
        job["recovered_at"] = _utc()
        job["resume_count"] = int(job.get("resume_count", 0)) + 1
        if _schedule_investigation(job_id):
            resumed.append(job_id)
        changed = True
    if changed:
        _persist()
    await asyncio.sleep(0)
    return {"resumed": resumed, "rejected": rejected}


def get_investigation(job_id: str) -> dict:
    job = INVESTIGATIONS.get(job_id)
    return {"ok": bool(job), "job": job} if job else {"ok": False, "error": "investigation job not found"}


def investigation_for_incident(incident_id: str) -> dict | None:
    jobs = [j for j in INVESTIGATIONS.values() if j.get("incident_id") == incident_id]
    return sorted(jobs, key=lambda j: (j.get("created_epoch", 0), j.get("event_count", 0)), reverse=True)[0] if jobs else None


def exposure_overview(session_id: str) -> dict:
    """Return only exposure produced by an eligible external response plan/job.

    Re-evaluate from the durable evidence chain on every eligibility read. This
    prevents an older incident snapshot from hiding a valid parent-linked plan
    after a backend restart.
    """
    chosen = None
    chosen_plan = None
    chosen_job = None
    evidence = store.read_session_evidence(session_id)["events"]
    for incident in reversed(store.session_incidents(session_id)):
        before = classification.value(incident)
        classification.apply(incident, evidence)
        if classification.value(incident) != before:
            store.upsert_incident(incident)
        if not classification.is_external_sufficient(incident):
            continue
        plan = incident.signals.get("orchestrator")
        job = investigation_for_incident(incident.incident_id)
        if plan or job:
            chosen, chosen_plan, chosen_job = incident, plan, job
            break
    if not chosen:
        return {
            "eligible": False, "status": "not_eligible", "incident_id": None,
            "classification": None, "response_plan": None, "investigation": None,
            "wordlist": [], "keywords": [], "overweb": [], "darkweb": [], "working_links": [],
            "updated_at": _utc(),
        }

    job = copy.deepcopy(chosen_job) if chosen_job else None
    overweb = ((job or {}).get("overweb") or {}).get("results") or []
    dark_scan = ((job or {}).get("darkweb") or {}).get("results") or []
    working_links = (job or {}).get("working_links") or []
    status = (job or {}).get("status") or "queued"
    updated_at = ((job or {}).get("completed_at") or (job or {}).get("started_at")
                  or (chosen_plan or {}).get("updated_at") or chosen.opened)
    return {
        "eligible": True,
        "status": status,
        "incident_id": chosen.incident_id,
        "classification": "external_intervention_suspected",
        "response_plan": copy.deepcopy(chosen_plan),
        "investigation": job,
        "wordlist": list((job or {}).get("wordlist") or WORDLISTS.get(chosen.incident_id, []))[:MAX_WORDLIST_TERMS],
        "keywords": list((job or {}).get("keywords") or [])[:6],
        "overweb": copy.deepcopy(overweb),
        "darkweb": copy.deepcopy(dark_scan),
        "working_links": copy.deepcopy(working_links),
        "updated_at": updated_at,
    }


def build_session_report(session_id: str, *, final: bool = False) -> dict:
    """Build a cumulative report from every durable evidence.jsonl record."""
    session = SESSIONS.get(session_id)
    if not session:
        return {"ok": False, "error": "session not found"}
    evidence = store.read_session_evidence(session_id)
    events = evidence["events"]
    incidents = store.session_incidents(session_id)
    incident_ids = {incident.incident_id for incident in incidents}
    incident_rows = [json.loads(incident.model_dump_json()) for incident in incidents]
    classifications = [
        {
            "incident_id": incident.incident_id,
            "classification": classification.value(incident),
            "basis": copy.deepcopy(incident.signals.get("classification") or {}),
        }
        for incident in incidents
    ]
    guardian_decisions = [
        {
            "event_id": event.id,
            "ts": event.ts,
            "agent_id": event.meta.get("agent_id") or event.process.name,
            **copy.deepcopy(event.meta.get("guardian") or {}),
        }
        for event in events if isinstance(event.meta.get("guardian"), dict)
    ]
    plans = [
        copy.deepcopy(incident.signals["orchestrator"])
        for incident in incidents if isinstance(incident.signals.get("orchestrator"), dict)
    ]
    jobs = [
        copy.deepcopy(job) for job in INVESTIGATIONS.values()
        if job.get("session_id") == session_id or job.get("incident_id") in incident_ids
    ]
    wordlists = {
        incident_id: list(WORDLISTS.get(incident_id, []))
        for incident_id in incident_ids if incident_id in WORDLISTS
    }
    overweb = [{"job_id": job.get("id"), "data": job.get("overweb")} for job in jobs if job.get("overweb") is not None]
    darkweb = [
        {"job_id": job.get("id"), "scan": job.get("darkweb"), "hunt": job.get("darkguard_hunt")}
        for job in jobs if job.get("darkweb") is not None or job.get("darkguard_hunt") is not None
    ]
    links_by_url: dict[str, dict] = {}
    for job in jobs:
        for link in job.get("working_links") or []:
            if isinstance(link, dict) and link.get("url"):
                links_by_url.setdefault(_link_key(link["url"]), copy.deepcopy(link))
    agent_state = copy.deepcopy(public_session(session).get("agent_state", {}))
    quarantined = {
        agent_id: state.get("quarantine")
        for agent_id, state in agent_state.items() if state.get("quarantined")
    }
    return {
        "session_id": session_id,
        "session": public_session(session),
        "session_metadata": {
            "target": session.get("target"), "target_host": session.get("target_host"),
            "scenario": session.get("scenario"), "objective": session.get("objective"),
            "coverage_mode": session.get("coverage_mode"), "proof": copy.deepcopy(session.get("proof")),
            "manifest": copy.deepcopy(session.get("manifest")), "policy": copy.deepcopy(session.get("policy")),
        },
        "lifecycle": {
            "status": session.get("status"), "opened": session.get("opened"),
            "ended_at": session.get("ended_at"), "end_reason": session.get("end_reason"),
            "last_heartbeat": session.get("last_heartbeat"),
        },
        "incidents": incident_rows,
        "classifications": classifications,
        "guardian_decisions": guardian_decisions,
        "orchestrator_plans": plans,
        "agent_state": agent_state,
        "reground_state": {
            agent_id: {
                "reground_required": state.get("reground_required"),
                "context": state.get("reground_context"),
                "last_ack": state.get("last_reground_ack"),
                "history": state.get("history") or [],
            }
            for agent_id, state in agent_state.items()
        },
        "quarantine_state": quarantined,
        "investigations": jobs,
        "wordlist": wordlists,
        "overweb": overweb,
        "darkweb": darkweb,
        "working_links": list(links_by_url.values()),
        "evidence": copy.deepcopy(evidence["records"]),
        "evidence_integrity": evidence["integrity"],
        "counts": {
            "evidence_records": len(evidence["records"]),
            "incidents": len(incidents),
            "classifications": len(classifications),
            "guardian_decisions": len(guardian_decisions),
            "orchestrator_plans": len(plans),
            "investigations": len(jobs),
            "working_links": len(links_by_url),
            "reground_required_agents": sum(1 for state in agent_state.values() if state.get("reground_required")),
            "quarantined_agents": len(quarantined),
        },
        "generated_at": _utc(),
        "final": bool(final),
    }


# ---- Analyst console (chat) ----------------------------------------------

async def console(message: str, incident_id: str | None) -> dict:
    from . import investigate as incident_assistant
    msg = (message or "").strip()
    low = msg.lower()
    inc = store.get_incident(incident_id) if incident_id else None

    if not msg:
        return {"action": "help", "answer": "Enter a command or question.", "commands": console_commands()}

    if low in ("help", "commands", "what can you do"):
        return {"action": "help", "answer": "Available analyst controls", "commands": console_commands(),
                "wordlist": WORDLISTS.get(incident_id or "", [])}

    if low in ("show wordlist", "wordlist", "list keywords"):
        if not incident_id:
            return {"action": "wordlist", "answer": "Bind an incident first.", "wordlist": []}
        return {"action": "wordlist", "answer": f"{len(WORDLISTS.get(incident_id, []))} keyword(s).",
                "wordlist": WORDLISTS.get(incident_id, [])}

    m = re.fullmatch(r"add keyword\s+(.+)", msg, re.I)
    if m and incident_id:
        term = m.group(1).strip()
        r = edit_wordlist(incident_id, [term], [])
        return {"action": "add" if r.get("ok") else "denied",
                "answer": f"Added '{term}'." if r.get("ok") else r.get("error"),
                "wordlist": r.get("wordlist", []), "limit": r.get("limit", MAX_WORDLIST_TERMS)}

    m = re.fullmatch(r"remove keyword\s+(.+)", msg, re.I)
    if m and incident_id:
        term = m.group(1).strip()
        r = edit_wordlist(incident_id, [], [term])
        return {"action": "remove", "answer": f"Removed '{term}'.", "wordlist": r.get("wordlist", [])}

    m = re.fullmatch(r"(?:search|look up|investigate)\s+(.+)", msg, re.I)
    if m and incident_id:
        gate = external_investigation_eligibility(incident_id)
        if not gate["eligible"]:
            return {"action": "denied", "answer": "Passive attacker OSINT requires an externally classified incident.", **gate}
        term = m.group(1).strip().strip(".")
        edit_wordlist(incident_id, [term], [])
        over = await osint([term])
        return {"action": "search", "answer": f"Added '{term}' and completed passive overweb OSINT.",
                "osint": over, "wordlist": WORDLISTS.get(incident_id, [])}

    m = re.fullmatch(r"(?:darkweb search|search darkweb for)\s+(.+)", msg, re.I)
    if m and incident_id:
        gate = external_investigation_eligibility(incident_id)
        if not gate["eligible"]:
            return {"action": "denied", "answer": "DarkGuard attribution requires an externally classified incident.", **gate}
        term = m.group(1).strip().strip(".")
        edit_wordlist(incident_id, [term], [])
        dark = await darkweb([term])
        return {"action": "darkweb", "answer": f"DarkGuard returned status '{dark.get('status')}'.",
                "darkweb": dark, "wordlist": WORDLISTS.get(incident_id, [])}

    if low in ("run full investigation", "start investigation", "investigate incident") and incident_id:
        r = start_investigation(incident_id, requested_by="analyst_console")
        if not r.get("ok"):
            return {"action": "denied", "answer": "Full attacker investigation requires external_intervention_suspected with sufficient lineage.", **r}
        return {"action": "investigation", "answer": "Autonomous footprint → wordlist → overweb + DarkGuard investigation started.", **r}

    m = re.fullmatch(r"(?:isolate|quarantine) agent\s+(.+)", msg, re.I)
    if m and inc:
        sid = inc.signals.get("session_id")
        r = quarantine(sid, m.group(1).strip(), "analyst-directed isolation from console", inc.event_ids[-1] if inc.event_ids else "")
        return {"action": "isolate", "answer": r.get("effect") if r.get("ok") else r.get("error"), "result": r}

    if inc:
        events = store.events_by_ids(inc.event_ids)
        report = incident_assistant.report(inc, events)
        # Deterministic evidence-only answers first. The optional LLM can summarize
        # this evidence elsewhere, but it does not establish cause.
        if any(k in low for k in ("why", "cause", "what happened", "explain", "fix", "next")):
            return {
                "action": "explain",
                "answer": report["summary"],
                "report": report,
                "wordlist": WORDLISTS.get(incident_id, []),
                "used_llm": False,
                "evidence_only": True,
            }

    return {
        "action": "insufficient_evidence",
        "answer": "I cannot establish that from the bound evidence. Try 'help', bind an incident, or start a real investigation.",
        "wordlist": WORDLISTS.get(incident_id or "", []),
        "used_llm": False,
    }


def console_commands() -> list[str]:
    return [
        "show wordlist", "add keyword <term>", "remove keyword <term>",
        "search <email/domain/ip/@handle>", "darkweb search <term>",
        "run full investigation", "isolate agent <registered-agent-id>",
        "why did this flag fire?",
    ]


# ---- Landscape / gaps (EXISTING_SOLUTIONS doc) ----------------------------

GAPS = [
    {"n": 1, "problem": "Unauthorized tool usage", "exists": "Defender, Check Point (tool allow/deny, preview)",
     "loophole": "Integration-bound; a permitted tool can still be misused with harmful args/destination",
     "anti": "Evaluate tool + arguments + destination + agent + user + process together, not just tool identity"},
    {"n": 2, "problem": "Memory poisoning", "exists": "Memory access controls; MPBench (research)",
     "loophole": "Not standardized; injection filtering doesn't protect stored memory; surfaces later",
     "anti": "Record provenance + trust + integrity at write; revalidate at retrieval"},
    {"n": 3, "problem": "Malicious plugins/tools", "exists": "Check Point / Defender discovery + config risk",
     "loophole": "Discovery isn't safety; a trusted tool can be compromised later",
     "anti": "Monitor each tool's runtime; drop trust on schema/behaviour change"},
    {"n": 4, "problem": "Long-term goal manipulation", "exists": "AgentDojo (benchmark); Defender single-event inspection",
     "loophole": "Benchmarks test, don't protect; single-event misses long timelines",
     "anti": "Persistent per-session timeline + sequence correlation"},
    {"n": 5, "problem": "Harmful autonomous actions", "exists": "AgentHarm (benchmark); Check Point intent screen",
     "loophole": "A harmful action looks normal if the agent is permitted it",
     "anti": "Actions vs. declared task manifest + action-specific safety policies"},
    {"n": 6, "problem": "Indirect prompt injection", "exists": "AgentDojo; Defender prompt/response inspection",
     "loophole": "Network inspection fails against cert pinning & HTTP/3; coverage gaps",
     "anti": "No TLS-interception dependency — correlate content access → action → egress metadata"},
    {"n": 7, "problem": "Multi-agent comms attacks", "exists": "OWASP guidance; research surveys",
     "loophole": "Checks focus on agents not the channel; origin hard to trace; trust not enforced",
     "anti": "Model the channel: identity, provenance, trust edges, cross-agent source tracing"},
    {"n": 8, "problem": "Identity & permission misuse", "exists": "Defender discovery; OWASP guidance",
     "loophole": "Valid permissions abused; logs don't explain why; user identity ≠ authorized",
     "anti": "Correlate user + agent + process + file + task context to expose off-task use"},
]

CROSS_CUTTING = [
    "No integration-gated blind spots: unsupported agents degrade to observe-mode, not zero visibility",
    "No dependency on TLS interception (works against pinning & HTTP/3)",
    "No 'discovery equals safety' — inventory is the first step, never the verdict",
    "No single-event tunnel vision — correlation across time and sources is the default",
    "No 'permitted equals authorized' — every action checked against the declared task",
    "No unexplained alerts — every incident cites event IDs and a cause chain",
    "No privacy overreach — observable evidence only, never the agent's internal reasoning",
]


def gaps() -> dict:
    return {"problems": GAPS, "cross_cutting": CROSS_CUTTING}
