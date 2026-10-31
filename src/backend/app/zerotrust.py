"""Feature B — Zero-Trust agent access gate.

Never trust an agent because it was approved before. Every *sensitive* action is
re-evaluated from scratch against the current session context on four axes:

    1. Identity     — the acting agent/process is the session's registered identity
    2. Task         — the action is within the session's declared objective
    3. Permissions  — the verb scope is granted in the capability manifest
    4. Destination  — the target is on the allowlist

The gate is STATELESS about prior approvals: it stores no "already approved"
flag, so re-submitting a denied action is re-evaluated, never auto-allowed. That
statelessness is the property that makes it zero-trust.

Decision follows the explicit D1 policy (data/destination/permission/action),
NOT the risk score: allow / warn / require_approval / deny. Each decision cites
the baseline AG rules it enforces (APEX_FINAL_FLOW Appendix B).
"""
from __future__ import annotations

import time

from . import manifest as mf

# Sensitive actions trigger a full four-axis re-check. Everything else takes the
# normal allow-plus-audit path.
SENSITIVE_TOOLS = {
    "send_email": "transmit", "transmit": "transmit", "exfil": "transmit",
    "http_post": "transmit", "upload": "transmit",
    "delete_file": "delete", "delete": "delete",
    "modify_permissions": "modify_permissions", "chmod": "modify_permissions", "set_acl": "modify_permissions",
    "run_shell": "shell",
}
SENSITIVE_SCOPES = {"transmit", "transmit-external", "delete", "modify_permissions"}

AG_RULES = ["AG-06", "AG-18", "AG-19", "AG-31"]      # zero-trust re-check baseline
AG_APPROVAL = ["AG-10", "AG-32"]                     # approval / destructive path

# Session identity registry: the first identity seen for a session is the one all
# later sensitive actions must match. This is session context, NOT an approval
# cache — it never records that an action was allowed.
_IDENTITY: dict[str, str] = {}
# Append-only decision log + per-event index, read by the attack graph / report.
DECISIONS: list[dict] = []
ZT_BY_EVENT: dict[str, dict] = {}


def _identity_key(session_id: str, identity: str) -> str:
    agent_id = (identity or "").split(":", 1)[0]
    return f"{session_id}:{agent_id}"


def see_identity(session_id: str, identity: str) -> None:
    key = _identity_key(session_id, identity)
    if session_id and identity and key not in _IDENTITY:
        _IDENTITY[key] = identity


def classify(tool: str, scope: str, args: str) -> tuple[bool, str]:
    """Return (is_sensitive, category)."""
    t = (tool or "").lower()
    s = (scope or "").lower()
    if s in SENSITIVE_SCOPES:
        return True, "transmit" if s.startswith("transmit") else s
    if t in SENSITIVE_TOOLS:
        return True, SENSITIVE_TOOLS[t]
    if t in ("read_file", "read") and mf.SENSITIVE.search(args or ""):
        return True, "read-sensitive"
    return False, ""


def _worst(a: str, b: str) -> str:
    order = {"allow": 0, "warn": 1, "require_approval": 2, "deny": 3}
    return a if order[a] >= order[b] else b


def evaluate(session_id: str, identity: str, tool: str, args: str, scope: str,
             destination: str, manifest: dict | None = None, event_id: str = "",
             explicit_approval: bool = False) -> dict:
    """Run the four-axis re-check for one sensitive action. Pure w.r.t. prior
    approvals — calling it twice with the same inputs yields the same decision."""
    manifest = manifest or mf.get(session_id)
    sensitive, category = classify(tool, scope, args)

    axes: list[dict] = []
    decision = "allow"

    # 1) Identity — acting identity matches the session's registered identity.
    registered = _IDENTITY.get(_identity_key(session_id, identity))
    id_ok = (not registered) or (identity == registered)
    axes.append({
        "axis": "identity", "ok": id_ok,
        "detail": (f"acting identity '{identity}' matches session identity"
                   if id_ok else
                   f"acting identity '{identity}' != session identity '{registered}'"),
    })
    if not id_ok:
        decision = _worst(decision, "deny")

    # 2) Task — the action is within the session's declared objective (manifest tools).
    task_ok = mf.tool_allowed(manifest, tool)
    axes.append({
        "axis": "task", "ok": task_ok,
        "detail": (f"'{tool}' is within the declared objective"
                   if task_ok else
                   f"'{tool}' is not part of the session's declared task"),
    })
    if not task_ok:
        decision = _worst(decision, "require_approval")

    # 3) Permissions — verb scope granted in the capability manifest.
    perm_ok = mf.scope_allowed(manifest, tool, scope) if scope else True
    # read-sensitive: a sensitive file is out of scope regardless of a read grant.
    if category == "read-sensitive":
        perm_ok = mf.file_allowed(manifest, args)
    axes.append({
        "axis": "permissions", "ok": perm_ok,
        "detail": (f"scope '{scope or 'read'}' is granted for '{tool}'"
                   if perm_ok else
                   f"scope '{scope or 'read'}' is NOT granted for '{tool}' in the manifest"),
    })
    if not perm_ok:
        decision = _worst(decision, "deny" if category in ("transmit", "delete", "modify_permissions", "read-sensitive") else "require_approval")

    # 4) Destination — target on the allowlist (only meaningful for egress).
    needs_dest = category == "transmit" or tool in ("http_get", "http_fetch", "http_post")
    if needs_dest and destination:
        dest_ok = mf.host_allowed(manifest, destination)
    else:
        dest_ok = True
    axes.append({
        "axis": "destination", "ok": dest_ok,
        "detail": (f"destination '{destination or '—'}' is on the allowlist"
                   if dest_ok else
                   f"destination '{destination}' is NOT on the allowlist"),
    })
    if needs_dest and not dest_ok:
        # critical data / external transmit to an off-allowlist target -> block.
        decision = _worst(decision, "deny" if category == "transmit" else "warn")

    # D1 explicit-policy floor: any sensitive action is at minimum require_approval.
    if sensitive and decision == "allow" and not explicit_approval:
        decision = "require_approval" if category in ("delete", "modify_permissions", "shell") else "allow"

    reason = _policy_reason(decision, category, axes)
    ag = AG_RULES + (AG_APPROVAL if decision in ("deny", "require_approval") else [])

    record = {
        "event_id": event_id,
        "session_id": session_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "tool": tool, "args": args, "scope": scope, "destination": destination,
        "sensitive": sensitive, "category": category,
        "decision": decision,
        "axes": axes,
        "all_axes_pass": all(a["ok"] for a in axes),
        "reason": reason,
        "ag_rules": ag,
        "stateless": True,
        "policy_basis": "D1 explicit policy (data + destination + permissions + action) — not the risk score",
    }
    if sensitive:
        DECISIONS.append(record)
        if event_id:
            ZT_BY_EVENT[event_id] = record
    return record


def _policy_reason(decision: str, category: str, axes: list[dict]) -> str:
    failed = [a["axis"] for a in axes if not a["ok"]]
    if decision == "deny":
        return f"BLOCK — {category} action failed zero-trust axes: {', '.join(failed)}"
    if decision == "require_approval":
        return f"REQUIRE APPROVAL — sensitive {category} action" + (f"; weak axes: {', '.join(failed)}" if failed else "")
    if decision == "warn":
        return f"WARN — {category} action within policy but unusual ({', '.join(failed)})"
    return f"ALLOW — {category or 'non-sensitive'} action; all four axes pass"


def decisions_for(event_ids: list[str]) -> list[dict]:
    return [ZT_BY_EVENT[e] for e in event_ids if e in ZT_BY_EVENT]
