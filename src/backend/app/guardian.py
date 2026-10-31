"""APEX GUARDIAN — independent pre-execution policy authority.

Guardian evaluates the action, actual data sensitivity, destination, compiled
session manifest, current taint, tool trust, and operator custom rules. The risk
score never decides enforcement. In gateway mode, only ALLOW/WARN responses
receive permission to execute; DENY/REQUIRE_APPROVAL receive no capability.
"""
from __future__ import annotations

import re
from typing import Any

from . import manifest as mf
from . import policy

TAINT_THRESHOLD = 50
DESTRUCTIVE_SHELL = re.compile(r"(?i)(rm\s+-rf|del\s+/|format\s|mkfs|dd\s+if=|:\(\)\{|shutdown|rmdir\s+/s)")
_ORDER = {"allow": 0, "warn": 1, "require_approval": 2, "deny": 3}


def _worse(current: str, candidate: str) -> str:
    return candidate if _ORDER[candidate] > _ORDER[current] else current


def _is_egress(tool: str, scope: str) -> bool:
    return tool in ("send_email", "transmit", "exfil", "http_post", "upload") or scope.startswith("transmit")


def _matrix(tool: str, args: str, scope: str) -> tuple[str, str, list[str], list[str]]:
    t = (tool or "").lower()
    if t in ("delete_file", "delete") or scope == "delete":
        return "require_approval", "baseline: delete requires explicit authorization", ["destructive_action"], ["AG-10", "AG-32"]
    if t in ("modify_permissions", "chmod", "set_acl") or scope == "modify_permissions":
        return "deny", "baseline: permission changes are prohibited unless explicitly mediated", ["destructive_action"], ["AG-06", "AG-10"]
    if t == "run_shell":
        if DESTRUCTIVE_SHELL.search(args or ""):
            return "deny", "baseline: destructive shell command blocked", ["destructive_action"], ["AG-32", "AG-33"]
        return "require_approval", "baseline: shell execution requires approval", ["destructive_action"], ["AG-33"]
    if _is_egress(t, scope):
        if scope == "transmit-external":
            return "deny", "baseline: external transmit denied without an authorized task purpose", ["unauthorized_scope"], ["AG-21", "AG-25", "AG-38"]
        return "require_approval", "baseline: sensitive transmit requires explicit authorization", [], ["AG-10", "AG-25"]
    return "allow", "", [], []


def validate_action(tool: str, args: str, manifest: dict, taint: int,
                    scope: str = "", tool_trust: str = "approved", *,
                    session_id: str = "", destination: str = "",
                    findings: list[Any] | None = None, event_type: str = "",
                    explicit_approval: bool = False) -> dict:
    reasons: list[str] = []
    flags: list[str] = []
    rule_ids: list[str] = ["AG-18", "AG-41", "AG-42"]
    decision = "allow"
    t = (tool or "").lower()
    findings = findings or []

    def apply(candidate: str, reason: str, new_flags=(), rules=()):
        nonlocal decision
        decision = _worse(decision, candidate)
        if reason:
            reasons.append(reason)
        flags.extend(new_flags)
        rule_ids.extend(rules)

    if not tool:
        apply("deny", "identity/action: a mediated action requires a tool identity", ["untrusted_tool"], ["AG-01", "AG-05", "AG-16"])

    # Tool Trust and baseline action matrix.
    if tool_trust in ("unknown", "revoked", "restricted"):
        apply("deny", f"tool trust '{tool_trust}' — tool not approved", ["untrusted_tool"], ["AG-16", "AG-17", "AG-20"])
    m_dec, m_reason, m_flags, m_rules = _matrix(t, args, scope)
    if m_dec == "require_approval" and explicit_approval:
        rule_ids.extend(m_rules)
        reasons.append("one-time action-bound human approval consumed")
    else:
        apply(m_dec, m_reason, m_flags, m_rules)

    # Manifest checks: exact tool, canonical file patterns, verb scope, exact host.
    if not mf.tool_allowed(manifest, tool):
        apply("deny", f"manifest: tool '{tool}' is outside the assigned task", ["unauthorized_scope"], ["AG-16", "AG-19", "AG-31"])
    if t in ("read_file", "read") and not mf.file_allowed(manifest, args):
        apply("deny", "manifest: sensitive or out-of-scope file read denied", ["privilege_inheritance", "sensitive_file_read"], ["AG-06", "AG-07", "AG-08", "AG-31"])
    if scope and not mf.scope_allowed(manifest, tool, scope):
        apply("deny", f"manifest: scope '{scope}' is not granted for '{tool}'", ["unauthorized_scope"], ["AG-09", "AG-18", "AG-19", "AG-31"])
    elif not scope:
        apply("deny", "manifest: verb scope is required for every mediated action", ["unauthorized_scope"], ["AG-05", "AG-18", "AG-41"])

    egress = _is_egress(t, scope) or t in ("http_get", "http_fetch")
    if egress:
        dest = destination or args
        if not mf.host_allowed(manifest, dest):
            apply("deny", f"network: destination '{dest}' is not allowlisted", ["destination_not_allowlisted"], ["AG-21", "AG-25", "AG-36", "AG-38"])

    # Data protection uses the actual locally detected payload classes.
    secret = any(getattr(f, "type", None) in ("secret", "canary", "entropy") or
                 (isinstance(f, dict) and f.get("type") in ("secret", "canary", "entropy")) for f in findings)
    pii = any(getattr(f, "type", None) == "pii" or (isinstance(f, dict) and f.get("type") == "pii") for f in findings)
    if secret and egress:
        apply("deny", "DLP: secret/high-entropy credential detected in outbound content", ["secret_in_payload"], ["AG-21", "AG-22", "AG-38"])
    elif pii and egress and decision == "allow":
        apply("deny" if manifest.get("scenario") == "testing" else "warn",
              "DLP: personal information detected; testing posture blocks, production requires policy review",
              [], ["AG-23"])

    # Taint only tightens; past memory or attacker content can never loosen policy.
    tightened = taint >= TAINT_THRESHOLD
    if tightened:
        if t in ("read_file", "read"):
            apply("deny", "tainted session: file reads denied until re-grounded", ["injection_suspected"], ["AG-12", "AG-15", "AG-27", "AG-29"])
        if egress:
            apply("deny", "tainted session: tool/network egress blocked", ["injection_suspected"], ["AG-12", "AG-15", "AG-21", "AG-36"])
        if t == "run_shell":
            apply("deny", "tainted session: shell blocked", ["injection_suspected"], ["AG-15", "AG-33"])

    # Declarative organization rules compiled at Setup.
    context = {
        "tool": tool, "scope": scope, "destination": destination or args,
        "path": args if t in ("read_file", "read") else "",
        "event_type": event_type,
        "data_type": "secret" if secret else "pii" if pii else "none",
    }
    custom_hits = policy.evaluate_custom(session_id, context)
    for hit in custom_hits:
        apply(hit["enforcement"], f"{hit['id']}: {hit['title']}", [], [hit["id"]])

    rule_ids = list(dict.fromkeys(rule_ids + [r for flag in flags for r in policy.rules_for_flag(flag)]))
    reason = "; ".join(dict.fromkeys(reasons)) or "within objective, manifest, data and destination policy"
    reminder = {
        "type": "trusted_security_context",
        "objective": manifest.get("task", ""),
        "allowed_tools": manifest.get("allowed_tools", []),
        "allowed_hosts": manifest.get("allowed_hosts", []),
        "instruction": ("The proposed action was denied. Return to the declared objective; do not retry, "
                        "reuse prior memory to bypass policy, add tools, or change destination."
                        if decision == "deny" else
                        "Continue only within the declared objective and capability manifest."),
        "policy_version": policy.version(),
    }
    return {
        "decision": decision,
        "execute": decision in ("allow", "warn"),
        "reason": reason,
        "rules": reasons,
        "rule_ids": rule_ids,
        "policy_version": policy.version(),
        "flags": sorted(set(flags)),
        "tightened": tightened,
        "taint": taint,
        "tool_trust": tool_trust,
        "custom_hits": custom_hits,
        "reminder": reminder,
        "policy_basis": "explicit policy: sensitivity + destination + permissions + action; risk score not used",
    }
