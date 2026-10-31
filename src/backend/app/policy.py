"""SENTINEL APEX policy loader and per-session compiler.

The standalone YAML file is the machine-readable source of truth. Setup compiles
it with an operator's custom layer. Rules marked ``floor: true`` may be tightened
but cannot be disabled or weakened. Guardian reads the compiled session policy;
the monitored agent never evaluates its own safety.
"""
from __future__ import annotations

import copy
import fnmatch
import os
import re
from functools import lru_cache
from typing import Any

import yaml

_PATH = os.path.join(os.path.dirname(__file__), "policies", "apex_agent_security_policy.yaml")
_SESSION_POLICIES: dict[str, dict[str, Any]] = {}

_ENFORCEMENT_RANK = {"allow": 0, "warn": 1, "require_approval": 2, "deny": 3}
_SEVERITY_RANK = {"medium": 0, "high": 1, "critical": 2}
_ALLOWED_ENFORCEMENT = set(_ENFORCEMENT_RANK)
_ALLOWED_SEVERITY = set(_SEVERITY_RANK)


@lru_cache(maxsize=1)
def load() -> dict:
    with open(_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def rules() -> list[dict]:
    return copy.deepcopy(load().get("rules", []))


def rule(rid: str) -> dict | None:
    return next((r for r in rules() if r.get("id") == rid), None)


def floor_ids() -> list[str]:
    return [r["id"] for r in rules() if r.get("floor")]


def version() -> str:
    return str(load().get("policy_version", "0"))


def summary(rule_set: list[dict] | None = None) -> dict:
    rs = rule_set if rule_set is not None else rules()
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    floor = 0
    enabled = 0
    for r in rs:
        by_cat[r.get("category", "custom")] = by_cat.get(r.get("category", "custom"), 0) + 1
        by_sev[r.get("severity", "high")] = by_sev.get(r.get("severity", "high"), 0) + 1
        by_mode[r.get("enforcement", "warn")] = by_mode.get(r.get("enforcement", "warn"), 0) + 1
        if r.get("floor"):
            floor += 1
        if r.get("enabled", True):
            enabled += 1
    return {
        "policy_version": version(),
        "total": len(rs),
        "enabled": enabled,
        "floor": floor,
        "by_category": by_cat,
        "by_severity": by_sev,
        "by_enforcement": by_mode,
        "categories": load().get("categories", {}),
        "enforcement_levels": load().get("enforcement_levels", {}),
        "standards_catalog": load().get("standards_catalog", {}),
        "design_invariant": load().get("design_invariant", ""),
    }


def compile_policy(customizations: list[dict] | None, scenario: str = "production") -> dict:
    """Merge customizations into the baseline and reject any floor weakening.

    Supported operations:
      * ``override``: change title/severity/enforcement/match (floor: tighten only)
      * ``disable``: non-floor rules only
      * ``add``: a CUSTOM-* rule with a declarative ``match`` object
    """
    effective = rules()
    by_id = {r["id"]: r for r in effective}
    errors: list[str] = []
    applied: list[dict] = []

    for raw in customizations or []:
        if not isinstance(raw, dict):
            errors.append("Each custom policy entry must be an object.")
            continue
        op = str(raw.get("operation", "override")).lower()
        rid = str(raw.get("id", "")).strip().upper()
        if not rid:
            errors.append("A custom policy entry is missing id.")
            continue

        if op == "add":
            if not rid.startswith("CUSTOM-"):
                errors.append(f"{rid}: added rule IDs must start with CUSTOM-.")
                continue
            if rid in by_id:
                errors.append(f"{rid}: duplicate rule ID.")
                continue
            enforcement = str(raw.get("enforcement", "warn")).lower()
            severity = str(raw.get("severity", "high")).lower()
            if enforcement not in _ALLOWED_ENFORCEMENT or severity not in _ALLOWED_SEVERITY:
                errors.append(f"{rid}: invalid severity or enforcement.")
                continue
            match = raw.get("match") or {}
            if not isinstance(match, dict) or not match:
                errors.append(f"{rid}: custom rules require a non-empty match object.")
                continue
            new_rule = {
                "id": rid,
                "title": str(raw.get("title") or rid),
                "category": "custom",
                "module": "guardian",
                "severity": severity,
                "enforcement": enforcement,
                "condition": "operator_custom_match",
                "match": match,
                "floor": False,
                "priority": "CUSTOM",
                "cis_controls": list(raw.get("cis_controls") or []),
                "standards": list(raw.get("standards") or ["organization_policy"]),
                "enabled": True,
            }
            effective.append(new_rule)
            by_id[rid] = new_rule
            applied.append({"operation": "add", "id": rid})
            continue

        base = by_id.get(rid)
        if not base:
            errors.append(f"{rid}: baseline rule not found; use operation=add and CUSTOM-*.")
            continue
        if op == "disable":
            if base.get("floor"):
                errors.append(f"{rid}: floor rule cannot be disabled.")
                continue
            base["enabled"] = False
            applied.append({"operation": "disable", "id": rid})
            continue
        if op != "override":
            errors.append(f"{rid}: unsupported operation '{op}'.")
            continue

        new_enf = str(raw.get("enforcement", base.get("enforcement", "warn"))).lower()
        new_sev = str(raw.get("severity", base.get("severity", "high"))).lower()
        if new_enf not in _ALLOWED_ENFORCEMENT or new_sev not in _ALLOWED_SEVERITY:
            errors.append(f"{rid}: invalid severity or enforcement.")
            continue
        if base.get("floor"):
            if _ENFORCEMENT_RANK[new_enf] < _ENFORCEMENT_RANK[base.get("enforcement", "allow")]:
                errors.append(f"{rid}: floor enforcement can be tightened, never weakened.")
                continue
            if _SEVERITY_RANK[new_sev] < _SEVERITY_RANK[base.get("severity", "medium")]:
                errors.append(f"{rid}: floor severity can be raised, never lowered.")
                continue
        base["enforcement"] = new_enf
        base["severity"] = new_sev
        if raw.get("title"):
            base["title"] = str(raw["title"])
        if isinstance(raw.get("match"), dict):
            base["match"] = raw["match"]
        applied.append({"operation": "override", "id": rid})

    # Testing uses the same baseline but defaults custom WARN rules to DENY when
    # the operator did not explicitly choose a stronger/weaker mode.
    if scenario == "testing":
        for r in effective:
            if r.get("category") == "custom" and r.get("enforcement") == "warn":
                r["enforcement"] = "deny"

    return {
        "ok": not errors,
        "errors": errors,
        "policy_version": version(),
        "rules": effective,
        "applied": applied,
        "summary": summary(effective),
        "invariant": load().get("design_invariant"),
    }


def register_session(session_id: str, compiled: dict) -> None:
    _SESSION_POLICIES[session_id] = copy.deepcopy(compiled)


def for_session(session_id: str) -> dict:
    return copy.deepcopy(_SESSION_POLICIES.get(session_id) or compile_policy([]))


def _match_value(value: str, pattern: Any) -> bool:
    if isinstance(pattern, list):
        return any(_match_value(value, p) for p in pattern)
    p = str(pattern or "")
    if not p:
        return True
    try:
        if p.startswith("re:"):
            return bool(re.search(p[3:], value or "", re.I))
    except re.error:
        return False
    return fnmatch.fnmatch((value or "").lower(), p.lower())


def evaluate_custom(session_id: str, context: dict) -> list[dict]:
    """Evaluate enabled rules that carry a declarative ``match`` block.

    Match keys: tool, scope, destination, path, event_type, data_type. Values may
    be glob strings, ``re:...`` regex strings, or lists. All supplied keys must
    match. This provides executable organization-specific rules without eval().
    """
    compiled = _SESSION_POLICIES.get(session_id)
    if not compiled:
        return []
    hits = []
    for r in compiled.get("rules", []):
        match = r.get("match")
        if not r.get("enabled", True) or not isinstance(match, dict) or not match:
            continue
        if all(_match_value(str(context.get(k, "")), v) for k, v in match.items()):
            hits.append({
                "id": r["id"], "title": r.get("title", r["id"]),
                "enforcement": r.get("enforcement", "warn"),
                "severity": r.get("severity", "high"),
            })
    return hits


# Map Guardian flags / behaviours to baseline rule IDs for decision audit.
FLAG_TO_RULE = {
    "untrusted_tool": ["AG-16", "AG-17"],
    "unauthorized_scope": ["AG-18", "AG-19", "AG-25"],
    "privilege_inheritance": ["AG-06", "AG-07", "AG-08"],
    "destructive_action": ["AG-10", "AG-32", "AG-33"],
    "injection_suspected": ["AG-11", "AG-12", "AG-14", "AG-15"],
    "memory_write_suspected": ["AG-24", "AG-26", "AG-27", "AG-28"],
    "memory_retrieval_untrusted": ["AG-29"],
    "untrusted_agent_message": ["AG-37"],
    "behaviour_sequence": ["AG-31", "AG-34"],
    "sensitive_file_read": ["AG-07", "AG-08", "AG-31"],
    "shell_spawn": ["AG-33"],
    "dangerous_flag": ["AG-06", "AG-31", "AG-44"],
    "destination_not_allowlisted": ["AG-21", "AG-25", "AG-36", "AG-38"],
    "secret_in_payload": ["AG-21", "AG-22", "AG-38"],
    "monitoring_bypass": ["AG-35", "AG-44"],
    "unregistered_agent": ["AG-01", "AG-03", "AG-05"],
}


def rules_for_flag(flag: str) -> list[str]:
    return FLAG_TO_RULE.get(flag, [])
