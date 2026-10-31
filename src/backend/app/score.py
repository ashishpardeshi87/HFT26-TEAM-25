"""Explainable threat scoring (PS requirement 5) — declarative, evidence-cited.

Weights live in scoring.yaml so the score is inspectable data, not UI decoration.
Every fired rule records the event_ids that triggered it, so a judge can trace any
point in the score back to the evidence that produced it.
"""
from __future__ import annotations

import os
from functools import lru_cache

import yaml

_DEFAULT = {
    "thresholds": {"critical": 75, "high": 50, "medium": 25},
    "provider": {"unapproved": 20, "unknown": 8, "local_llm": 6},
    "data_leak": {"critical": 40, "high": 26, "medium": 14, "low": 6, "max_findings": 3},
    "behaviour": {"critical": 40, "high": 26, "medium": 14, "low": 6},
    "confirmations": {"canary_exfiltration": 60, "fingerprint_match": 45},
    "external_exposure_divisor": 5, "external_exposure_max": 15,
}


@lru_cache(maxsize=1)
def _rules() -> dict:
    path = os.path.join(os.path.dirname(__file__), "scoring.yaml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return {**_DEFAULT, **data}
    except Exception:
        return _DEFAULT


def level_for(score: int) -> str:
    t = _rules()["thresholds"]
    if score >= t["critical"]:
        return "critical"
    if score >= t["high"]:
        return "high"
    if score >= t["medium"]:
        return "medium"
    return "low"


def score_incident(signals, findings_ev, behaviors_ev, external_exposure=None,
                   canary_confirmed=False, fingerprint_match=False):
    """findings_ev / behaviors_ev are lists of (event_id, obj).

    Returns dict(score, level, reasons, fired_rules).
    """
    r = _rules()
    score = 0
    fired: list[dict] = []

    def fire(rule, points, event_ids, detail):
        nonlocal score
        score += points
        fired.append({"rule": rule, "points": points, "event_ids": sorted(set(event_ids)), "detail": detail})

    # high-confidence confirmations dominate (near ground-truth)
    if canary_confirmed:
        eids = [e for e, f in findings_ev if f.type == "canary"]
        fire("canary_exfiltration", r["confirmations"]["canary_exfiltration"], eids,
             "Canary token planted in bait .env reappeared in an outbound payload")
    if fingerprint_match:
        eids = [e for e, f in findings_ev if f.fingerprint]
        fire("fingerprint_match", r["confirmations"]["fingerprint_match"], eids,
             "A secret read from a sensitive file reappeared in a payload (HMAC fingerprint match)")

    # destination approval (only when a real destination was observed)
    approval = signals.get("approval", "unknown")
    has_dest = bool(signals.get("providers") or signals.get("destinations"))
    if approval == "unapproved":
        fire("unapproved_provider", r["provider"]["unapproved"],
             signals.get("_provider_eids", []), "Destination is an unapproved AI provider")
    elif approval == "unknown" and has_dest:
        fire("unknown_provider", r["provider"]["unknown"],
             signals.get("_provider_eids", []), "Destination provider is unknown")
    if signals.get("local_llm"):
        fire("local_llm", r["provider"]["local_llm"],
             signals.get("_provider_eids", []), "Data sent to an unmonitored local LLM")

    # data-leak findings (strongest few; skip canary already counted)
    leaks = [(e, f) for e, f in findings_ev if f.type != "canary"]
    leaks.sort(key=lambda x: r["data_leak"].get(x[1].severity, 0), reverse=True)
    for e, f in leaks[: r["data_leak"]["max_findings"]]:
        fire(f"data_leak:{f.label}", r["data_leak"].get(f.severity, 0), [e],
             f"{f.severity} data leak: {f.label}")

    # agent behaviour
    for e, b in behaviors_ev:
        if b.type == "policy_decision":
            continue  # decisions are enforcement outcomes, not risk points
        fire(f"behaviour:{b.type}", r["behaviour"].get(b.severity, 0), [e], b.detail)

    # external corroboration
    if external_exposure and external_exposure.get("exposure_score", 0) > 0:
        bump = min(r["external_exposure_max"], external_exposure["exposure_score"] // r["external_exposure_divisor"])
        if bump:
            fire("external_exposure", bump, [],
                 f"DarkGuard: asset already exposed externally (score {external_exposure['exposure_score']})")

    score = max(0, min(100, score))
    reasons = [f"+{x['points']} {x['detail']}" for x in fired]
    return {"score": score, "level": level_for(score), "reasons": reasons, "fired_rules": fired}
