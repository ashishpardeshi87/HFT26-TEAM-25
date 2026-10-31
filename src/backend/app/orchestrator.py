"""SENTINEL AI Orchestrator driven by deterministic recorded facts.

Classification is shared by testing and production. Policy enforcement remains
independent of severity and investigation is launched only for a sufficiently
evidence-linked external intervention.
"""
from __future__ import annotations

import time

from . import classification, flow
from .store import store

_PLANS: dict[str, dict] = {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _agent_for(incident, fallback_event):
    details = incident.signals.get("classification") or {}
    terminals = store.events_by_ids_durable(
        details.get("terminal_event_ids") or [], incident.signals.get("session_id") or ""
    )
    event = terminals[-1] if terminals else fallback_event
    return str(event.meta.get("agent_id") or event.process.name), event


def on_incident(incident, event) -> dict:
    """Advance one incident's response from canonical classification facts."""
    sid = incident.signals.get("session_id") or event.session_id
    session = flow.SESSIONS.get(sid)
    details = incident.signals.get("classification") or {}
    value = classification.value(incident)
    external = classification.is_external_sufficient(incident)
    self_drift = value == "self_drift"
    agent_id, terminal = _agent_for(incident, event)
    guardian = terminal.meta.get("guardian") or {}
    denied = guardian.get("decision") == "deny"

    reground = None
    if session and session.get("status") == "monitoring" and self_drift and denied:
        reground = flow.require_reground(
            sid, agent_id, guardian.get("reason") or "Gateway policy deviation",
            guardian.get("rule_ids") or [], terminal.id,
        )

    isolation = None
    if session and session.get("status") == "monitoring" and external:
        isolation = flow.quarantine(
            sid, agent_id,
            "external intervention suspected from recorded parent_id ancestry",
            terminal.id,
        )

    state = flow.get_agent_state(sid, agent_id) or {}
    if guardian:
        if guardian.get("execute") is False:
            enforce_detail = "Gateway denied the proposed action before execution."
        else:
            enforce_detail = "Gateway evaluated the proposed action and returned an affirmative decision."
        enforce_status = "completed"
    else:
        enforce_detail = "Observe-only evidence recorded; no Gateway containment is asserted."
        enforce_status = "observe_only"

    stages = [
        {"id": "observe", "status": "completed", "detail": f"event {event.id} stored"},
        {"id": "detect", "status": "completed", "detail": value},
        {"id": "enforce", "status": enforce_status, "detail": enforce_detail},
        {
            "id": "reground",
            "status": ("pending" if state.get("reground_required") else
                       "completed" if self_drift and state.get("last_reground_ack") else "not_required"),
            "detail": ("trusted objective and manifest context awaits authenticated acknowledgment"
                       if state.get("reground_required") else
                       "authenticated context acknowledgment recorded"
                       if self_drift and state.get("last_reground_ack") else
                       "not required for this classification"),
        },
        {
            "id": "isolate",
            "status": "completed" if state.get("quarantined") else "not_triggered",
            "detail": ("Gateway access revoked and capability epoch incremented"
                       if state.get("quarantined") else "isolation criteria not met"),
        },
        {
            "id": "forensics", "status": "queued" if external else "not_required",
            "detail": ("parent_id-linked external ingress evidence" if external
                       else "external lineage not established"),
        },
        {
            "id": "investigate", "status": "queued" if external else "not_required",
            "detail": ("passive overweb plus live DarkGuard scan and hunt" if external
                       else "attacker investigation not launched"),
        },
        {"id": "report", "status": "ready", "detail": f"{len(incident.event_ids)} cited event(s)"},
    ]

    job = None
    if session and session.get("status") == "monitoring" and session.get("auto_investigate") and external:
        started = flow.start_investigation(incident.incident_id, requested_by="sentinel_orchestrator")
        job = started.get("job") if started.get("ok") else None
        if job:
            for stage in stages:
                if stage["id"] == "forensics":
                    stage["status"] = "completed" if job.get("footprint") else job.get("status", "queued")
                    stage["detail"] = job.get("id")
                if stage["id"] == "investigate":
                    stage["status"] = job.get("status", "queued")
                    stage["detail"] = job.get("id")

    result_exists = bool(job and job.get("status") == "completed" and (
        job.get("overweb") is not None or job.get("darkweb") is not None
        or job.get("darkguard_hunt") is not None
    ))
    plan = {
        "incident_id": incident.incident_id,
        "session_id": sid,
        "updated_at": _now(),
        "autonomous": True,
        "classification": value,
        "classification_basis": details,
        "cause_class": value,
        "cause_evidence": details.get("statement"),
        "evidence_sufficiency": details.get("evidence_sufficiency", "insufficient"),
        "guardian_decision": guardian.get("decision"),
        "execute": guardian.get("execute"),
        "agent_id": agent_id,
        "capability_epoch": state.get("capability_epoch"),
        "reground_required": bool(state.get("reground_required")),
        "reground_context_version": ((state.get("reground_context") or {}).get("version")),
        "quarantined": bool(state.get("quarantined")),
        "isolation": isolation,
        "investigation_job_id": job.get("id") if job else None,
        "stages": stages,
        "next_action": _next(stages),
        "next_view": "exposure_overview" if external and result_exists else "command_center",
        "safety_invariant": (
            "Guardian policy is independent of classification, posture, and risk score. "
            "Only recorded parent_id ancestry can trigger external investigation."
        ),
    }
    _PLANS[incident.incident_id] = plan
    incident.signals["orchestrator"] = plan
    return plan


def _next(stages: list[dict]) -> str:
    active = next((stage for stage in stages if stage["status"] in ("queued", "running", "pending")), None)
    return active["id"] if active else "analyst_review"


def _hydrate(incident_id: str) -> dict | None:
    if incident_id in _PLANS:
        return _PLANS[incident_id]
    incident = store.get_incident(incident_id)
    persisted = (incident.signals.get("orchestrator") if incident else None)
    if isinstance(persisted, dict):
        _PLANS[incident_id] = persisted
        return persisted
    return None


def _refresh_job(plan: dict) -> None:
    job_id = plan.get("investigation_job_id")
    job = flow.INVESTIGATIONS.get(job_id) if job_id else None
    if not job:
        return
    for stage in plan.get("stages", []):
        if stage["id"] == "forensics":
            stage["status"] = "completed" if job.get("footprint") else job.get("status")
        if stage["id"] == "investigate":
            stage["status"] = job.get("status")
    state = flow.get_agent_state(plan.get("session_id", ""), plan.get("agent_id", "")) or {}
    for stage in plan.get("stages", []):
        if stage["id"] == "reground":
            stage["status"] = "pending" if state.get("reground_required") else (
                "completed" if state.get("last_reground_ack") else stage["status"]
            )
    plan["reground_required"] = bool(state.get("reground_required"))
    plan["quarantined"] = bool(state.get("quarantined"))
    plan["capability_epoch"] = state.get("capability_epoch")
    plan["next_action"] = _next(plan.get("stages", []))
    if job.get("status") == "completed" and (
            job.get("overweb") is not None or job.get("darkweb") is not None
            or job.get("darkguard_hunt") is not None):
        plan["next_view"] = "exposure_overview"


def status(session_id: str) -> dict:
    for incident in store.session_incidents(session_id):
        _hydrate(incident.incident_id)
    plans = [plan for plan in _PLANS.values() if plan.get("session_id") == session_id]
    for plan in plans:
        _refresh_job(plan)
    return {
        "agent": "SENTINEL AI Orchestrator",
        "session_id": session_id,
        "autonomous": True,
        "plans": sorted(plans, key=lambda plan: plan["updated_at"], reverse=True),
        "active_jobs": sum(1 for plan in plans if plan.get("next_action") in ("forensics", "investigate")),
        "controls": ["Guardian", "Zero Trust", "Injection Guard", "Memory Guard", "Tool Trust",
                     "Agent Trust", "Behaviour Intelligence", "APEX TRACE", "DarkGuard bridge"],
    }


def get_plan(incident_id: str) -> dict | None:
    plan = _hydrate(incident_id)
    if plan:
        _refresh_job(plan)
    return plan
