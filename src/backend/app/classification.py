"""Deterministic, evidence-linked incident classification.

The classifier never uses timing, score, severity, or deployment posture.  An
external intervention is suspected only when a recorded untrusted ingress is in
the ``parent_id`` ancestry of an offending Gateway action.  The relationship is
still described as execution lineage, not proof that content changed intent.
"""
from __future__ import annotations

from typing import Iterable

from .models import Event, Incident

CLASSIFIER_VERSION = "lineage-v1"
VALUES = ("self_drift", "external_intervention_suspected", "unresolved")
_EXTERNAL_BEHAVIOURS = {
    "injection_suspected",
    "memory_write_suspected",
    "memory_retrieval_untrusted",
    "untrusted_agent_message",
}
_DENIALS = {"deny", "pause", "require_approval"}


def _is_gateway_deviation(event: Event) -> bool:
    if not event.tool or not bool(event.meta.get("gateway_mediated")):
        return False
    decision = event.meta.get("guardian") or {}
    return decision.get("decision") in _DENIALS or decision.get("execute") is False


def _is_external_ingress(event: Event) -> bool:
    """Recognize untrusted ingress, while excluding taint copied onto an action."""
    if event.meta.get("gateway_mediated"):
        return False
    behaviours = {b.type for b in event.behavior}
    equivalent = behaviours & {
        "memory_write_suspected", "memory_retrieval_untrusted", "untrusted_agent_message",
    }
    injected_untrusted_content = (
        "injection_suspected" in behaviours
        and event.trust_level == "untrusted"
        and not event.tool
    )
    provenance_untrusted = bool(
        event.meta.get("provenance_tainted")
        or event.meta.get("spoofed")
        or "untrusted" in (event.meta.get("input_trusts") or [])
    )
    return bool(injected_untrusted_content or equivalent or (
        provenance_untrusted and behaviours & _EXTERNAL_BEHAVIOURS
    ))


def classify(incident: Incident, session_events: Iterable[Event]) -> dict:
    """Return the canonical classification and its auditable evidence basis."""
    events = list(session_events)
    by_id = {event.id: event for event in events}
    incident_ids = set(incident.event_ids)
    incident_events = [by_id[event_id] for event_id in incident.event_ids if event_id in by_id]
    terminals = [event for event in incident_events if _is_gateway_deviation(event)]
    ingress_in_incident = [event for event in incident_events if _is_external_ingress(event)]

    linked_paths: list[list[str]] = []
    incomplete_paths: list[dict] = []
    traversed_ids: set[str] = set()

    for terminal in terminals:
        path = [terminal.id]
        seen = {terminal.id}
        parent_id = terminal.parent_id
        linked = False
        while parent_id:
            if parent_id in seen:
                incomplete_paths.append({
                    "terminal_event_id": terminal.id,
                    "path_event_ids": list(reversed(path)),
                    "reason": "parent_id_cycle",
                    "missing_parent_id": None,
                })
                break
            parent = by_id.get(parent_id)
            if parent is None:
                incomplete_paths.append({
                    "terminal_event_id": terminal.id,
                    "path_event_ids": list(reversed(path)),
                    "reason": "parent_event_unavailable",
                    "missing_parent_id": parent_id,
                })
                break
            if terminal.session_id and parent.session_id != terminal.session_id:
                incomplete_paths.append({
                    "terminal_event_id": terminal.id,
                    "path_event_ids": list(reversed([*path, parent.id])),
                    "reason": "cross_session_parent",
                    "missing_parent_id": None,
                })
                break
            seen.add(parent.id)
            path.append(parent.id)
            traversed_ids.add(parent.id)
            if _is_external_ingress(parent):
                linked_paths.append(list(reversed(path)))
                linked = True
                break
            parent_id = parent.parent_id
            if len(path) >= 64 and parent_id:
                incomplete_paths.append({
                    "terminal_event_id": terminal.id,
                    "path_event_ids": list(reversed(path)),
                    "reason": "ancestry_depth_exceeded",
                    "missing_parent_id": parent_id,
                })
                break
        if linked:
            continue

    terminal_ids = [event.id for event in terminals]
    unlinked_ingress_ids = [
        event.id for event in ingress_in_incident if event.id not in traversed_ids
    ]

    common = {
        "classifier_version": CLASSIFIER_VERSION,
        "terminal_event_ids": terminal_ids,
        "external_ingress_event_ids": [event.id for event in ingress_in_incident],
        "unlinked_external_ingress_event_ids": unlinked_ingress_ids,
        "incomplete_paths": incomplete_paths,
        "time_proximity_used": False,
    }

    if linked_paths:
        path = linked_paths[0]
        return {
            **common,
            "value": "external_intervention_suspected",
            "basis_event_ids": path,
            "relationship": "parent_id_ancestry",
            "evidence_sufficiency": "sufficient",
            "lineage_paths": linked_paths,
            "statement": (
                "External intervention is suspected because an untrusted ingress is in the "
                "recorded parent_id ancestry of a denied or offending Gateway action. "
                "Execution lineage does not prove semantic influence or actor identity."
            ),
        }

    if not terminals:
        return {
            **common,
            "value": "unresolved",
            "basis_event_ids": [event.id for event in ingress_in_incident],
            "relationship": "no_offending_gateway_action",
            "evidence_sufficiency": "insufficient",
            "lineage_paths": [],
            "statement": "No denied or offending Gateway action is available for lineage classification.",
        }

    if incomplete_paths:
        basis = list(dict.fromkeys([
            *terminal_ids,
            *(event_id for path in incomplete_paths for event_id in path["path_event_ids"]),
        ]))
        return {
            **common,
            "value": "unresolved",
            "basis_event_ids": basis,
            "relationship": "incomplete_parent_id_ancestry",
            "evidence_sufficiency": "insufficient",
            "lineage_paths": [],
            "statement": "The Gateway policy deviation is observed, but its recorded ancestry is incomplete or invalid.",
        }

    if unlinked_ingress_ids:
        return {
            **common,
            "value": "unresolved",
            "basis_event_ids": list(dict.fromkeys([*unlinked_ingress_ids, *terminal_ids])),
            "relationship": "same_incident_without_parent_id_lineage",
            "evidence_sufficiency": "insufficient",
            "lineage_paths": [],
            "statement": (
                "Untrusted ingress and a Gateway policy deviation occurred in the same incident, "
                "but no parent_id ancestry links them; time or session proximity is not causation."
            ),
        }

    return {
        **common,
        "value": "self_drift",
        "basis_event_ids": terminal_ids,
        "relationship": "gateway_policy_deviation_without_linked_external_ingress",
        "evidence_sufficiency": "sufficient",
        "lineage_paths": [],
        "statement": (
            "Observed Gateway policy deviation with no linked external ingress. "
            "This describes observed behavior and does not prove agent intent."
        ),
    }


def apply(incident: Incident, session_events: Iterable[Event]) -> dict:
    result = classify(incident, session_events)
    incident.classification = result["value"]
    # Keep the legacy field coherent for existing readers while the structured
    # evidence lives under signals.classification.
    incident.cause = result["value"]
    incident.signals["classification"] = result
    return result


def value(incident: Incident) -> str:
    recorded = incident.signals.get("classification") or {}
    candidate = recorded.get("value") or getattr(incident, "classification", "unresolved")
    return candidate if candidate in VALUES else "unresolved"


def is_external_sufficient(incident: Incident) -> bool:
    recorded = incident.signals.get("classification") or {}
    return (
        value(incident) == "external_intervention_suspected"
        and recorded.get("evidence_sufficiency") == "sufficient"
        and recorded.get("relationship") == "parent_id_ancestry"
        and bool(recorded.get("basis_event_ids"))
    )
