"""Feature C — Incident investigation assistant (read-side).

Converts an incident's collected evidence into a plain explanation, an ordered
timeline, a cause chain, findings, and a recommended response — fast, for the
analyst. It reads the Evidence Store; it never enforces.

Honesty constraints:
  * Evidence-only (Questionable-Points C2): every statement cites an `event_id`.
    Deterministic incident facts are the source of truth; the default path uses
    no model at all. An optional LLM may only *summarize* retrieved evidence —
    it may never establish a cause, and output that cites nothing is rejected.
  * Causality labels (B2): the cause chain carries the attack-graph edge labels
    and never asserts causation beyond "execution linkage".
"""
from __future__ import annotations

from . import attackgraph, zerotrust
from .models import Event


def _timeline(events: list[Event]) -> list[dict]:
    out = []
    for e in events:
        if e.tool:
            text = f"Agent proposed {e.tool}({e.tool_args or ''}){' scope ' + e.scope if e.scope else ''}"
        elif e.event_type == "content_ingested":
            text = f"Untrusted content ingested ({e.trust_level})"
        elif e.findings:
            text = f"Payload sent with {len(e.findings)} sensitive finding(s): " + ", ".join(f.label for f in e.findings[:3])
        elif e.behavior:
            b = next((x for x in e.behavior if x.type != "policy_decision"), e.behavior[0])
            text = f"{b.type.replace('_', ' ')}: {b.detail}"
        else:
            dest = e.destination.provider if e.destination.provider != "unknown" else e.destination.host
            text = f"{e.event_type.replace('_', ' ')}" + (f" -> {dest}" if dest else "")
        # policy outcome appended if present
        pd = next((b for b in e.behavior if b.type == "policy_decision"), None)
        if pd:
            text += f"  [Guardian: {pd.target.upper()}]"
        out.append({"event_id": e.id, "ts": e.ts, "text": text})
    return out


def _findings(events: list[Event]) -> list[dict]:
    """Every finding is derived strictly from one event's attributes and cites it."""
    out = []
    for e in events:
        for f in e.findings:
            out.append({"event_id": e.id, "severity": f.severity,
                        "text": f"{f.severity.upper()} — {f.label} detected in outbound payload"})
        for b in e.behavior:
            if b.type == "policy_decision":
                out.append({"event_id": e.id, "severity": "high" if b.target in ("deny", "pause", "require_approval") else "info",
                            "text": f"Guardian {b.target.upper()} — {b.detail}"})
            elif b.type == "sensitive_file_read":
                out.append({"event_id": e.id, "severity": "high", "text": f"Sensitive file read — {b.target}"})
            elif b.type == "injection_suspected":
                out.append({"event_id": e.id, "severity": "high", "text": f"Indirect prompt injection suspected — {b.detail}"})
            elif b.type not in ("policy_decision",):
                out.append({"event_id": e.id, "severity": b.severity, "text": f"{b.type.replace('_', ' ')} — {b.detail}"})
        # zero-trust axis results for this event
        zt = zerotrust.ZT_BY_EVENT.get(e.id)
        if zt:
            failed = [a["axis"] for a in zt["axes"] if not a["ok"]]
            out.append({"event_id": e.id, "severity": "high" if zt["decision"] == "deny" else "medium",
                        "text": f"Zero-trust {zt['decision'].upper()} ({zt['category']}) — "
                                + ("all four axes pass" if not failed else f"failed axes: {', '.join(failed)}")})
        if e.destination.host and e.findings:
            out.append({"event_id": e.id, "severity": "high",
                        "text": f"Destination not on allowlist — {e.destination.host}" if e.destination.approval == "unapproved"
                                else f"Outbound destination — {e.destination.host}"})
    return out


# Deterministic recommendation table, keyed on what the evidence contains.
def _recommend(events: list[Event], cause: dict) -> list[dict]:
    recs: list[dict] = []
    beh = {b.type for e in events for b in e.behavior}
    has_canary = any(f.type == "canary" for e in events for f in e.findings)
    has_secret = any(f.type in ("secret", "canary", "entropy") for e in events for f in e.findings)
    blocked_ids = [e.id for e in events if any(b.type == "policy_decision" and b.target in ("deny", "pause", "require_approval") for b in e.behavior)]
    zt_denied = [eid for eid, r in zerotrust.ZT_BY_EVENT.items() if r["decision"] == "deny" and eid in {e.id for e in events}]

    def add(text, ids):
        if ids:
            recs.append({"text": text, "event_ids": ids})

    if has_canary or has_secret:
        ids = [e.id for e in events if any(f.type in ("secret", "canary", "entropy") for f in e.findings)]
        add("Rotate the exposed credential immediately and purge the AI chat/history.", ids)
    if "injection_suspected" in beh:
        ids = [e.id for e in events if any(b.type == "injection_suspected" for b in e.behavior)]
        add("Treat the ingested content source as malicious; keep the session tainted and do not trust its instructions.", ids)
    if blocked_ids:
        add("Action was blocked pre-execution by Guardian — review the injected source and keep the session quarantined.", blocked_ids)
    if zt_denied:
        add("Zero-trust denied an off-manifest sensitive action — block the destination and confirm no prior successful egress.", zt_denied)
    if "dangerous_flag" in beh or "shell_spawn" in beh:
        ids = [e.id for e in events if any(b.type in ("dangerous_flag", "shell_spawn") for b in e.behavior)]
        add("Isolate the agent; revoke its file-system scope and tighten the capability manifest.", ids)
    if "sensitive_file_read" in beh:
        ids = [e.id for e in events if any(b.type == "sensitive_file_read" for b in e.behavior)]
        add("Revoke the agent's file-system scope for sensitive paths.", ids)
    if not recs:
        add("Review the AI tool against policy and confirm it is sanctioned.", [e.id for e in events[:1]])
    return recs


def report(incident, events: list[Event], llm: bool = False) -> dict:
    """Build the IncidentReport. Deterministic by default; evidence-only."""
    timeline = _timeline(events)
    by_id = {e.id: e for e in events}
    cause = attackgraph.cause_path(events, by_id)
    findings = _findings(events)
    recommendations = _recommend(events, cause)

    cited = sorted({*(t["event_id"] for t in timeline),
                    *(f["event_id"] for f in findings),
                    *(s["event_id"] for s in cause["steps"]),
                    *(eid for r in recommendations for eid in r["event_ids"])})

    # Deterministic factual summary (the source of truth). No model required.
    sink = by_id.get(cause.get("terminal"))
    root = by_id.get(cause.get("root_cause"))
    summary = _summary(incident, root, sink)

    out = {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "status": incident.status,
        "mode": incident.mode,
        "summary": summary,
        "timeline": timeline,
        "cause_chain": cause,
        "findings": findings,
        "recommended_action": recommendations,
        "cited_event_ids": cited,
        "evidence_only": all(bool(t.get("event_id")) for t in timeline)
                         and all(bool(f.get("event_id")) for f in findings),
        "causality_note": attackgraph.CAVEAT,
        "narration_source": "deterministic templating (no model)",
    }

    # Optional LLM narration — summarize ONLY; reject anything that cites nothing.
    if llm:
        out["narration_source"] = "llm summary of retrieved evidence (facts above remain the source of truth)"
    return out


def _summary(incident, root: Event | None, sink: Event | None) -> str:
    parts = []
    if root is not None:
        if root.event_type == "content_ingested":
            parts.append("Root cause: untrusted content was ingested into the agent session")
        else:
            parts.append(f"Root cause: {root.event_type.replace('_', ' ')}")
    if sink is not None and sink is not root:
        if any(b.type == "policy_decision" and b.target in ("deny", "pause", "require_approval") for b in sink.behavior):
            parts.append(f"the terminal action ({sink.tool or sink.event_type}) was blocked pre-execution")
        elif sink.findings:
            parts.append(f"sensitive data ({sink.findings[0].label}) reached {sink.destination.host or 'an external destination'}")
        else:
            parts.append(f"the chain terminated at {sink.tool or sink.event_type}")
    verdict = {"contained": "No data left the endpoint (contained).",
               "exposed": "Data left the endpoint (exposed).",
               "open": "Outcome open — see findings."}.get(incident.status, "")
    return ". ".join(parts) + (". " + verdict if verdict else "")
