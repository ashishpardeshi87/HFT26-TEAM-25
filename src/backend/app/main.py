"""SENTINEL APEX backend — FastAPI app.

Pipeline:  event -> enrich (provider classify + payload scan) -> graph correlation
           -> scoring -> DarkGuard enrichment -> store -> WebSocket push.
"""
from __future__ import annotations

import asyncio
import json
import os

from fastapi import FastAPI, Header, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import (agenttrust, attackgraph, behaviour, classification, coverage, darkguard, detect, execution, exposure, flow,
               guardian, injection_guard, investigate, manifest, memory_guard, monitor, orchestrator, ownership, policy, providers,
               telemetry, tooltrust, torfinder, triage, zerotrust)
from .correlate import Correlator
from .models import Behavior, Destination, Event, Process
from .store import store

app = FastAPI(title="SENTINEL APEX", version="1.1.0")
_CORS = [x.strip() for x in os.getenv("SENTINEL_CORS_ORIGINS", "http://127.0.0.1:4173,http://localhost:4173").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=_CORS, allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Sentinel-Session", "X-Sentinel-Token"],
    allow_credentials=False,
)

correlator = Correlator()
SESSION_TAINT: dict[str, int] = {}   # session_id -> taint score (set by Injection Guard)


# --------------------------------------------------------------- pipeline
def enrich(ev: Event) -> Event:
    d = ev.destination
    if (d.host or d.ip or d.port) and d.provider in ("", "unknown"):
        c = providers.classify(d.host, d.ip, d.port)
        d.provider, d.approval, d.local_llm = c["provider"], c["approval"], c["local_llm"]
    if ev.payload_excerpt and not ev.findings:
        ev.findings = detect.scan(ev.payload_excerpt)
    return ev


async def ingest(ev: Event) -> dict:
    telemetry.heartbeat()   # sensor liveness (E3): absence of evidence is not safety
    ev = enrich(ev)
    sid = ev.session_id or ev.host
    # Zero-trust session context: the first identity seen for a session is the one
    # every later sensitive action must match (session context, not an approval cache).
    zerotrust.see_identity(sid, f"{ev.process.name}:{ev.process.pid}:{ev.user}")

    def raise_taint(v):
        SESSION_TAINT[sid] = max(SESSION_TAINT.get(sid, 0), v)

    # SESSION REGISTRY (AG-01/03/05): passive discovery still records unknown
    # AI processes instead of silently excluding them from the chosen scope.
    if ev.source == "process" and ev.process.name and sid in flow.SESSIONS:
        if not manifest.process_allowed(manifest.get(sid), ev.process.name, ev.process.pid):
            ev.behavior.append(Behavior(
                type="unregistered_agent", severity="high", target=ev.process.name,
                detail=f"AI-connected process '{ev.process.name}' (pid {ev.process.pid}) is not a registered agent [AG-01,AG-03,AG-05]",
            ))

    # INJECTION GUARD (problem 6): untrusted content at ingress raises session taint.
    if ev.trust_level == "untrusted" and ev.payload_excerpt and not ev.tool:
        ig = injection_guard.scan(ev.payload_excerpt)
        if ig["behavior"]:
            ev.behavior.append(ig["behavior"]); raise_taint(ig["taint"])

    # MEMORY GUARD (problem 2): inspect writes, revalidate retrievals.
    if ev.event_type == "memory_write":
        r = memory_guard.write(
            ev.meta.get("memory_id", "mem"), ev.payload_excerpt,
            ev.meta.get("source", "agent"), SESSION_TAINT.get(sid, 0) >= 50,
            source_ids=ev.meta.get("source_ids") or [ev.parent_id or ev.id],
            input_trusts=ev.meta.get("input_trusts") or [ev.trust_level],
            derived_from=ev.meta.get("derived_from") or [],
        )
        if r["behavior"]:
            ev.behavior.append(r["behavior"]); raise_taint(60)
    elif ev.event_type == "memory_retrieval":
        r = memory_guard.retrieve(ev.meta.get("memory_id", "mem"))
        if r["behavior"]:
            ev.behavior.append(r["behavior"]); raise_taint(r["taint"])

    # TOOL TRUST (problem 3): inventory + schema-change detection at registration.
    if ev.event_type == "tool_registered":
        r = tooltrust.register(ev.meta.get("tool_id", ""), ev.meta.get("publisher", ""),
                               ev.meta.get("endpoint", ""), ev.meta.get("caps"))
        if r["behavior"]:
            ev.behavior.append(r["behavior"])

    # AGENT TRUST (problem 7): authenticate inter-agent messages, don't inherit trust.
    if ev.event_type == "agent_message":
        r = agenttrust.check_message(ev.meta.get("from_agent", ""), ev.meta.get("to_agent", ""),
                                     ev.meta.get("provenance_tainted", False), ev.meta.get("spoofed", False))
        if r["behavior"]:
            ev.behavior.append(r["behavior"]); raise_taint(r["taint"])

    # GUARDIAN + ZERO-TRUST (features 1/5/8 + Phase 4): one authoritative,
    # pre-execution result. Zero-trust is independently re-run on every action.
    if ev.tool:
        tid = ev.meta.get("tool_id")
        ttrust = tooltrust.trust_of(tid) if tid else "approved"
        mf = manifest.get(sid)
        agent_id = str(ev.meta.get("agent_id") or ev.process.name)
        egress = ev.tool in ("http_get", "http_fetch", "http_post", "send_email", "transmit", "exfil", "upload") \
            or ev.scope.startswith("transmit")
        zt_dest = ev.destination.host or (ev.tool_args if egress else "")
        zerotrust.see_identity(sid, f"{agent_id}:{ev.process.pid}:{ev.user}")

        dec = guardian.validate_action(
            ev.tool, ev.tool_args, mf, SESSION_TAINT.get(sid, 0),
            scope=ev.scope, tool_trust=ttrust, session_id=sid,
            destination=zt_dest, findings=ev.findings, event_type=ev.event_type,
            explicit_approval=bool(ev.meta.get("explicit_approval")),
        )
        zt = zerotrust.evaluate(
            sid, f"{agent_id}:{ev.process.pid}:{ev.user}", ev.tool, ev.tool_args,
            ev.scope, zt_dest, mf, event_id=ev.id,
            explicit_approval=bool(ev.meta.get("explicit_approval")),
        )
        rank = {"allow": 0, "warn": 1, "require_approval": 2, "pause": 2, "deny": 3}
        if rank.get(zt["decision"], 0) > rank.get(dec["decision"], 0):
            dec["decision"] = zt["decision"]
            dec["execute"] = zt["decision"] in ("allow", "warn")
            dec["reason"] += "; " + zt["reason"]
            dec["rule_ids"] = list(dict.fromkeys(dec["rule_ids"] + zt.get("ag_rules", [])))
        dec["zero_trust_axes"] = zt["axes"]
        ev.meta["guardian"] = dec
        ev.meta["zero_trust"] = zt

        sev = "critical" if dec["decision"] == "deny" else ("high" if dec["decision"] == "require_approval" else "medium")
        ev.behavior.append(Behavior(
            type="policy_decision", target=dec["decision"], severity=sev,
            detail=(f"{dec['decision'].upper()} {ev.tool}({ev.tool_args or ev.scope}) — {dec['reason']} "
                    f"[policy {dec['policy_version']}; {','.join(dec['rule_ids'])}]")
        ))
        for flag in dec["flags"]:
            ags = policy.rules_for_flag(flag)
            tag = f" [{','.join(ags)}]" if ags else ""
            ev.behavior.append(Behavior(type=flag, severity="high", target=ev.tool,
                                        detail=f"{flag.replace('_', ' ')} on {ev.tool} {ev.scope}{tag}".strip()))

        if dec["decision"] == "deny" and sid in flow.SESSIONS:
            # Classification and external isolation are decided only after the
            # event is durably stored and its parent_id ancestry is resolved.
            retry = flow.record_denial(sid, agent_id, f"{ev.tool}|{ev.scope}|{zt_dest}|{ev.tool_args}",
                                       ev.id, False, egress, direct_linkage=False)
            ev.meta["denial_tracking"] = retry
            if retry.get("count", 0) >= 2:
                ev.behavior.append(Behavior(type="monitoring_bypass", severity="critical", target=agent_id,
                                            detail="Agent retried an action after Guardian denial [AG-35,AG-44]"))

    # BEHAVIOUR INTELLIGENCE (problem 4): record action for sequence/drift analysis.
    if ev.tool:
        seq_label = f"{ev.tool}:{ev.tool_args}"
    elif any(b.type == "sensitive_file_read" for b in ev.behavior):
        seq_label = "read_confidential"
    elif ev.event_type in ("exfil", "ai_payload", "browser_prompt", "local_llm_prompt") and (
            ev.destination.host or ev.destination.provider != "unknown"):
        seq_label = "connect_" + (ev.destination.host or ev.destination.provider)
    else:
        seq_label = ""
    if seq_label:
        sb = behaviour.record(sid, seq_label)
        if sb:
            ev.behavior.append(sb)

    # Evidence boundary: detections use the original in-memory payload, then raw
    # secrets/regulated identifiers are irreversibly masked before persistence.
    ev.payload_excerpt = detect.redact_for_storage(ev.payload_excerpt)
    ev.redacted = True
    store.add_event(ev)
    asyncio.create_task(store.anchor_if_due())
    inc = correlator.ingest(ev)
    # The canonical branch is derived from complete durable session evidence.
    # Same-session/time proximity is deliberately ignored without parent lineage.
    session_evidence = store.read_session_evidence(ev.session_id)["events"]
    classification.apply(inc, session_evidence)
    inc.ai_explanation = triage.explain(inc, [], [])

    store.upsert_incident(inc)

    # The SENTINEL AI Orchestrator advances the autonomous response plan from
    # deterministic incident and Guardian facts. It launches read-side
    # investigation without delaying the enforcement decision.
    if sid in flow.SESSIONS:
        orchestrator.on_incident(inc, ev)
        store.upsert_incident(inc)
    msg = {"type": "update", "event": json.loads(ev.model_dump_json()),
           "incident": json.loads(inc.model_dump_json()),
           "stats": store.stats(sid)}
    await store.publish(msg)
    return msg


# --------------------------------------------------------------- session auth
def _session_token(x_sentinel_token: str | None, authorization: str | None) -> str:
    if x_sentinel_token:
        return x_sentinel_token
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _authenticate_session(session_id: str, x_sentinel_token: str | None,
                          authorization: str | None) -> dict:
    """Authenticate the ownership-bound session token without changing lifecycle."""
    token = _session_token(x_sentinel_token, authorization)
    if not session_id or not token:
        raise HTTPException(status_code=401, detail="Verified monitoring session and Gateway token required.")
    if not flow.token_valid(session_id, token):
        raise HTTPException(status_code=401, detail="Invalid session gateway token.")
    session = flow.SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session gateway token.")
    return session


def _authorize(session_id: str, x_sentinel_token: str | None, authorization: str | None) -> dict:
    # Authenticate before evaluating lifecycle so an arbitrary caller cannot
    # mutate a session to credential_expired with a guessed session id.
    _authenticate_session(session_id, x_sentinel_token, authorization)
    try:
        return flow.require_monitoring(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _authorize_incident(incident_id: str, session_id: str, x_sentinel_token: str | None,
                        authorization: str | None) -> dict:
    sess = _authorize(session_id, x_sentinel_token, authorization)
    inc = store.get_incident(incident_id)
    if not inc or inc.signals.get("session_id") != session_id:
        raise HTTPException(status_code=404, detail="incident not found in this monitoring session")
    return sess


# --------------------------------------------------------------- REST API
@app.get("/api/health")
async def health():
    return {"ok": True, "service": "SENTINEL APEX", "version": "1.1.0",
            "featherless": bool(os.getenv("FEATHERLESS_API_KEY")),
            "darkguard": darkguard.configured(),
            "runtime_data": "real-only", "setup_required": True,
            "security_config": {
                "stable_secret_fingerprints": bool(os.getenv("ORG_HMAC_KEY")),
                "stable_execution_signing": bool(os.getenv("SENTINEL_EXECUTION_HMAC_KEY")),
                "offbox_evidence_anchor": bool(os.getenv("SENTINEL_ANCHOR_URL")),
            }}


@app.get("/api/stats")
async def get_stats(x_sentinel_session: str | None = Header(default=None),
                    x_sentinel_token: str | None = Header(default=None),
                    authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""; _authorize(sid, x_sentinel_token, authorization)
    return store.stats(sid)


@app.get("/api/events")
async def get_events(limit: int = 50, x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""; _authorize(sid, x_sentinel_token, authorization)
    return [json.loads(e.model_dump_json()) for e in store.recent_events(limit, sid)]


@app.get("/api/incidents")
async def get_incidents(limit: int = 50, x_sentinel_session: str | None = Header(default=None),
                        x_sentinel_token: str | None = Header(default=None),
                        authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""; _authorize(sid, x_sentinel_token, authorization)
    return [json.loads(i.model_dump_json()) for i in store.recent_incidents(limit, sid)]


@app.get("/api/incidents/{iid}")
async def get_incident(iid: str,
                       x_sentinel_session: str | None = Header(default=None),
                       x_sentinel_token: str | None = Header(default=None),
                       authorization: str | None = Header(default=None)):
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    inc = store.get_incident(iid)
    return json.loads(inc.model_dump_json()) if inc else {"error": "not found"}


# --------------------------------------------------------------- Phase-4 features
@app.get("/api/incidents/{iid}/graph")
async def incident_graph(iid: str,
                         x_sentinel_session: str | None = Header(default=None),
                         x_sentinel_token: str | None = Header(default=None),
                         authorization: str | None = Header(default=None)):
    """Feature A — attack graph: event-lineage {nodes, edges} + path-to-sink
    + Mermaid/DOT, with B2 causality labels on every edge."""
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    inc = store.get_incident(iid)
    if not inc:
        return {"error": "not found"}
    return attackgraph.build(store.events_by_ids(inc.event_ids))


@app.get("/api/incidents/{iid}/report")
async def incident_report(iid: str, llm: bool = False,
                          x_sentinel_session: str | None = Header(default=None),
                          x_sentinel_token: str | None = Header(default=None),
                          authorization: str | None = Header(default=None)):
    """Feature C — investigation assistant: evidence-only timeline, cause chain,
    findings, and recommended response. Every line cites an event_id."""
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    inc = store.get_incident(iid)
    if not inc:
        return {"error": "not found"}
    return investigate.report(inc, store.events_by_ids(inc.event_ids), llm=llm)


@app.get("/api/incidents/{iid}/zerotrust")
async def incident_zerotrust(iid: str,
                             x_sentinel_session: str | None = Header(default=None),
                             x_sentinel_token: str | None = Header(default=None),
                             authorization: str | None = Header(default=None)):
    """Feature B — recorded four-axis zero-trust decisions for this incident."""
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    inc = store.get_incident(iid)
    if not inc:
        return {"error": "not found"}
    return {"decisions": zerotrust.decisions_for(inc.event_ids)}


@app.get("/api/providers")
async def get_providers():
    return {"cloud": providers.CLOUD_PROVIDERS, "local": providers.LOCAL_LLM_PORTS}


@app.get("/api/telemetry")
async def get_telemetry():
    """Monitoring state (E3): active / degraded / unavailable — never 'safe' on gaps."""
    return telemetry.report()


@app.get("/api/evidence/integrity")
async def evidence_integrity():
    """Verify the local append-only hash chain and report remote-anchor status."""
    return store.integrity_status()


@app.get("/api/coverage")
async def get_coverage(x_sentinel_session: str | None = Header(default=None),
                       x_sentinel_token: str | None = Header(default=None),
                       authorization: str | None = Header(default=None)):
    """The eight AI-agent security problems + fired counts + tool inventory."""
    sid = x_sentinel_session or ""; _authorize(sid, x_sentinel_token, authorization)
    fired: dict[int, int] = {}
    for i in store.recent_incidents(100, sid):
        for p in i.problems:
            fired[p] = fired.get(p, 0) + 1
    return {"problems": coverage.PROBLEMS, "fired": fired, "tools": tooltrust.inventory()}


@app.get("/api/attribution/status")
async def attribution_status():
    """Live DarkGuard APEX readiness. No synthetic capability counts."""
    ready = await darkguard.readiness()
    if not ready.get("configured"):
        return {
            "mode": "live-only", "status": "unconfigured", "synthetic": False,
            "darkguard": ready,
            "capabilities": [],
            "note": "Configure the server-side DarkGuard bridge to enable live onion-service attribution.",
        }
    try:
        upstream = await darkguard.attribution("GET", "status")
    except Exception as exc:
        return {"mode": "live-only", "status": "unavailable", "synthetic": False,
                "darkguard": ready, "capabilities": [], "error": str(exc)}
    # Upstream status describes the engine; this SENTINEL surface exposes live
    # collection only. Synthetic corpus/evaluation claims are never shown as live.
    return {
        "mode": "live-only", "status": ready.get("status", "degraded"),
        "synthetic": False, "darkguard": ready,
        "capabilities": upstream.get("capabilities", []),
        "cannotDo": upstream.get("cannotDo", []),
        "corpus": "not loaded in production UI; live service comparison only",
    }


# --------------------------------------------------------------- APEX final flow
@app.get("/api/policy")
async def get_policy():
    """The 45-rule AI Agent Security Policy (Guardian baseline / floor)."""
    return {"summary": policy.summary(), "rules": policy.rules(), "floor_ids": policy.floor_ids()}


@app.post("/api/setup/token")
async def setup_token(body: dict):
    """Issue a one-time ownership challenge; only a digest is retained."""
    try:
        return flow.issue_token(body.get("target", ""))
    except (ValueError, ownership.VerificationError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/sessions")
async def create_session(body: dict):
    """Verify ownership, compile policy/manifest, and start monitoring."""
    result = await flow.register_session(body)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    session = result["session"]
    monitor.start(session["session_id"], session["target"], flow.update_target_health)
    return result


@app.get("/api/sessions/{sid}")
async def get_session(sid: str,
                      x_sentinel_token: str | None = Header(default=None),
                      authorization: str | None = Header(default=None)):
    _authorize(sid, x_sentinel_token, authorization)
    session = flow.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="session not found")
    return {"session": session}


@app.get("/api/sessions/{sid}/report")
async def session_report(sid: str,
                         x_sentinel_token: str | None = Header(default=None),
                         authorization: str | None = Header(default=None)):
    session = _authenticate_session(sid, x_sentinel_token, authorization)
    orchestrator.status(sid)
    if session.get("status") == "ended":
        snapshot = store.load_session_report(sid)
        if snapshot:
            return snapshot
    report = flow.build_session_report(sid, final=session.get("status") == "ended")
    if report.get("ok") is False:
        raise HTTPException(status_code=404, detail=report.get("error"))
    return report


def _complete_session_end(sid: str, x_sentinel_token: str | None,
                          authorization: str | None, reason: str) -> dict:
    session = _authenticate_session(sid, x_sentinel_token, authorization)
    orchestrator.status(sid)
    if session.get("status") == "ended":
        monitor.stop(sid)
        report = store.load_session_report(sid)
        if report is None:
            report = flow.build_session_report(sid, final=True)
            snapshot = store.save_session_report(sid, report)
            flow.record_final_report(sid, snapshot)
        return {"ok": True, "session": flow.get_session(sid), "report": report}
    try:
        flow.require_monitoring(sid)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Establish the complete evidence cutoff before the terminal transition,
    # then rebuild after epoch revocation so the final lifecycle is represented.
    flow.build_session_report(sid, final=False)
    ended = flow.end_session(sid, reason=reason)
    if not ended.get("ok"):
        raise HTTPException(status_code=409, detail=ended.get("error"))
    monitor.stop(sid)
    orchestrator.status(sid)
    report = flow.build_session_report(sid, final=True)
    snapshot = store.save_session_report(sid, report)
    flow.record_final_report(sid, snapshot)
    return {"ok": True, "session": flow.get_session(sid), "report": report}


@app.post("/api/sessions/{sid}/end")
async def end_monitoring_session(sid: str,
                                 x_sentinel_token: str | None = Header(default=None),
                                 authorization: str | None = Header(default=None)):
    return _complete_session_end(sid, x_sentinel_token, authorization, "operator_requested")


@app.post("/api/sessions/{sid}/stop")
async def stop_monitoring_session(sid: str, x_sentinel_token: str | None = Header(default=None),
                                  authorization: str | None = Header(default=None)):
    """Compatibility route using the same idempotent terminal behavior as /end."""
    return _complete_session_end(sid, x_sentinel_token, authorization, "stop_compatibility_route")


@app.post("/api/sessions/{sid}/agents/{agent_id}/reground/ack")
async def acknowledge_agent_reground(sid: str, agent_id: str, body: dict,
                                     x_sentinel_token: str | None = Header(default=None),
                                     authorization: str | None = Header(default=None)):
    _authorize(sid, x_sentinel_token, authorization)
    if "context_version" not in body:
        raise HTTPException(status_code=400, detail="context_version is required")
    result = flow.acknowledge_reground(sid, agent_id, body.get("context_version"))
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result.get("error"))
    return result


@app.post("/api/sessions/{sid}/agents/{agent_id}/release")
async def release_quarantined_agent(sid: str, agent_id: str,
                                    x_sentinel_token: str | None = Header(default=None),
                                    authorization: str | None = Header(default=None)):
    _authorize(sid, x_sentinel_token, authorization)
    return flow.release_agent(sid, agent_id)


@app.get("/api/approvals")
async def list_pending_approvals(x_sentinel_session: str | None = Header(default=None),
                                 x_sentinel_token: str | None = Header(default=None),
                                 authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    return {"approvals": flow.list_approvals(sid)}


@app.post("/api/approvals/{approval_id}/decision")
async def decide_pending_approval(approval_id: str, body: dict,
                                  x_sentinel_session: str | None = Header(default=None),
                                  x_sentinel_token: str | None = Header(default=None),
                                  authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    result = flow.decide_approval(sid, approval_id, bool(body.get("approve")))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/sessions/{sid}/heartbeat")
async def monitoring_heartbeat(sid: str, x_sentinel_token: str | None = Header(default=None),
                               authorization: str | None = Header(default=None)):
    _authorize(sid, x_sentinel_token, authorization)
    flow.touch_heartbeat(sid)
    telemetry.heartbeat()
    return {"ok": True, "session_id": sid, "monitoring_state": "active"}


@app.post("/api/policy/preview")
async def preview_policy(body: dict):
    result = policy.compile_policy(body.get("custom_rules") or [], body.get("scenario", "production"))
    if not result["ok"]:
        raise HTTPException(status_code=400, detail={"error": "policy rejected", "errors": result["errors"]})
    return {"summary": result["summary"], "applied": result["applied"], "rules": result["rules"]}


@app.post("/api/trace")
async def trace(body: dict,
                x_sentinel_session: str | None = Header(default=None),
                x_sentinel_token: str | None = Header(default=None),
                authorization: str | None = Header(default=None)):
    """Stage 6/7 — extract the attacker footprint and evidence-derived wordlist."""
    iid = body.get("incident_id", "")
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    return flow.footprint(iid)


@app.post("/api/wordlist")
async def wordlist(body: dict,
                   x_sentinel_session: str | None = Header(default=None),
                   x_sentinel_token: str | None = Header(default=None),
                   authorization: str | None = Header(default=None)):
    """Stage 7 — edit the active incident wordlist."""
    iid = body.get("incident_id", "")
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    return flow.edit_wordlist(iid, body.get("add", []), body.get("remove", []))


@app.post("/api/osint")
async def osint_ep(body: dict,
                   x_sentinel_session: str | None = Header(default=None),
                   x_sentinel_token: str | None = Header(default=None),
                   authorization: str | None = Header(default=None)):
    """Stage 8a — passive OSINT for a lineage-qualified external incident."""
    iid = str(body.get("incident_id") or "")
    if not iid:
        raise HTTPException(status_code=400, detail="incident_id is required")
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    gate = flow.external_investigation_eligibility(iid)
    if not gate["eligible"]:
        raise HTTPException(status_code=409, detail=gate)
    return await flow.osint(body.get("keywords", []))


@app.post("/api/darkweb")
async def darkweb_ep(body: dict,
                     x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    """Stage 8b — live DarkGuard only for a lineage-qualified external incident."""
    iid = str(body.get("incident_id") or "")
    if not iid:
        raise HTTPException(status_code=400, detail="incident_id is required")
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    gate = flow.external_investigation_eligibility(iid)
    if not gate["eligible"]:
        raise HTTPException(status_code=409, detail=gate)
    return await flow.darkweb(body.get("keywords", []))


@app.get("/api/darkguard/readiness")
async def darkguard_readiness():
    return await darkguard.readiness()


_DARKGUARD_UI_MAX_REQUEST_BYTES = 1024 * 1024


async def _darkguard_ui_body(request: Request) -> dict | None:
    declared = request.headers.get("content-length")
    if declared:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length.") from exc
        if declared_size < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length.")
        if declared_size > _DARKGUARD_UI_MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="DarkGuard UI request exceeds 1 MiB.")

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _DARKGUARD_UI_MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="DarkGuard UI request exceeds 1 MiB.")
        chunks.append(chunk)
    raw = b"".join(chunks)

    if request.method != "POST":
        if raw:
            raise HTTPException(status_code=400, detail="Request body is not allowed for this DarkGuard UI operation.")
        return None
    if not raw:
        return None
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="DarkGuard UI requests require application/json.")
    try:
        body = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HTTPException(status_code=400, detail="Invalid DarkGuard UI JSON body.") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="DarkGuard UI request body must be a JSON object.")
    return body


@app.api_route("/api/darkguard/ui/{upstream_path:path}", methods=["GET", "POST", "DELETE"])
async def darkguard_ui_bridge(upstream_path: str, request: Request,
                              x_sentinel_session: str | None = Header(default=None),
                              x_sentinel_token: str | None = Header(default=None),
                              authorization: str | None = Header(default=None)):
    """Evidence-gated bridge for the explicitly allowlisted DarkGuard UI surface."""
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    if flow.exposure_overview(sid).get("eligible") is not True:
        raise HTTPException(
            status_code=403,
            detail="DarkGuard UI requires evidence-linked external intervention.",
        )

    body = await _darkguard_ui_body(request)
    path = "/" + upstream_path
    raw_path = request.scope.get("raw_path")
    if isinstance(raw_path, bytes) and raw_path.startswith(b"/api/darkguard/ui"):
        raw_path = raw_path[len(b"/api/darkguard/ui"):]
    try:
        result = await darkguard.ui_request(
            request.method,
            path,
            body=body,
            params=request.query_params.multi_items(),
            raw_path=raw_path,
        )
    except darkguard.UIRequestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return Response(
        content=result.content,
        status_code=result.status_code,
        media_type=result.media_type,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/investigations/{iid}/start")
async def start_investigation(iid: str,
                              x_sentinel_session: str | None = Header(default=None),
                              x_sentinel_token: str | None = Header(default=None),
                              authorization: str | None = Header(default=None)):
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    result = flow.start_investigation(iid, requested_by="analyst")
    if not result.get("ok"):
        status = 404 if result.get("reason") == "incident_not_found" else 409
        raise HTTPException(status_code=status, detail=result)
    return result


@app.get("/api/investigations/{iid}")
async def get_incident_investigation(iid: str,
                                     x_sentinel_session: str | None = Header(default=None),
                                     x_sentinel_token: str | None = Header(default=None),
                                     authorization: str | None = Header(default=None)):
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    job = flow.investigation_for_incident(iid)
    return {"ok": bool(job), "job": job}


@app.get("/api/investigation-jobs/{jid}")
async def get_investigation_job(jid: str,
                                x_sentinel_session: str | None = Header(default=None),
                                x_sentinel_token: str | None = Header(default=None),
                                authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    result = flow.get_investigation(jid)
    if result.get("ok"):
        inc = store.get_incident(result["job"].get("incident_id", ""))
        if not inc or inc.signals.get("session_id") != sid:
            raise HTTPException(status_code=404, detail="investigation job not found in this session")
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@app.get("/api/attribution/live/services")
async def attribution_live_services(x_sentinel_session: str | None = Header(default=None),
                                    x_sentinel_token: str | None = Header(default=None),
                                    authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await darkguard.attribution("GET", "live/services")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/attribution/live/start")
async def attribution_live_start(body: dict,
                                 x_sentinel_session: str | None = Header(default=None),
                                 x_sentinel_token: str | None = Header(default=None),
                                 authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await darkguard.attribution("POST", "live/start", body=body)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/attribution/live/job/{job_id}")
async def attribution_live_job(job_id: str, after: int = 0,
                               x_sentinel_session: str | None = Header(default=None),
                               x_sentinel_token: str | None = Header(default=None),
                               authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await darkguard.attribution("GET", f"live/job/{job_id}", params={"after": after})
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/attribution/live/compare")
async def attribution_live_compare(body: dict,
                                   x_sentinel_session: str | None = Header(default=None),
                                   x_sentinel_token: str | None = Header(default=None),
                                   authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await darkguard.attribution("POST", "live/compare", body=body)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/attribution/categorise")
async def attribution_categorise(body: dict,
                                 x_sentinel_session: str | None = Header(default=None),
                                 x_sentinel_token: str | None = Header(default=None),
                                 authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await darkguard.attribution("POST", "categorise", body=body)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/orchestrator/status")
async def orchestrator_status(x_sentinel_session: str | None = Header(default=None),
                              x_sentinel_token: str | None = Header(default=None),
                              authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    return orchestrator.status(sid)


@app.get("/api/orchestrator/incidents/{iid}")
async def orchestrator_plan(iid: str,
                            x_sentinel_session: str | None = Header(default=None),
                            x_sentinel_token: str | None = Header(default=None),
                            authorization: str | None = Header(default=None)):
    _authorize_incident(iid, x_sentinel_session or "", x_sentinel_token, authorization)
    plan = orchestrator.get_plan(iid)
    if not plan:
        raise HTTPException(status_code=404, detail="orchestrator plan not found")
    return plan


@app.post("/api/console")
async def console_ep(body: dict,
                     x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    """Analyst console — fixed auditable commands, never arbitrary tool execution."""
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    iid = body.get("incident_id")
    if iid:
        _authorize_incident(iid, sid, x_sentinel_token, authorization)
    return await flow.console(body.get("message", ""), iid)


@app.get("/api/gaps")
async def gaps_ep():
    """Existing solutions, loopholes, and SENTINEL anti-requirements (landscape)."""
    return flow.gaps()


class GatewayAction(BaseModel):
    session_id: str
    agent_id: str
    user: str = "service"
    process_name: str
    pid: int = 0
    parent_id: str = ""
    tool: str
    args: str = ""
    scope: str
    destination: str = ""
    payload_excerpt: str = ""
    resource_hash: str = ""
    trust_level: str = "trusted"
    approval_id: str = ""
    approval_token: str = ""


@app.post("/api/gateway/action")
async def gateway_action(body: GatewayAction,
                         x_sentinel_token: str | None = Header(default=None),
                         authorization: str | None = Header(default=None)):
    """Authoritative pre-execution gate for managed agents.

    ALLOW/WARN => execute=true. DENY/REQUIRE_APPROVAL => execute=false. The
    gateway also returns a trusted re-ground message; callers must not execute
    without an affirmative response.
    """
    sess = _authorize(body.session_id, x_sentinel_token, authorization)
    mf = manifest.get(body.session_id)
    if not manifest.agent_allowed(mf, body.agent_id, body.process_name, body.pid):
        raise HTTPException(status_code=403, detail="Agent identity/process is not registered for this session.")
    state = flow.get_agent_state(body.session_id, body.agent_id)
    if not state:
        raise HTTPException(status_code=403, detail="Agent capability state is unavailable.")
    if state.get("quarantined"):
        quarantine_state = state.get("quarantine") or {}
        return {
            "decision": "deny", "execute": False, "quarantined": True,
            "reground_required": bool(state.get("reground_required")),
            "capability_epoch": state.get("capability_epoch"),
            "reason": quarantine_state.get("reason") or "agent is quarantined",
            "rule_ids": ["AG-03", "AG-35", "AG-44"],
            "policy_version": policy.version(),
            "reminder": {"objective": mf.get("task"), "instruction": "This agent is quarantined. Stop all tool use and await analyst release."},
        }
    if state.get("reground_required"):
        return {
            "decision": "deny", "execute": False, "quarantined": False,
            "reground_required": True,
            "capability_epoch": state.get("capability_epoch"),
            "reason": "Authenticated re-ground acknowledgment is required before another Gateway action.",
            "rule_ids": ((state.get("reground_context") or {}).get("rule_ids") or []),
            "policy_version": policy.version(),
            "trusted_context": state.get("reground_context"),
            "ack_endpoint": f"/api/sessions/{body.session_id}/agents/{body.agent_id}/reground/ack",
        }

    capability_epoch = int(state.get("capability_epoch", 1))
    binding = flow.action_binding(
        body.session_id, body.agent_id, body.tool, body.args, body.scope,
        body.destination, body.resource_hash, capability_epoch,
    )
    approved = bool(body.approval_id and flow.consume_approval(
        body.session_id, body.approval_id, body.approval_token, binding
    ))
    ev = Event(
        source="agent", session_id=body.session_id, parent_id=body.parent_id,
        host=sess["target_host"], user=body.user, event_type="action_proposed",
        trust_level=body.trust_level,
        process=Process(name=body.process_name, pid=body.pid),
        destination=Destination(host=body.destination),
        payload_excerpt=body.payload_excerpt, tool=body.tool,
        tool_args=body.args, scope=body.scope,
        meta={"agent_id": body.agent_id, "gateway_mediated": True, "explicit_approval": approved},
    )
    flow.touch_heartbeat(body.session_id)
    result = await ingest(ev)
    event = result["event"]
    decision = event.get("meta", {}).get("guardian", {})
    approval = None
    if decision.get("decision") == "require_approval":
        approval = flow.request_approval(
            body.session_id, event["id"], body.agent_id, binding,
            f"{body.tool}({body.args}) · {body.scope} · {body.destination}",
            decision.get("rule_ids", []),
        )
    state_after = flow.get_agent_state(body.session_id, body.agent_id) or {}
    can_issue = bool(decision.get("execute")) and not state_after.get("quarantined") \
        and not state_after.get("reground_required")
    capability = execution.issue({
        "session_id": body.session_id, "agent_id": body.agent_id,
        "tool": body.tool, "args": body.args, "scope": body.scope,
        "destination": body.destination, "resource_hash": body.resource_hash,
    }, capability_epoch=int(state_after.get("capability_epoch", capability_epoch))) if can_issue else None
    trusted_context = state_after.get("reground_context") if state_after.get("reground_required") else None
    return {
        "action_id": event["id"],
        "incident_id": result["incident"]["incident_id"],
        **decision,
        "execute": bool(decision.get("execute")) and can_issue,
        "approval": approval,
        "execution_capability": capability,
        "classification": result["incident"].get("classification", "unresolved"),
        "classification_basis": result["incident"].get("signals", {}).get("classification", {}),
        "quarantined": bool(state_after.get("quarantined")),
        "reground_required": bool(state_after.get("reground_required")),
        "capability_epoch": state_after.get("capability_epoch"),
        "trusted_context": trusted_context,
        "reminder": trusted_context or decision.get("reminder"),
        "ack_endpoint": (f"/api/sessions/{body.session_id}/agents/{body.agent_id}/reground/ack"
                         if trusted_context else None),
        "coverage_mode": "gateway",
        "scope_note": "Enforcement applies to actions routed through this gateway; observe-only paths are detection, not containment.",
    }


class GatewayCommit(BaseModel):
    session_id: str
    agent_id: str
    tool: str
    args: str = ""
    scope: str
    destination: str = ""
    resource_hash: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    execution_token: str


@app.post("/api/gateway/commit")
async def gateway_commit(body: GatewayCommit,
                         x_sentinel_token: str | None = Header(default=None),
                         authorization: str | None = Header(default=None)):
    """Single-use TOCTOU revalidation immediately before external execution."""
    sess = _authenticate_session(body.session_id, x_sentinel_token, authorization)
    if sess.get("status") == "monitoring":
        try:
            flow.require_monitoring(body.session_id)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    agent_state = flow.get_agent_state(body.session_id, body.agent_id)
    result = execution.commit(body.execution_token, {
        "session_id": body.session_id, "agent_id": body.agent_id,
        "tool": body.tool, "args": body.args, "scope": body.scope,
        "destination": body.destination, "resource_hash": body.resource_hash,
    }, body.redirect_chain, agent_state=agent_state, session_status=str(sess.get("status") or "inactive"))
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result)
    return result


@app.post("/api/events")
async def post_event(ev: Event,
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    """Authenticated sensor ingest for a verified monitoring session."""
    sess = _authorize(ev.session_id, x_sentinel_token, authorization)
    agent_id = str(ev.meta.get("agent_id") or ev.process.name)
    if ev.source == "agent" and not manifest.agent_allowed(manifest.get(ev.session_id), agent_id, ev.process.name, ev.process.pid):
        raise HTTPException(status_code=403, detail="Event agent/process is outside the registered monitoring scope.")
    flow.touch_heartbeat(ev.session_id)
    return await ingest(ev)


class ScanIn(BaseModel):
    text: str


@app.post("/api/scan")
async def scan_text(body: ScanIn,
                    x_sentinel_session: str | None = Header(default=None),
                    x_sentinel_token: str | None = Header(default=None),
                    authorization: str | None = Header(default=None)):
    """Ad-hoc local payload inspection inside a verified session."""
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    findings = detect.scan(body.text)
    return {"findings": [json.loads(f.model_dump_json()) for f in findings],
            "raw_payload_stored": False}


# --------------------------------------------------------------- Exposure panel
# The overview is populated only by a lineage-qualified external response plan.
@app.get("/api/exposure/overview")
async def exposure_overview(x_sentinel_session: str | None = Header(default=None),
                            x_sentinel_token: str | None = Header(default=None),
                            authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    orchestrator.status(sid)  # refresh job-derived stage and next_view state
    return flow.exposure_overview(sid)


# --------------------------------------------------------------- Tor Finder
# Onion browser proxied directly to the DarkGuard scraper (/tor/*), exactly like
# darkguard.in's backend passthrough. Session-authenticated, but intentionally
# NOT gated on external-intervention eligibility, so the onion browser works
# whenever Tor (:9050) and the scraper (:9000) are running.
class TorSearchIn(BaseModel):
    query: str
    engines: list[str] = Field(default_factory=lambda: ["ahmia", "tor66"])
    limit: int = 2


class TorOpenIn(BaseModel):
    url: str


@app.get("/api/tor/ip")
async def tor_ip(x_sentinel_session: str | None = Header(default=None),
                 x_sentinel_token: str | None = Header(default=None),
                 authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await torfinder.ip()
    except torfinder.TorFinderError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.post("/api/tor/newnym")
async def tor_newnym(x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    try:
        return await torfinder.newnym()
    except torfinder.TorFinderError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.post("/api/tor/search")
async def tor_search(body: TorSearchIn,
                     x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    query = (body.query or "").strip()
    if len(query) < 2:
        raise HTTPException(status_code=400, detail="query required (min 2 characters)")
    try:
        return await torfinder.search(query, body.engines, body.limit)
    except torfinder.TorFinderError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@app.post("/api/tor/open")
async def tor_open(body: TorOpenIn,
                   x_sentinel_session: str | None = Header(default=None),
                   x_sentinel_token: str | None = Header(default=None),
                   authorization: str | None = Header(default=None)):
    _authorize(x_sentinel_session or "", x_sentinel_token, authorization)
    url = (body.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    try:
        return await torfinder.open_url(url)
    except torfinder.TorFinderError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


# DarkGuard-style surface-web sweep. Real data: XposedOrNot (email breaches) +
# crt.sh (certificate-transparency subdomain / brand discovery). Mirrors the
# DarkGuard /scans shape so the ported Exposure pages work unchanged.
@app.post("/api/scans")
async def create_scan(body: dict,
                      x_sentinel_session: str | None = Header(default=None),
                      x_sentinel_token: str | None = Header(default=None),
                      authorization: str | None = Header(default=None)):
    """Create a real exposure scan inside a verified monitoring session."""
    sid = x_sentinel_session or body.get("session_id", "")
    sess = _authorize(sid, x_sentinel_token, authorization)
    raw = str(body.get("targetUrl") or body.get("email") or body.get("query") or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="email, targetUrl or query required")
    # Domain/email scans must stay on the verified organization namespace.
    kind = exposure.detect_kind(raw)
    if kind == "website":
        domain = exposure.bare_domain(raw)
        if domain != sess["target_host"] and not domain.endswith("." + sess["target_host"]):
            raise HTTPException(status_code=403, detail="Domain is outside the verified monitoring target.")
    if kind == "email":
        domain = raw.rsplit("@", 1)[-1].lower()
        if domain != sess["target_host"] and not domain.endswith("." + sess["target_host"]):
            raise HTTPException(status_code=403, detail="Email domain is outside the verified monitoring target.")
    body = {**body, "session_id": sid}
    return exposure.create_scan(body)


@app.get("/api/scans")
async def list_scans(x_sentinel_session: str | None = Header(default=None),
                     x_sentinel_token: str | None = Header(default=None),
                     authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    return exposure.list_scans(sid)


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str,
                   x_sentinel_session: str | None = Header(default=None),
                   x_sentinel_token: str | None = Header(default=None),
                   authorization: str | None = Header(default=None)):
    sid = x_sentinel_session or ""
    _authorize(sid, x_sentinel_token, authorization)
    result = exposure.get_scan(scan_id, sid)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


class CopilotIn(BaseModel):
    question: str
    incident_id: str | None = None


@app.post("/api/copilot")
async def copilot(body: CopilotIn):
    if body.incident_id:
        inc = store.get_incident(body.incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="incident not found")
        report = investigate.report(inc, store.events_by_ids(inc.event_ids))
        ctx = json.dumps({"timeline": report["timeline"], "findings": report["findings"],
                          "recommended_action": report["recommended_action"]}, ensure_ascii=False)
        result = await triage.copilot(body.question, ctx)
        citations = report["cited_event_ids"]
        if result.get("used_llm") and not any(eid in result.get("answer", "") for eid in citations):
            result = {"answer": report["summary"] + " Citations: " + ", ".join(citations),
                      "model": "deterministic-citation-guard", "used_llm": False,
                      "rejected_llm_output": "no event citation"}
        return {**result, "cited_event_ids": citations, "evidence_only": True,
                "facts_source": "deterministic incident report"}
    return {"answer": "Bind an incident before asking for an evidence-grounded explanation.",
            "used_llm": False, "cited_event_ids": [], "evidence_only": True}


@app.post("/api/ingest/upload")
async def upload(file: UploadFile,
                 x_sentinel_session: str | None = Header(default=None),
                 x_sentinel_token: str | None = Header(default=None),
                 authorization: str | None = Header(default=None)):
    """Accept an authorized HAR or JSONL request log. PCAP is not claimed here."""
    sid = x_sentinel_session or ""
    sess = _authorize(sid, x_sentinel_token, authorization)
    raw_bytes = await file.read()
    if len(raw_bytes) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Upload exceeds 20 MiB.")
    raw = raw_bytes.decode("utf-8", errors="ignore")
    name = (file.filename or "").lower()
    if not (name.endswith(".har") or name.endswith(".json") or name.endswith(".jsonl")):
        raise HTTPException(status_code=400, detail="Supported uploads: HAR, JSON, JSONL.")
    events = _parse_har(raw) if name.endswith(".har") or raw.lstrip().startswith("{\"log\"") else _parse_jsonl(raw)
    out = []
    for ev in events:
        ev.session_id = sid
        ev.host = sess["target_host"]
        out.append(await ingest(ev))
        await asyncio.sleep(0.02)
    flow.touch_heartbeat(sid)
    return {"ingested": len(out), "session_id": sid, "source": "authorized upload"}


def _parse_har(raw: str) -> list[Event]:
    try:
        har = json.loads(raw)
        entries = har.get("log", {}).get("entries", [])
    except Exception:
        return []
    out = []
    for e in entries:
        req = e.get("request", {})
        url = req.get("url", "")
        host = url.split("/")[2] if "://" in url else ""
        body = (req.get("postData", {}) or {}).get("text", "")
        out.append(Event(source="upload", event_type="http_request",
                         process=Process(name="browser", pid=0),
                         destination=Destination(host=host, port=443 if url.startswith("https") else 80),
                         payload_excerpt=body[:2000]))
    return out


def _parse_jsonl(raw: str) -> list[Event]:
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(Event(**json.loads(line)))
        except Exception:
            continue
    return out


# Runtime starts empty. Monitoring data enters only through a verified session's
# authenticated sensor or Gateway endpoints; no demo/seed route is registered.

@app.websocket("/ws")
async def ws(socket: WebSocket):
    sid = socket.query_params.get("session_id", "")
    token = socket.query_params.get("token", "")
    await socket.accept()
    if not flow.token_valid(sid, token):
        await socket.close(code=4401, reason="verified monitoring session required")
        return
    try:
        flow.require_monitoring(sid)
    except ValueError as exc:
        await socket.close(code=4403, reason=str(exc))
        return
    q = store.subscribe()
    try:
        await socket.send_json({"type": "snapshot",
                                "stats": store.stats(sid),
                                "incidents": [json.loads(i.model_dump_json()) for i in store.recent_incidents(50, sid)],
                                "events": [json.loads(e.model_dump_json()) for e in store.recent_events(50, sid)]})
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=30)
            except TimeoutError:
                try:
                    flow.require_monitoring(sid)
                except ValueError as exc:
                    await socket.close(code=4403, reason=str(exc))
                    return
                continue
            if msg.get("event", {}).get("session_id") == sid:
                await socket.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        store.unsubscribe(q)


@app.on_event("startup")
async def start_registered_monitors():
    """Restore canonical plans, eligible investigation jobs, and URL monitors."""
    for session in flow.SESSIONS.values():
        sid = session["session_id"]
        evidence = store.read_session_evidence(sid)["events"]
        for incident in store.session_incidents(sid):
            classification.apply(incident, evidence)
            incident_events = store.events_by_ids_durable(incident.event_ids, sid)
            if session.get("status") == "monitoring" and incident_events:
                orchestrator.on_incident(incident, incident_events[-1])
            store.upsert_incident(incident)

        if session.get("status") != "monitoring":
            continue
        try:
            flow.require_monitoring(sid)
        except ValueError:
            continue
        monitor.start(sid, session["target"], flow.update_target_health)
    await flow.resume_investigations()
