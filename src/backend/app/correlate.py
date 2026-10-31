"""Graph-based Risk Correlation Engine (the core differentiator).

Joins related events (same session, or same host+process within a window, plus
parent/child lineage) into a single Incident with an evidence graph. Beyond time
windows it links evidence structurally:
  - HMAC fingerprint match: a secret read from a file that reappears in a payload
    -> provable file->provider exfiltration edge.
  - Canary token in a payload -> confirmed exfiltration.
  - Injection-at-ingress -> Guardian decision at egress -> outcome (contained/exposed).
"""
from __future__ import annotations

import time

from . import coverage
from . import score as scoring
from . import triage
from .models import Event, GraphEdge, GraphNode, Incident

WINDOW_SECONDS = 180


class Correlator:
    def __init__(self) -> None:
        self._open: list[tuple[float, Incident]] = []
        self._fstore: dict[str, list] = {}   # iid -> [(event_id, Finding)]
        self._bstore: dict[str, list] = {}   # iid -> [(event_id, Behavior)]

    def _find_open(self, ev: Event) -> Incident | None:
        now = time.time()
        self._open = [(t, i) for (t, i) in self._open if now - t <= WINDOW_SECONDS]
        for _, inc in reversed(self._open):
            if ev.session_id:
                if inc.signals.get("session_id") == ev.session_id:
                    return inc
                continue  # never cross-link two explicit sessions by PID/host
            same_host = inc.host == ev.host
            same_proc = ev.process.pid and inc.signals.get("pid") == ev.process.pid
            related = ev.process.parent and ev.process.parent == inc.signals.get("process_name")
            if same_host and (same_proc or related):
                return inc
        return None

    def ingest(self, ev: Event) -> Incident:
        inc = self._find_open(ev)
        if inc is None:
            inc = Incident(host=ev.host, signals={
                "session_id": ev.session_id, "pid": ev.process.pid,
                "process_name": ev.process.name, "approval": ev.destination.approval,
                "local_llm": ev.destination.local_llm, "providers": [], "data_leak": [],
                "agent_behavior": [], "destinations": [], "_provider_eids": [],
            })

        inc.event_ids.append(ev.id)
        self._merge(inc, ev)
        self._graph(inc, ev)
        self.finalize(inc)

        self._open = [(t, i) for (t, i) in self._open if i.incident_id != inc.incident_id]
        self._open.append((time.time(), inc))
        return inc

    def finalize(self, inc: Incident) -> None:
        """Recompute status, score and narrative from stored evidence. Idempotent,
        so DarkGuard enrichment can call it again after attaching exposure."""
        f_ev = self._fstore.get(inc.incident_id, [])
        b_ev = self._bstore.get(inc.incident_id, [])

        canary = any(f.type == "canary" for _, f in f_ev)
        read_fps = {fp for _, b in b_ev for fp in b.fingerprints}
        leak_fps = {f.fingerprint for _, f in f_ev if f.fingerprint}
        fp_match = bool(read_fps & leak_fps)

        guardian_decisions = [b for _, b in b_ev if b.type == "policy_decision"]
        guardian_denied = any(b.target in ("deny", "pause", "require_approval") for b in guardian_decisions)
        inc.mode = "gateway" if guardian_decisions else "observe"
        inc.taint = 70 if any(b.type == "injection_suspected" for _, b in b_ev) else 0
        inc.guardian = [{"decision": b.target, "reason": b.detail} for b in guardian_decisions]

        has_leak = any(f.type != "injection" for _, f in f_ev)
        exposed = canary or fp_match or (has_leak and not guardian_denied)
        inc.status = "exposed" if exposed else ("contained" if guardian_denied else "open")

        if fp_match:
            self._add_exfil_edge(inc)

        res = scoring.score_incident(inc.signals, f_ev, b_ev, inc.darkguard, canary, fp_match)
        inc.score, inc.level = res["score"], res["level"]
        inc.score_reasons, inc.fired_rules = res["reasons"], res["fired_rules"]

        inc.problems = coverage.problems_for([b for _, b in b_ev], inc.signals)
        inc.title = self._title(inc, canary, fp_match)
        # Canonical cause/classification is applied from complete durable event
        # lineage after this correlator pass. Never infer it from co-presence.
        if not inc.signals.get("classification"):
            inc.classification = "unresolved"
            inc.cause = "unresolved"
        inc.remediation = self._remediation(inc)
        inc.ai_explanation = triage.explain(inc, [f for _, f in f_ev], [b for _, b in b_ev])

    def _collect_findings(self, inc): return [f for _, f in self._fstore.get(inc.incident_id, [])]
    def _collect_behaviors(self, inc): return [b for _, b in self._bstore.get(inc.incident_id, [])]

    def _merge(self, inc: Incident, ev: Event) -> None:
        s = inc.signals
        if ev.destination.provider and ev.destination.provider != "unknown":
            if ev.destination.provider not in s["providers"]:
                s["providers"].append(ev.destination.provider)
            s["approval"] = ev.destination.approval
            s["local_llm"] = s["local_llm"] or ev.destination.local_llm
            if ev.id not in s["_provider_eids"]:
                s["_provider_eids"].append(ev.id)
        if ev.destination.host and ev.destination.host not in s["destinations"]:
            s["destinations"].append(ev.destination.host)
        for f in ev.findings:
            if f.label not in s["data_leak"]:
                s["data_leak"].append(f.label)
        for b in ev.behavior:
            if b.type not in s["agent_behavior"]:
                s["agent_behavior"].append(b.type)
        self._fstore.setdefault(inc.incident_id, []).extend((ev.id, f) for f in ev.findings)
        self._bstore.setdefault(inc.incident_id, []).extend((ev.id, b) for b in ev.behavior)

    def _graph(self, inc: Incident, ev: Event) -> None:
        nodes = {n["id"]: n for n in inc.graph["nodes"]}
        edges = {(e["src"], e["dst"], e["rel"]) for e in inc.graph["edges"]}

        def node(nid, kind, label):
            if nid not in nodes:
                nodes[nid] = GraphNode(id=nid, kind=kind, label=label).model_dump()

        def edge(src, dst, rel):
            if (src, dst, rel) not in edges:
                edges.add((src, dst, rel))
                inc.graph["edges"].append(GraphEdge(src=src, dst=dst, rel=rel).model_dump())

        pid = f"proc:{ev.process.name}:{ev.process.pid}"
        node(pid, "process", f"{ev.process.name} (pid {ev.process.pid})")
        if ev.process.parent:
            par = f"proc:{ev.process.parent}"
            node(par, "process", ev.process.parent); edge(par, pid, "spawned")
        if ev.destination.provider and ev.destination.provider != "unknown":
            prov = f"prov:{ev.destination.provider}"
            node(prov, "provider", ev.destination.provider); edge(pid, prov, "connected_to")
            for f in ev.findings:
                fn = f"leak:{f.label}"
                node(fn, "pii" if f.type == "pii" else ("anomaly" if f.type == "canary" else "secret"), f.label)
                edge(pid, fn, "leaked"); edge(fn, prov, "sent_to")
        for b in ev.behavior:
            if b.type == "policy_decision":
                dn = f"decision:{b.target}"
                node(dn, "behavior", f"Guardian: {b.target}"); edge(pid, dn, "gated_by")
                continue
            kind = "injection" if b.type == "injection_suspected" else "behavior"
            bn = f"beh:{b.type}"
            node(bn, kind, b.detail[:28]); edge(pid, bn, "performed")
            if b.target and b.type == "sensitive_file_read":
                tn = f"file:{b.target}"; node(tn, "file", b.target); edge(pid, tn, "accessed")
        inc.graph["nodes"] = list(nodes.values())

    def _add_exfil_edge(self, inc: Incident) -> None:
        files = [n["id"] for n in inc.graph["nodes"] if n["kind"] == "file"]
        provs = [n["id"] for n in inc.graph["nodes"] if n["kind"] == "provider"]
        dests = provs or [n["id"] for n in inc.graph["nodes"] if n["kind"] == "secret"]
        have = {(e["src"], e["dst"], e["rel"]) for e in inc.graph["edges"]}
        for fsrc in files:
            for d in dests:
                if (fsrc, d, "exfiltrated") not in have:
                    inc.graph["edges"].append(GraphEdge(src=fsrc, dst=d, rel="exfiltrated").model_dump())

    def _title(self, inc: Incident, canary: bool, fp: bool) -> str:
        s = inc.signals
        proc = s.get("process_name") or "a process"
        prov = s["providers"][0] if s["providers"] else (s["destinations"][0] if s["destinations"] else "an AI tool")
        if canary:
            return f"CONFIRMED exfiltration — canary token from {proc} reached {prov}"
        if fp:
            return f"CONFIRMED exfiltration — secret read by {proc} reappeared at {prov}"
        if inc.status == "contained":
            return f"Guardian blocked an out-of-policy agent action in {proc}"
        leaks = ", ".join(s["data_leak"][:2]) if s["data_leak"] else None
        beh = next((b.replace("_", " ") for b in s["agent_behavior"] if b != "policy_decision"), None)
        if leaks and beh:
            return f"{proc} leaked {leaks} to {prov} while performing {beh}"
        if leaks:
            return f"{proc} sent {leaks} to unapproved {prov}"
        if beh:
            return f"{proc} showed risky agent behaviour: {beh}"
        return f"{proc} contacted {prov}"

    def _cause(self, inc: Incident, confirmed: bool) -> str:
        """Compatibility accessor; classification is applied from durable lineage."""
        recorded = inc.signals.get("classification") or {}
        return recorded.get("value", "unresolved")

    def _remediation(self, inc: Incident) -> list[str]:
        s = inc.signals
        out: list[str] = []
        if inc.status == "contained":
            out.append("Action was blocked pre-execution by Guardian — review the injected content source and keep the session quarantined")
        if any(k in str(s["data_leak"]) for k in ("Key", "Token", "Secret", "Canary")):
            out.append("Rotate the exposed credential immediately and purge the AI chat/history")
        if s["approval"] == "unapproved" and s["destinations"]:
            out.append(f"Block {s['destinations'][0]} for this host or add it to the approved allowlist")
        if any(x in ("Aadhaar", "PAN", "Credit Card") for x in s["data_leak"]):
            out.append("File a DPDP exposure note — regulated personal data left the endpoint")
        if "sensitive_file_read" in s["agent_behavior"]:
            out.append("Revoke the agent's file-system scope and tighten its capability manifest")
        if not out:
            out.append("Review the AI tool against policy and confirm it is sanctioned")
        return out
