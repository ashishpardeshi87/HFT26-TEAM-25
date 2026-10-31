"""Pydantic schemas: the normalized Event, Finding, and the correlated Incident.

Every sensor emits an Event. The correlation engine groups related Events into
one Incident. This single schema is the contract that lets sensors, the backend,
and the dashboard evolve independently.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()) + "+05:30"


def _eid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


Severity = Literal["info", "low", "medium", "high", "critical"]
Approval = Literal["approved", "unapproved", "unknown"]
SourceKind = Literal["process", "packet", "browser", "agent", "upload", "sensor"]
Classification = Literal["self_drift", "external_intervention_suspected", "unresolved"]


class Finding(BaseModel):
    type: Literal["secret", "pii", "entropy", "canary", "injection"]
    label: str
    severity: Severity
    confidence: float = 0.8
    match_masked: str = ""
    fingerprint: str = ""          # HMAC(org_key, secret) — links a file read to a payload leak


class Behavior(BaseModel):
    type: str                      # shell_spawn | sensitive_file_read | dangerous_flag | injection_suspected | policy_decision
    detail: str
    severity: Severity = "high"
    target: str = ""
    fingerprints: list[str] = Field(default_factory=list)  # secrets seen in a read file


class Destination(BaseModel):
    host: str = ""
    ip: str = ""
    port: int = 0
    provider: str = "unknown"
    approval: Approval = "unknown"
    local_llm: bool = False


class Process(BaseModel):
    name: str = ""
    pid: int = 0
    cmdline: str = ""
    parent: str = ""


class Event(BaseModel):
    id: str = Field(default_factory=lambda: _eid("evt"))
    ts: str = Field(default_factory=_now_iso)
    source: SourceKind = "process"
    host: str = ""
    user: str = ""
    session_id: str = ""           # groups one agent task; ties ingress content to egress action
    parent_id: str = ""            # lineage: the event that directly produced this one (causality correction)
    event_type: str = "ai_provider_connection"
    trust_level: str = "trusted"   # trusted | untrusted (web/doc/tool output entering an agent)
    process: Process = Field(default_factory=Process)
    destination: Destination = Field(default_factory=Destination)
    payload_excerpt: str = ""
    # action-egress fields (ACTION_PROPOSED events from the tool gateway)
    tool: str = ""
    tool_args: str = ""
    scope: str = ""                # verb scope: read | write | delete | transmit | transmit-external
    meta: dict[str, Any] = Field(default_factory=dict)  # module-specific: tool_id, memory_id, from_agent...
    findings: list[Finding] = Field(default_factory=list)
    behavior: list[Behavior] = Field(default_factory=list)
    bytes_out: int = 0
    redacted: bool = True


class GraphNode(BaseModel):
    id: str
    kind: str          # process | provider | file | secret | pii | behavior | anomaly
    label: str


class GraphEdge(BaseModel):
    src: str
    dst: str
    rel: str           # spawned | connected_to | accessed | leaked | sent_to | occurred_after


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: _eid("inc"))
    opened: str = Field(default_factory=_now_iso)
    title: str = ""
    host: str = ""
    event_ids: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)
    graph: dict[str, list] = Field(default_factory=lambda: {"nodes": [], "edges": []})
    score: int = 0
    level: Severity = "low"
    status: Literal["exposed", "contained", "open"] = "open"   # did data actually leave?
    mode: Literal["gateway", "observe"] = "observe"            # enforcement vs detection-only
    taint: int = 0
    score_reasons: list[str] = Field(default_factory=list)
    fired_rules: list[dict[str, Any]] = Field(default_factory=list)  # {rule, points, event_ids}
    guardian: list[dict[str, Any]] = Field(default_factory=list)     # policy decisions
    classification: Classification = "unresolved"
    cause: str = "unresolved"  # compatibility alias; structured basis is signals.classification
    problems: list[int] = Field(default_factory=list)   # which of the 8 agent-security problems apply
    ai_explanation: str = ""
    remediation: list[str] = Field(default_factory=list)
    darkguard: Optional[dict[str, Any]] = None


class IngestResult(BaseModel):
    event: Event
    incident: Optional[Incident] = None
