"""APEX INJECTION GUARD — signal producer at context ingress.

Scans untrusted content entering an agent (web pages, docs, tool output) for
prompt-injection indicators. It NEVER blocks on its own; it raises a session taint
score that Guardian reads at action egress. A missed detection still leaves the
baseline policy in force.
"""
from __future__ import annotations

import re

from .models import Behavior

INDICATORS: list[tuple[str, re.Pattern]] = [
    ("override_instructions", re.compile(r"(?i)ignore (all |the )?(previous|prior|above) (instructions|prompts)")),
    ("disregard", re.compile(r"(?i)disregard (your|all|previous) (rules|instructions|guidelines)")),
    ("reveal_system", re.compile(r"(?i)(print|reveal|show|repeat) (your |the )?(system prompt|instructions|rules)")),
    ("role_hijack", re.compile(r"(?i)you are now|from now on you are|act as (an?|the) ")),
    ("exfil_command", re.compile(r"(?i)(send|upload|exfiltrate|post|email|copy|transfer)\b[^.]{0,40}(\.env|secret|credential|password|api[_ ]?key|document|confidential|customer|database)")),
    ("fetch_and_run", re.compile(r"(?i)(curl|wget|fetch|invoke-webrequest)\s+https?://")),
    ("read_secret", re.compile(r"(?i)(read|open|cat|get-content).{0,20}(\.env|id_rsa|\.ssh|credentials)")),
    ("tool_hijack", re.compile(r"(?i)(call|use) the (run_shell|http_get|exec) tool")),
]


def scan(text: str) -> dict:
    """Return {indicators, taint, behavior|None}. Taint is additive, capped at 100."""
    if not text:
        return {"indicators": [], "taint": 0, "behavior": None}
    hits = [name for name, rx in INDICATORS if rx.search(text)]
    if not hits:
        return {"indicators": [], "taint": 0, "behavior": None}
    taint = min(100, 35 * len(hits))
    sev = "critical" if taint >= 70 else "high"
    beh = Behavior(type="injection_suspected", severity=sev,
                   detail=f"Prompt-injection indicators in untrusted content: {', '.join(hits)}",
                   target=",".join(hits))
    return {"indicators": hits, "taint": taint, "behavior": beh}
