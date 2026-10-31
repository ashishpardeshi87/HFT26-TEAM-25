"""APEX BEHAVIOUR INTELLIGENCE (problem 4) — long-term goal-manipulation detection.

Keeps a per-session action history and flags suspicious SEQUENCES of individually
permitted actions (e.g. read confidential -> connect to an unknown host). The sequence
trips a rule even though each step passed its own policy.
"""
from __future__ import annotations

import re

from .models import Behavior

# session_id -> list of action labels in order
_HISTORY: dict[str, list[str]] = {}

_SENSITIVE_READ = re.compile(r"(?i)(confidential|customer_db|\.env|secret|credential|read_confidential|access_customer)")
_EGRESS = re.compile(r"(?i)(connect_unknown|http_get|transmit|exfil|send_email|external)")


def record(session_id: str, label: str) -> Behavior | None:
    """Append an action and flag a sensitive-read -> egress chain within the session."""
    if not session_id or not label:
        return None
    hist = _HISTORY.setdefault(session_id, [])
    hist.append(label)
    joined = " -> ".join(hist)

    saw_sensitive = any(_SENSITIVE_READ.search(h) for h in hist[:-1])
    now_egress = bool(_EGRESS.search(hist[-1]))
    if saw_sensitive and now_egress and len(hist) >= 2:
        return Behavior(type="behaviour_sequence", severity="high", target=joined[-120:],
                        detail=f"Objective-drift chain: {joined[-120:]}")
    return None
