"""The eight AI-agent security problems and how observed signals map to them.

Used to tag each incident with the problem(s) it implicates and to render the
coverage matrix on the dashboard.
"""
from __future__ import annotations

PROBLEMS = {
    1: {"name": "Unauthorized tool usage", "module": "Guardian + Tool Gateway", "point": "action egress"},
    2: {"name": "Memory poisoning", "module": "APEX Memory Guard", "point": "memory write + retrieval"},
    3: {"name": "Malicious plugins / tools", "module": "APEX Tool Trust", "point": "tool registration + runtime"},
    4: {"name": "Long-term goal manipulation", "module": "APEX Behaviour Intelligence", "point": "action sequence"},
    5: {"name": "Harmful autonomous actions", "module": "Guardian + sandbox", "point": "action egress"},
    6: {"name": "Indirect prompt injection", "module": "APEX Injection Guard", "point": "content ingress"},
    7: {"name": "Multi-agent comms attacks", "module": "APEX Agent Trust", "point": "agent-to-agent messages"},
    8: {"name": "Identity & permission misuse", "module": "Session Registry + Guardian", "point": "action egress + identity"},
}

# behaviour.type  ->  problem number
BEHAVIOUR_TO_PROBLEM = {
    "injection_suspected": 6,
    "memory_write_suspected": 2,
    "memory_retrieval_untrusted": 2,
    "untrusted_tool": 3,
    "tool_schema_changed": 3,
    "untrusted_agent_message": 7,
    "behaviour_sequence": 4,
    "privilege_inheritance": 8,
    "destructive_action": 5,
    "unauthorized_scope": 1,
    "shell_spawn": 5,
    "dangerous_flag": 5,
    "sensitive_file_read": 8,
    "unregistered_agent": 8,
}


def problems_for(behaviors, signals) -> list[int]:
    found: set[int] = set()
    for b in behaviors:
        if b.type in BEHAVIOUR_TO_PROBLEM:
            found.add(BEHAVIOUR_TO_PROBLEM[b.type])
        # a policy_decision that denied an unauthorized scope -> problem 1
        if b.type == "policy_decision" and "scope" in (b.detail or "").lower():
            found.add(1)
    if signals.get("data_leak") and signals.get("approval") == "unapproved":
        found.add(1)
    return sorted(found)
