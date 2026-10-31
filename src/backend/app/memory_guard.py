"""APEX MEMORY GUARD — origin-bound provenance on write and retrieval.

Content is never retained here, only its hash and authority metadata. Derived
records inherit the *lowest* trust of all inputs and the complete contributing
source-ID set. Trusted-agent/tool echoes never launder an untrusted origin.
"""
from __future__ import annotations

import hashlib

from . import injection_guard
from .models import Behavior

# memory_id -> provenance metadata (no raw content)
_STORE: dict[str, dict] = {}
_TRUST = {"untrusted": 0, "unknown": 1, "trusted": 2}


def _h(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def _least(values: list[str]) -> str:
    clean = [v if v in _TRUST else "unknown" for v in values]
    return min(clean, key=lambda v: _TRUST[v]) if clean else "unknown"


def write(memory_id: str, text: str, source: str, session_tainted: bool,
          source_ids: list[str] | None = None, input_trusts: list[str] | None = None,
          derived_from: list[str] | None = None) -> dict:
    """Inspect and write authority metadata. Untrusted taint is non-malleable."""
    ig = injection_guard.scan(text)
    source_trust = "untrusted" if source in ("web", "tool_output", "email", "document", "agent_message") else "trusted"
    inherited_trusts = list(input_trusts or [])
    origins = set(source_ids or [])
    origins.add(source or "unknown")
    for parent_id in derived_from or []:
        parent = _STORE.get(parent_id)
        if parent:
            inherited_trusts.append(parent.get("trust", "unknown"))
            origins.update(parent.get("origin_source_ids") or [])

    suspicious = bool(ig["indicators"]) or session_tainted
    trust = _least([source_trust, *inherited_trusts, "untrusted" if suspicious else "trusted"])
    prev = _STORE.get(memory_id)
    _STORE[memory_id] = {
        "content_hash": _h(text),
        "original_source": source,
        "origin_source_ids": sorted(origins),
        "derived_from": list(derived_from or []),
        "trust": trust,
        "taint": max(ig["taint"] if suspicious else 0,
                     max((int(_STORE.get(p, {}).get("taint", 0)) for p in derived_from or []), default=0)),
        "version": (prev["version"] + 1) if prev else 1,
        "raw_content_stored": False,
        "trust_auto_upgrade_allowed": False,
    }
    behavior = None
    if trust == "untrusted":
        behavior = Behavior(
            type="memory_write_suspected", severity="critical", target=memory_id,
            detail=(f"Untrusted authority bound to memory '{memory_id}' (origin {source}; "
                    f"sources {', '.join(sorted(origins))}; "
                    f"{', '.join(ig['indicators']) or 'inherited/session taint'})"),
        )
    return {"trust": trust, "behavior": behavior,
            "provenance": {k: v for k, v in _STORE[memory_id].items() if k != "content_hash"},
            "content_hash": _STORE[memory_id]["content_hash"]}


def retrieve(memory_id: str) -> dict:
    """Revalidate recalled memory against its origin-bound authority."""
    rec = _STORE.get(memory_id)
    if not rec:
        return {"trust": "unknown", "taint": 0, "behavior": None,
                "visibility": "record unavailable"}
    if rec["trust"] != "trusted":
        beh = Behavior(
            type="memory_retrieval_untrusted", severity="high", target=memory_id,
            detail=(f"Agent recalled {rec['trust']} memory '{memory_id}'; original sources "
                    f"{', '.join(rec.get('origin_source_ids') or ['unknown'])}; trust was not upgraded by copies/echoes"),
        )
        return {"trust": rec["trust"], "taint": max(60, rec["taint"]), "behavior": beh,
                "provenance": rec, "visibility": "available"}
    return {"trust": "trusted", "taint": 0, "behavior": None,
            "provenance": rec, "visibility": "available"}
