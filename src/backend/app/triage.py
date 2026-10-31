"""Featherless AI Security Copilot (suggested Featherless usage).

explain()  -> deterministic natural-language incident summary (always works, offline).
copilot()  -> optional richer answer via the Featherless OpenAI-compatible API when
              FEATHERLESS_API_KEY is set; falls back to the deterministic text.

Detection and scoring stay deterministic; the LLM only interprets masked evidence.
"""
from __future__ import annotations

import os

import httpx

FEATHERLESS_BASE = os.getenv("FEATHERLESS_API_BASE", "https://api.featherless.ai/v1")
FEATHERLESS_MODEL = os.getenv("FEATHERLESS_MODEL", "Qwen/Qwen2.5-Coder-32B-Instruct")

CAUSE_TEXT = {
    "self_drift": "an observed Gateway policy deviation; intent is not established",
    "external_intervention_suspected": "external intervention suspected from recorded execution lineage",
    "unresolved": "activity whose cause is unresolved from the recorded lineage",
    "internal_autonomous_deviation": "an autonomous agent acting beyond its intended scope",
    "shadow_ai_data_exposure": "sensitive data sent to an unsanctioned AI tool",
    "unapproved_ai_usage": "use of an unapproved AI service",
    "unknown": "AI-related activity that needs review",
}


def explain(inc, findings, behaviors) -> str:
    """Deterministic, offline incident explanation grounded in masked evidence."""
    s = inc.signals
    prov = ", ".join(s.get("providers") or s.get("destinations") or ["an AI tool"])
    parts = [f"A {inc.level.upper()} incident: {CAUSE_TEXT.get(inc.cause, CAUSE_TEXT['unknown'])}."]
    proc = s.get("process_name") or "A process"
    if s.get("data_leak"):
        parts.append(f"{proc} sent {', '.join(s['data_leak'][:3])} toward {prov}"
                     f" ({s.get('approval', 'unknown')}).")
    else:
        parts.append(f"{proc} contacted {prov} ({s.get('approval', 'unknown')}).")
    if s.get("agent_behavior"):
        parts.append("Agent behaviour observed: " + ", ".join(b.replace("_", " ") for b in s["agent_behavior"]) + ".")
    if inc.darkguard and inc.darkguard.get("exposure_score"):
        parts.append(f"DarkGuard shows this asset already exposed externally "
                     f"(score {inc.darkguard['exposure_score']}).")
    return " ".join(parts)


async def copilot(question: str, context: str) -> dict:
    """Answer an analyst question. Uses Featherless if configured, else a grounded fallback."""
    key = os.getenv("FEATHERLESS_API_KEY", "").strip()
    if not key:
        return {"answer": _fallback_answer(question, context), "model": "offline-fallback", "used_llm": False}

    sys = ("You are SENTINEL APEX, a security analyst summarizer. Use only the supplied "
           "deterministic evidence. Every factual sentence must include the exact event_id it relies on. "
           "You may summarize; you may not establish semantic causation, identity, or facts absent from evidence. "
           "Say 'insufficient evidence' when needed. Never invent values. Secrets are masked. No tools are available.")
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.post(
                f"{FEATHERLESS_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "HTTP-Referer": "https://sentinel-apex.local",
                         "X-Title": "SENTINEL APEX"},
                json={"model": FEATHERLESS_MODEL, "temperature": 0,
                      "messages": [{"role": "system", "content": sys},
                                   {"role": "user", "content": f"EVIDENCE:\n{context}\n\nQUESTION: {question}"}]},
            )
            r.raise_for_status()
            data = r.json()
            return {"answer": data["choices"][0]["message"]["content"].strip(),
                    "model": FEATHERLESS_MODEL, "used_llm": True}
    except Exception as e:  # network/credits/rate-limit -> graceful fallback
        return {"answer": _fallback_answer(question, context),
                "model": f"fallback ({type(e).__name__})", "used_llm": False}


def _fallback_answer(question: str, context: str) -> str:
    q = question.lower()
    if "unapproved" in q or "shadow" in q:
        return "Unapproved AI destinations appear in the incident list below; filter the AI Discovery tab by approval = unapproved."
    if "fix" in q or "remediat" in q or "do" in q:
        return "Prioritise critical incidents: rotate any exposed credential, block the unapproved destination, and file a DPDP note if Aadhaar/PAN/cards were involved."
    if "why" in q or "explain" in q or "critical" in q:
        return "Scores combine destination approval, data-leak severity, agent behaviour, and external exposure. Open any incident to see the per-point scoring reasons."
    return ("Based on recorded evidence: " + (context[:400] if context else "no incidents yet."))
