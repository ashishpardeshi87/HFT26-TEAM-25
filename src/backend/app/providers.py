"""AI-provider fingerprinting + Shadow AI classification (PS requirement 2).

Resolves a connection (host / ip / port) to a known AI provider, including local
LLM servers by port, then classifies it approved / unapproved / unknown against an
org allowlist. A provider match alone is not a verdict of exfiltration.
"""
from __future__ import annotations

import os

# host substring -> provider display name
CLOUD_PROVIDERS: dict[str, str] = {
    "api.openai.com": "OpenAI",
    "chatgpt.com": "OpenAI (ChatGPT)",
    "openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "claude.ai": "Anthropic (Claude)",
    "generativelanguage.googleapis.com": "Google Gemini",
    "gemini.google.com": "Google Gemini",
    "api2.cursor.sh": "Cursor",
    "cursor.sh": "Cursor",
    "api.githubcopilot.com": "GitHub Copilot",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot",
    "huggingface.co": "Hugging Face",
    "hf.co": "Hugging Face",
    "api.mistral.ai": "Mistral",
    "api.perplexity.ai": "Perplexity",
    "api.cohere.ai": "Cohere",
    "api.groq.com": "Groq",
    "api.featherless.ai": "Featherless",
    "api.together.xyz": "Together AI",
    "api.deepseek.com": "DeepSeek",
}

# local LLM servers by port -> (provider, note)
LOCAL_LLM_PORTS: dict[int, str] = {
    11434: "Ollama (local)",
    1234: "LM Studio (local)",
    1337: "Jan (local)",
    8080: "llama.cpp (local)",
    8000: "vLLM (local)",
    4891: "GPT4All (local)",
    5001: "KoboldCpp (local)",
}


def _allowlist() -> set[str]:
    raw = os.getenv("ORG_ALLOWLIST", "")
    return {x.strip() for x in raw.split(",") if x.strip()}


def classify(host: str = "", ip: str = "", port: int = 0) -> dict:
    """Return {provider, approval, local_llm, matched}."""
    host = (host or "").lower().strip()
    allow = _allowlist()

    # 1) local LLM by port
    if port in LOCAL_LLM_PORTS and (host in ("", "127.0.0.1", "localhost", "::1") or ip.startswith("127.")):
        provider = LOCAL_LLM_PORTS[port]
        return {"provider": provider, "approval": _approval(provider, host, allow),
                "local_llm": True, "matched": f"port {port}"}

    # 2) cloud provider by hostname substring
    for needle, provider in CLOUD_PROVIDERS.items():
        if needle in host:
            return {"provider": provider, "approval": _approval(provider, host, allow),
                    "local_llm": False, "matched": needle}

    # 3) unknown destination
    if host or ip:
        return {"provider": "unknown", "approval": "unknown", "local_llm": False, "matched": ""}
    return {"provider": "unknown", "approval": "unknown", "local_llm": False, "matched": ""}


def _approval(provider: str, host: str, allow: set[str]) -> str:
    if not allow:
        # No policy configured: cloud AI is "unapproved" by default, nothing is "approved".
        return "unapproved"
    if host in allow or provider in allow:
        return "approved"
    return "unapproved"


def is_ai_destination(host: str = "", ip: str = "", port: int = 0) -> bool:
    c = classify(host, ip, port)
    return c["provider"] != "unknown"
