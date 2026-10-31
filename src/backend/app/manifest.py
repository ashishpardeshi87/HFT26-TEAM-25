"""Session Registry capability manifests.

Setup compiles the operator's objective and scope into a deterministic manifest.
Guardian evaluates actions against this object; the LLM never decides scope.
"""
from __future__ import annotations

import copy
import fnmatch
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

# session_id -> manifest
_REGISTRY: dict[str, dict] = {}

DEFAULT_MANIFEST = {
    "task": "No verified session objective",
    "target": "",
    "agents": [],
    "scenario": "production",
    "allowed_files": [],
    "allowed_tools": [],
    "allowed_hosts": [],
    "allowed_scopes": {},
    "trust_sources": {"web": "untrusted", "email": "untrusted", "document": "untrusted",
                      "tool_output": "untrusted", "agent_message": "untrusted", "repo": "trusted"},
}

SENSITIVE = re.compile(
    r"(?i)(^|[/\\])(?:\.env(?:\.|$)|id_rsa$|id_ed25519$|\.ssh(?:[/\\]|$)|"
    r"\.aws[/\\]credentials$|\.npmrc$|\.git-credentials$|secrets?(?:\.|[/\\]|$)|"
    r"credentials?(?:\.|[/\\]|$)|private[_-]?key)"
)


def compile_manifest(body: dict, target_host: str) -> dict:
    scope = body.get("manifest") or {}
    agents = []
    for raw in body.get("agents") or []:
        if isinstance(raw, str):
            aid = raw.strip()
            if aid:
                agents.append({"id": aid, "process": aid, "pid": None})
        elif isinstance(raw, dict) and str(raw.get("id") or "").strip():
            agents.append({
                "id": str(raw["id"]).strip(),
                "process": str(raw.get("process") or raw["id"]).strip(),
                "pid": int(raw["pid"]) if raw.get("pid") not in (None, "") else None,
            })

    allowed_tools = _clean(scope.get("allowed_tools") or ["read_file", "http_get", "read_inbox"])
    allowed_files = _clean(scope.get("allowed_files") or ["README*", "docs/**", "src/**"])
    allowed_hosts = _clean(scope.get("allowed_hosts") or ([target_host] if target_host else []))
    allowed_scopes = scope.get("allowed_scopes") or {
        "read_file": ["read"], "http_get": ["read"], "read_inbox": ["read"],
    }
    normalized_scopes = {
        str(tool): sorted({str(v) for v in vals if str(v)})
        for tool, vals in allowed_scopes.items() if isinstance(vals, list)
    }
    return {
        "task": str(body.get("objective") or "Monitor registered AI agents within the declared target").strip(),
        "target": target_host,
        "agents": agents,
        "scenario": body.get("scenario", "production"),
        "allowed_files": allowed_files,
        "allowed_tools": allowed_tools,
        "allowed_hosts": allowed_hosts,
        "allowed_scopes": normalized_scopes,
        "trust_sources": copy.deepcopy(DEFAULT_MANIFEST["trust_sources"]),
    }


def _clean(values) -> list[str]:
    return list(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))


def register(session_id: str, manifest: dict | None = None) -> dict:
    _REGISTRY[session_id] = copy.deepcopy(manifest or DEFAULT_MANIFEST)
    return copy.deepcopy(_REGISTRY[session_id])


def unregister(session_id: str) -> None:
    _REGISTRY.pop(session_id, None)


def get(session_id: str) -> dict:
    return copy.deepcopy(_REGISTRY.get(session_id, DEFAULT_MANIFEST))


def exists(session_id: str) -> bool:
    return session_id in _REGISTRY


def file_allowed(manifest: dict, path: str) -> bool:
    raw = (path or "").strip().replace("\\", "/")
    if not raw or SENSITIVE.search(raw):
        return False
    # Collapse ./ and reject traversal before glob matching.
    parts = [p for p in PurePosixPath(raw).parts if p not in (".", "")]
    if ".." in parts:
        return False
    normalized = "/".join(parts)
    patterns = manifest.get("allowed_files", [])
    return any(fnmatch.fnmatch(normalized.lower(), str(p).lower()) for p in patterns)


def tool_allowed(manifest: dict, tool: str) -> bool:
    return bool(tool) and tool in manifest.get("allowed_tools", [])


def _host(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "@" in raw and "://" not in raw:
        raw = raw.rsplit("@", 1)[-1]
    if "://" not in raw:
        raw = "https://" + raw
    try:
        return (urlparse(raw).hostname or "").rstrip(".")
    except Exception:
        return ""


def host_allowed(manifest: dict, value: str) -> bool:
    host = _host(value)
    if not host:
        return False
    for allowed in manifest.get("allowed_hosts", []):
        a = _host(str(allowed).lstrip("*."))
        if not a:
            continue
        if str(allowed).startswith("*."):
            if host.endswith("." + a):
                return True
        elif host == a:
            return True
    return False


def scope_allowed(manifest: dict, tool: str, scope: str) -> bool:
    if not scope:
        return False
    return scope in manifest.get("allowed_scopes", {}).get(tool, [])


def agent_allowed(manifest: dict, agent_id: str, process_name: str = "", pid: int | None = None) -> bool:
    agents = manifest.get("agents") or []
    for a in agents:
        if a.get("id") != agent_id:
            continue
        proc_ok = not a.get("process") or not process_name or a.get("process").lower() == process_name.lower()
        pid_ok = a.get("pid") in (None, 0) or pid in (None, 0) or a.get("pid") == pid
        if proc_ok and pid_ok:
            return True
    return False


def process_allowed(manifest: dict, process_name: str, pid: int | None = None) -> bool:
    """Match passive process telemetry to any registered agent process."""
    for a in manifest.get("agents") or []:
        proc = str(a.get("process") or "")
        proc_ok = proc == "*" or (proc and proc.lower() == (process_name or "").lower())
        pid_ok = a.get("pid") in (None, 0) or pid in (None, 0) or a.get("pid") == pid
        if proc_ok and pid_ok:
            return True
    return False
