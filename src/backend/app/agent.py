"""Autonomous-agent behaviour analysis (PS requirement 4).

Flags the patterns behind real incidents like s1ngularity: an AI-agent process
spawning a shell, reading secrets/credentials, or running with reckless flags.
Observation, not inferred intent.
"""
from __future__ import annotations

import re

from .models import Behavior

# process names that look like AI agents / coding assistants
AGENT_HINTS = re.compile(
    r"(?i)(cursor|copilot|aider|autogpt|auto-gpt|langchain|crewai|openinterpreter|"
    r"open-interpreter|claude|gemini|ollama|continue|cline|windsurf|agent)")

SHELLS = re.compile(r"(?i)\b(cmd\.exe|powershell|pwsh|bash|sh|zsh|/bin/sh)\b")

SENSITIVE_FILES = re.compile(
    r"(?i)(\.env|id_rsa|id_ed25519|\.ssh[/\\]|\.aws[/\\]credentials|\.npmrc|"
    r"\.git-credentials|secrets?\.(?:json|ya?ml)|credentials?\.(?:json|ya?ml)|"
    r"\.kube[/\\]config|\.docker[/\\]config)")

DANGEROUS_FLAGS = re.compile(
    r"(?i)(--dangerously-skip-permissions|--yolo|--trust-all-tools|--no-sandbox|"
    r"--disable-safe-mode|--auto-approve)")


def looks_like_agent(proc_name: str, cmdline: str = "") -> bool:
    return bool(AGENT_HINTS.search(f"{proc_name} {cmdline}"))


def analyze(proc_name: str, cmdline: str = "", child: str = "",
            file_access: str = "") -> list[Behavior]:
    """Return behaviour findings for one process observation."""
    out: list[Behavior] = []
    blob = f"{proc_name} {cmdline} {child}"

    if DANGEROUS_FLAGS.search(cmdline):
        flag = DANGEROUS_FLAGS.search(cmdline).group(0)
        out.append(Behavior(type="dangerous_flag", severity="critical",
                            detail=f"Agent launched with reckless flag {flag}", target=flag))

    if SHELLS.search(child or ""):
        out.append(Behavior(type="shell_spawn", severity="high",
                            detail=f"{proc_name} spawned a shell ({child.strip()})", target=child.strip()))

    if file_access and SENSITIVE_FILES.search(file_access):
        sev = "critical" if re.search(r"(?i)(id_rsa|credentials|\.env)", file_access) else "high"
        out.append(Behavior(type="sensitive_file_read", severity=sev,
                            detail=f"Agent accessed sensitive file {file_access}", target=file_access))

    return out
