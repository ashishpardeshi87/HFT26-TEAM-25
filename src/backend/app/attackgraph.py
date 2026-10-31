"""Feature A — Attack graph visualization (read-side).

Turns one incident's event set into a directed graph that shows how the attack
moved, event to event: malicious page -> agent -> file access -> sensitive data
-> external destination. It reads the Evidence Store (stored Event objects); it
never enforces.

Honesty (Questionable-Points B2): edges carry an explicit label and we never
assert causality beyond it.

    direct_execution_linkage  (evidence relationship) — a recorded parent-child link
    strong_correlation        (inference strength)    — independent corroboration (HMAC/canary match)
    possible_correlation      (inference strength)    — temporal/session association only

Even direct execution linkage does NOT prove the *semantic* influence of content
on the model's decision. The graph shows execution relationships, not that a
page's words changed the model's mind.
"""
from __future__ import annotations

from .models import Event

LABELS = {
    "direct_execution_linkage": {"kind": "evidence_relationship",
                                 "meaning": "A recorded parent-child / tool-call relationship."},
    "strong_correlation": {"kind": "inference_strength",
                           "meaning": "Multiple independent supporting signals (e.g. HMAC fingerprint or canary match)."},
    "possible_correlation": {"kind": "inference_strength",
                             "meaning": "Temporal- or session-based association only."},
}
CAVEAT = ("Edges show execution relationships, not proven causation. Even a direct "
          "execution linkage does not prove a page's content changed the model's decision.")


def _blocked(ev: Event) -> bool:
    return any(b.type == "policy_decision" and b.target in ("deny", "pause", "require_approval") for b in ev.behavior)


def _leak(ev: Event) -> bool:
    return bool(ev.findings) or ev.event_type in ("exfil", "ai_payload")


def _sensitive(ev: Event) -> bool:
    return bool(ev.findings) or any(b.type == "sensitive_file_read" for b in ev.behavior)


def _external(ev: Event) -> bool:
    d = ev.destination
    host = d.host or ""
    is_local = host.startswith("127.") or host == "localhost"
    return (bool(host) and not is_local) or ev.scope == "transmit-external"


def _node_label(ev: Event) -> str:
    if ev.tool:
        return f"{ev.tool}({(ev.tool_args or '')[:22]})"
    if ev.event_type == "content_ingested":
        return "ingest untrusted content"
    if ev.findings:
        return f"{ev.event_type}: {ev.findings[0].label}"
    if ev.behavior:
        b = next((x for x in ev.behavior if x.type != "policy_decision"), ev.behavior[0])
        return f"{b.type.replace('_', ' ')}"
    return ev.event_type.replace("_", " ")


def _outcome(ev: Event) -> str:
    if _blocked(ev):
        return "blocked"
    if ev.findings:
        return "leak"
    if ev.trust_level == "untrusted" and ev.event_type == "content_ingested":
        return "ingress"
    return "observed"


def _node(ev: Event) -> dict:
    return {
        "id": ev.id,
        "label": _node_label(ev),
        "type": ev.event_type,
        "ts": ev.ts,
        "outcome": _outcome(ev),
        "blocked": _blocked(ev),
        "sensitive": _sensitive(ev),
        "external": _external(ev),
        "process": ev.process.name,
        "detail": next((b.detail for b in ev.behavior if b.type != "policy_decision"),
                       (ev.findings[0].label if ev.findings else (ev.tool_args or ev.payload_excerpt[:80]))),
    }


def build(events: list[Event]) -> dict:
    """Build {nodes, edges} + cause_path + text exports from an incident's events."""
    ids = {e.id for e in events}
    by_id = {e.id: e for e in events}
    nodes = [_node(e) for e in events]
    edges: list[dict] = []
    seen: set[tuple] = set()

    def add_edge(src, dst, label):
        key = (src, dst, label)
        if src in ids and dst in ids and src != dst and key not in seen:
            seen.add(key)
            edges.append({"source": src, "target": dst, "label": label, **LABELS[label]})

    # 1) Direct execution linkage — real parent-child links.
    direct_children: set[str] = set()
    for e in events:
        if e.parent_id and e.parent_id in ids:
            add_edge(e.parent_id, e.id, "direct_execution_linkage")
            direct_children.add(e.id)

    # 2) Strong correlation — HMAC fingerprint / canary match between a read and a leak.
    reads = [(e, {fp for b in e.behavior for fp in b.fingerprints}) for e in events]
    for leak_ev in events:
        leak_fps = {f.fingerprint for f in leak_ev.findings if f.fingerprint}
        if not leak_fps:
            continue
        for read_ev, read_fps in reads:
            if read_ev.id != leak_ev.id and (read_fps & leak_fps):
                add_edge(read_ev.id, leak_ev.id, "strong_correlation")

    # 3) Possible correlation — same-session predecessor with no direct link.
    last_in_session: dict[str, str] = {}
    for e in events:
        key = e.session_id or f"{e.host}:{e.process.pid}"
        prev = last_in_session.get(key)
        if prev and e.id not in direct_children:
            add_edge(prev, e.id, "possible_correlation")
        last_in_session[key] = e.id

    cause = cause_path(events, by_id)
    return {
        "nodes": nodes,
        "edges": edges,
        "cause_path": cause,
        "labels_legend": LABELS,
        "causality_caveat": CAVEAT,
        "mermaid": to_mermaid(nodes, edges),
        "dot": to_dot(nodes, edges),
        "stats": {
            "events": len(nodes),
            "blocked": sum(1 for n in nodes if n["blocked"]),
            "direct_links": sum(1 for e in edges if e["label"] == "direct_execution_linkage"),
            "strong": sum(1 for e in edges if e["label"] == "strong_correlation"),
            "possible": sum(1 for e in edges if e["label"] == "possible_correlation"),
        },
    }


def cause_path(events: list[Event], by_id: dict[str, Event]) -> dict:
    """Path to sink: from the terminal event (blocked, else leak, else last) back
    to the root cause via parent lineage."""
    if not events:
        return {"terminal": None, "steps": []}
    terminal = (next((e for e in reversed(events) if _blocked(e)), None)
                or next((e for e in reversed(events) if e.findings), None)
                or events[-1])

    chain: list[Event] = []
    cur = terminal
    guard = 0
    while cur and guard < 64:
        chain.append(cur)
        cur = by_id.get(cur.parent_id)
        guard += 1
    chain.reverse()

    steps = []
    for i, e in enumerate(chain):
        steps.append({
            "event_id": e.id,
            "label": _node_label(e),
            "outcome": _outcome(e),
            "edge": "direct_execution_linkage" if i > 0 else "root",
        })
    return {"terminal": terminal.id, "steps": steps,
            "root_cause": chain[0].id if chain else None}


# ---- text exports ----------------------------------------------------------

def _mnode(n: dict) -> str:
    nid = n["id"].replace("-", "_")
    shape = (f'{nid}["{n["label"]}"]')
    return shape


def to_mermaid(nodes: list[dict], edges: list[dict]) -> str:
    arrow = {"direct_execution_linkage": "-->", "strong_correlation": "-.->", "possible_correlation": "-.->"}
    lines = ["flowchart TD"]
    for n in nodes:
        lines.append(f"    {_mnode(n)}")
    for n in nodes:
        if n["blocked"]:
            lines.append(f"    style {n['id'].replace('-', '_')} stroke:#ff453a,stroke-width:3px")
        elif n["outcome"] == "leak":
            lines.append(f"    style {n['id'].replace('-', '_')} stroke:#ffb020,stroke-width:2px")
    for e in edges:
        a = arrow[e["label"]]
        lbl = {"direct_execution_linkage": "direct", "strong_correlation": "strong", "possible_correlation": "possible"}[e["label"]]
        lines.append(f"    {e['source'].replace('-', '_')} {a}|{lbl}| {e['target'].replace('-', '_')}")
    return "\n".join(lines)


def to_dot(nodes: list[dict], edges: list[dict]) -> str:
    style = {"direct_execution_linkage": "solid", "strong_correlation": "bold", "possible_correlation": "dashed"}
    out = ["digraph attack {", '  rankdir=TB; bgcolor="transparent"; node [shape=box, fontname="monospace"];']
    for n in nodes:
        color = "#ff453a" if n["blocked"] else "#ffb020" if n["outcome"] == "leak" else "#8d8d85"
        out.append(f'  "{n["id"]}" [label="{n["label"]}", color="{color}"];')
    for e in edges:
        out.append(f'  "{e["source"]}" -> "{e["target"]}" [style={style[e["label"]]}, label="{e["label"].split("_")[0]}"];')
    out.append("}")
    return "\n".join(out)
