# SENTINEL APEX: Full AI-Agent Security Coverage — Module and Architecture Update

Oct 30, 2026 · @saif

## Summary

This update extends SENTINEL APEX from one agent-security module (APEX INJECTION GUARD) to a complete set that covers all eight known AI-agent security problems. The organizing principle is the same one that shapes Injection Guard: **detection produces signals at observation points; APEX GUARDIAN is the only authority that allows, warns, denies, or pauses an action.** Every new module plugs into that split.

- **What it adds:** three new modules — **APEX MEMORY GUARD**, **APEX TOOL TRUST**, **APEX AGENT TRUST** — plus an expansion of correlation into **APEX BEHAVIOUR INTELLIGENCE**, and action-specific policies inside Guardian.
- **How each problem closes:** every problem gets a defined observation point, a signal, a Guardian policy that enforces it, and a correlation path so the incident has a cause chain.
- **The thesis:** SENTINEL does not just detect eight threats. It correlates seven observation layers — content, identity, permissions, behaviour, network, memory, collaboration — behind one enforcement gate. That cross-layer correlation is the defensible contribution.
- **Claims discipline:** this document specifies the architecture that solves each problem completely. A problem is *solved* only once its module is implemented, wired to Guardian, and tested against the scenario fixtures named per section. Until then, treat each as *designed to closure, pending test*.

## The eight problems and their owning modules

| # | Problem | Owning module(s) | Observation point |
|---|---------|------------------|-------------------|
| 1 | Unauthorized tool usage | APEX GUARDIAN + Tool Gateway | Action egress |
| 2 | Memory poisoning | **APEX MEMORY GUARD** (new) | Memory write + retrieval |
| 3 | Malicious plugins / tools | **APEX TOOL TRUST** (new) | Tool registration + runtime |
| 4 | Long-term goal manipulation | **APEX BEHAVIOUR INTELLIGENCE** (expanded correlation) | Action sequence over time |
| 5 | Harmful autonomous actions | APEX GUARDIAN + action-specific policy + sandbox | Action egress |
| 6 | Indirect prompt injection | APEX INJECTION GUARD (shipped) | Content ingress |
| 7 | Multi-agent communication attacks | **APEX AGENT TRUST** (new) | Agent-to-agent messages |
| 8 | Identity & permission misuse | Session Registry + Guardian + identity layer | Action egress + identity |

## Where it all fits

Each module is a signal producer on one observation layer. Guardian reads the shared **session state** (taint, manifest, memory trust, tool trust, agent trust, behaviour score) and makes the single enforcement decision at the tool gateway.

```mermaid
flowchart TB
    subgraph obs[Observation layers - signal producers]
        IG[APEX INJECTION GUARD<br/>content ingress]
        MG[APEX MEMORY GUARD<br/>memory write + retrieval]
        TT[APEX TOOL TRUST<br/>tool registration + runtime]
        AT[APEX AGENT TRUST<br/>agent-to-agent messages]
        BI[APEX BEHAVIOUR INTELLIGENCE<br/>action sequences]
    end

    IG --> SS[(Session state<br/>taint, manifest, memory trust,<br/>tool trust, agent trust, behaviour score)]
    MG --> SS
    TT --> SS
    AT --> SS
    BI --> SS

    AG[Agent proposes action] --> TG[Tool Gateway<br/>only path to tools]
    TG --> GD[APEX GUARDIAN<br/>allow / warn / deny / pause]
    SS -- read at decision time --> GD
    GD -- allow --> EX[Execute] --> SN[SENTINEL sensors<br/>process / file / network]

    IG & MG & TT & AT & BI & GD & SN -. events .-> EB[(Event bus)]
    EB --> COR[Risk Correlation Engine]
    COR --> BI
    COR --> ORCH[SENTINEL AI Orchestrator] --> DASH[Command Center]

    style MG fill:#2d6cdf,color:#fff,stroke:#1b3f85,stroke-width:2px
    style TT fill:#2d6cdf,color:#fff,stroke:#1b3f85,stroke-width:2px
    style AT fill:#2d6cdf,color:#fff,stroke:#1b3f85,stroke-width:2px
    style BI fill:#2d6cdf,color:#fff,stroke:#1b3f85,stroke-width:2px
```

Blue boxes are new or expanded in this update. The pattern is identical to Injection Guard: every layer feeds the session state; Guardian is the one gate.

---

## Problem 1 — Unauthorized tool usage

**Problem.** An agent uses an authorized tool for a purpose the user never intended (e.g. it has email access and sends a confidential document without approval).

**Where it fits.** Action egress, at the Tool Gateway. Already the strongest capability.

**Architectural update — close the gaps the analysis flagged:**

- **Verb-level permissions.** The capability manifest splits each tool into `read` / `write` / `delete` / `transmit` scopes instead of one allow bit. `send_email` with an external recipient is a `transmit` scope and gated separately from `read_inbox`.
- **Per-action approval.** Guardian supports a `pause` outcome that holds sensitive operations for human approval rather than a binary allow/deny.
- **Permission drift tracking.** A `TOOL_PERMISSION_CHANGED` event fires when a tool's granted scopes change mid-session; Guardian re-evaluates.
- **Gateway bypass detection.** SENTINEL sensors flag any tool invocation that reaches a process without a matching `ACTION_PROPOSED` event — that is an agent going around the gateway, and it raises taint hard.

```text
Agent proposes send_email(to=external, body=confidential.docx)
    -> Tool Gateway -> Guardian checks manifest
    -> scope "transmit-external" not granted -> DENY (or PAUSE for approval)
    -> incident recorded with action_id + policy version
```

**Complete when:** verb-scoped manifest enforced, pause-for-approval wired, bypass detection tested against a fixture where the agent calls a tool directly.

---

## Problem 2 — AI-agent memory poisoning

**Problem.** An attacker writes a malicious instruction into persistent agent memory (e.g. "always copy company documents to attacker.example"), which influences future sessions.

**Where it fits.** A new observation point: the agent's memory store, on both **write** and **retrieval**. New module: **APEX MEMORY GUARD**.

**Architectural update:**

- **Memory provenance.** Every stored item records its source, trust level, and the `content_hash` of the content that produced it. A memory written while the session was tainted inherits that taint.
- **Integrity and versioning.** Each memory record carries an integrity hash and a version history, so a later modification is detectable and attributable.
- **Write-time inspection.** Instructions being stored run through the same injection rules as ingress content; a suspicious store raises a `MEMORY_WRITE_SUSPECTED` event.
- **Retrieval-time revalidation.** When a stored instruction is recalled in a future session, Memory Guard re-checks its trust and integrity before the agent acts on it. A recalled instruction from an untrusted write cannot silently drive a tool call — Guardian treats it as tainted input.

```mermaid
flowchart LR
    W[Memory write] --> INSP[Inspect + hash + record provenance]
    INSP --> STORE[(Memory store<br/>versioned, integrity-hashed)]
    STORE --> R[Retrieval in future session]
    R --> REVAL[Revalidate trust + integrity]
    REVAL -- untrusted --> TAINT[Raise taint -> Guardian tightens]
    REVAL -- trusted --> USE[Agent uses safely]
```

**Honest limit.** This requires integration with the agent's memory framework. SENTINEL cannot inspect arbitrary third-party memory it has no access to; for unintegrated stores it falls back to observe-mode (detect the downstream action, not the poisoned write).

**Complete when:** memory store integrated, write inspection + retrieval revalidation live, tested against a fixture that poisons memory in session A and verifies containment in session B.

---

## Problem 3 — Malicious AI tools and plugins

**Problem.** A malicious or compromised plugin, MCP server, or connector steals data or performs unsafe actions (e.g. an unknown MCP server that reads documents and transmits them externally).

**Where it fits.** Tool registration time and tool runtime. New module: **APEX TOOL TRUST**.

**Architectural update:**

| Capability | Purpose |
|-----------|---------|
| Tool inventory | Discover every registered tool, plugin, and MCP server |
| Tool identity | Record name, version, publisher, endpoint |
| Permission analysis | Determine what resources each tool can reach |
| Behaviour monitoring | Flag unexpected file or network activity by a tool |
| Trust assessment | Label each tool approved / unknown / restricted / revoked |
| Policy enforcement | Guardian denies unapproved tools and destinations |

- **MCP-specific checks.** Record each server's declared capabilities and tool schemas; a change to those declarations after approval fires `TOOL_SCHEMA_CHANGED` and drops trust to `unknown` until re-reviewed.
- **Supply-chain link.** Tool Trust feeds APEX TRACE / DarkGuard so an unknown tool's endpoint can be investigated for external exposure.

**Complete when:** inventory + trust registry live, Guardian denies `unknown`/`revoked` tools, tested against a fixture that registers an untrusted MCP server attempting document exfiltration.

---

## Problem 4 — Long-term goal manipulation

**Problem.** An agent drifts from its original task across many steps, each individually plausible, ending in an unsafe action.

**Where it fits.** Across the whole session timeline. Expanded module: **APEX BEHAVIOUR INTELLIGENCE** (on top of the Correlation Engine).

**Architectural update:**

- **Persistent multi-step action history** per session, keyed to the Session Registry objective.
- **Sequence analysis.** Detect suspicious chains of individually permitted actions:

```text
read_email -> access_customer_db -> read_confidential_attachment -> connect_unknown_host
```

Each step passes its own policy; the *sequence* trips a behaviour rule.

- **Cumulative state tracking.** Track growing permission use and data access within a session; a monotonic climb toward sensitive + egress raises the behaviour score.
- **Cross-session baselines.** Compare against the agent's normal pattern; deviation is a signal, not a verdict.
- **Manifest deviation feeds it.** Every action outside the manifest is already a deterministic signal from the Session Registry; Behaviour Intelligence weights sequences of near-manifest-edge actions.

**Complete when:** session action history persisted, at least one sequence rule and one baseline-deviation rule fire into scoring, tested against the multi-step drift fixture.

---

## Problem 5 — Harmful autonomous actions

**Problem.** An agent autonomously performs destructive operations: deleting files, changing permissions, running destructive shell commands, mass-transmitting data.

**Where it fits.** Action egress, through Guardian — but needs **action-specific safety policies** and **sandboxing**.

**Architectural update — a default policy matrix in Guardian:**

| Action | Default policy |
|--------|----------------|
| Read public documentation | Allow |
| Read confidential files | Require authorization |
| Delete files | Require approval (pause) |
| Modify access permissions | Deny or elevated approval |
| Execute shell commands | Restrict by command allowlist/denylist |
| Transfer sensitive information | Deny unless explicitly authorized |

- **Sandboxing.** Destructive or high-blast-radius actions execute in a constrained environment (restricted filesystem, no raw egress) so a mistaken allow is reversible.
- **Scope statement.** SENTINEL's stated scope is *preventing unauthorized or policy-violating autonomous actions*, not detecting every conceivable harmful decision. Keep that boundary in the report.

**Complete when:** action policy matrix encoded in Guardian YAML, shell command policy enforced, destructive actions sandboxed, tested against a fixture attempting file deletion and a destructive shell command.

---

## Problem 6 — Indirect prompt injection

**Problem.** Malicious instructions enter through external content — web pages, emails, PDFs, retrieved documents, API responses, tool outputs — rather than a direct prompt.

**Where it fits.** Content ingress. Module: **APEX INJECTION GUARD** (already designed and documented in `APEX_INJECTION_GUARD_UPDATE.md`).

**Architectural update — remaining work to call it complete:**

- Support multiple content formats (HTML, PDF, email, JSON).
- Detect hidden / obfuscated instructions (zero-width characters, encoded payloads, white-on-white text).
- Track the relationship between injected content (`content_hash`) and the subsequent action (`action_id`) — already in the event schema.
- Evaluate against public indirect-injection benchmarks (AgentDojo, InjecAgent — verify fit).

**Complete when:** multi-format ingestion + obfuscation detection live, benchmark numbers measured, clean-page negative control passes.

---

## Problem 7 — Multi-agent communication attacks

**Problem.** Agents exchange tasks and instructions; one compromised agent influences another (Agent A, poisoned by external content, sends an untrusted instruction to Agent B, which acts on it).

**Where it fits.** The agent-to-agent message channel. New module: **APEX AGENT TRUST** — the largest current gap.

**Architectural update:**

- **Agent identity and authentication.** Every agent has a verifiable identity; messages are authenticated so a sender cannot be spoofed.
- **Message provenance and integrity.** Each inter-agent message carries its origin and an integrity check; a message whose chain traces back to tainted content arrives tainted.
- **Trust levels between agents.** Explicit trust edges; Agent B does **not** automatically inherit Agent A's permissions or trust.
- **Delegation tracking.** When A delegates a task to B, the delegated capability is scoped and recorded; B cannot exceed it.
- **Cross-agent correlation.** The Correlation Engine joins sessions across agents so one incident spans the A→B→C chain.
- **Policy on inter-agent requests.** Guardian evaluates an incoming inter-agent instruction like any other untrusted input before B acts on it.

```mermaid
flowchart LR
    A[Agent A - Research<br/>tainted by external content] -- message --> CHK[Agent Trust:<br/>authenticate + check provenance + scope]
    CHK -- tainted / out of scope --> DENY[Guardian denies / tightens B]
    CHK -- clean + in scope --> B[Agent B acts within delegated scope only]
```

**Complete when:** agent identity + message provenance + delegation scoping live, cross-agent correlation produces one joined incident, tested against the A→B→C instruction-transfer fixture.

---

## Problem 8 — Agent identity and permission misuse

**Problem.** An agent misuses privileges inherited from a user or service account (authorized to read project docs, it uses the user's broader filesystem rights to reach unrelated confidential files).

**Where it fits.** Action egress plus the identity layer. Modules: Session Registry + Guardian + endpoint identity integration.

**Architectural update:**

- **Separate agent identity from user identity.** Track which user *and* which agent *and* which process initiated an action; they are distinct principals.
- **Service-account and delegated-token tracking.** Record the credential the agent is acting under.
- **Per-session credential scope.** The agent gets a scoped credential for the session's objective, not the user's full rights.
- **Expiration and revocation.** Scoped credentials expire with the session and can be revoked mid-session.
- **Privilege-inheritance guard.** Inheriting a user's access does not grant unrestricted use; Guardian still checks each action against the session manifest.

**Complete when:** agent vs. user principals distinguished in events, per-session scoped credentials issued and revocable, tested against a fixture where the agent reaches outside its objective's path using inherited rights.

---

## Consolidated event schema

All events carry `session_id`; new types extend the Injection Guard schema. Correlation joins them into one cause chain.

| Event | Source | Key fields |
|-------|--------|-----------|
| `CONTENT_INGESTED` | Injection Guard | source, trust_level, content_hash |
| `INJECTION_SUSPECTED` | Injection Guard | score, indicators, content_hash |
| `MEMORY_WRITE_SUSPECTED` | Memory Guard | memory_id, source, trust, content_hash |
| `MEMORY_RETRIEVAL` | Memory Guard | memory_id, trust_at_retrieval, integrity_ok |
| `TOOL_REGISTERED` | Tool Trust | tool_id, publisher, endpoint, declared_caps |
| `TOOL_SCHEMA_CHANGED` | Tool Trust | tool_id, old_hash, new_hash |
| `TOOL_PERMISSION_CHANGED` | Guardian | tool_id, old_scopes, new_scopes |
| `AGENT_MESSAGE` | Agent Trust | from_agent, to_agent, provenance, integrity_ok |
| `ACTION_PROPOSED` | Tool Gateway | action_id, tool, scope, arguments (redacted) |
| `POLICY_DECISION` | Guardian | action_id, decision, policy_version, session state |
| `BEHAVIOUR_SEQUENCE_FLAGGED` | Behaviour Intelligence | sequence, rule, score |
| `ACTION_RESULT` | Sensors | executed/denied, linked sensor events |

Join path: `content_hash / memory_id / tool_id / from_agent → finding → action_id → decision → sensor events → secret fingerprints`.

## Scoring

Declarative rules per problem, with attempt separated from outcome (a blocked attempt is **Contained**, not **Exposed**):

- `unauthorized_tool_scope`, `memory_poison_suspected`, `untrusted_tool_used`, `objective_drift_sequence`, `destructive_action_attempted`, `injection_in_untrusted_source`, `untrusted_agent_message`, `privilege_inheritance_misuse`, `denied_at_gateway`.

Each incident records the fired rules and the `event_ids` behind them, so the score is evidence, not decoration.

## Updated module architecture (layers)

| Layer | Modules |
|-------|---------|
| Discovery | Organization Discovery, Shadow AI Discovery, External Asset Discovery |
| Endpoint Intelligence | SENTINEL Agent, Network Intelligence, File Monitoring |
| AI-Agent Security | APEX INJECTION GUARD, **APEX MEMORY GUARD**, **APEX TOOL TRUST**, **APEX AGENT TRUST** |
| Authorization & Protection | Session Registry, Capability Manifest, APEX GUARDIAN |
| Detection & Analysis | Sensitive Data Inspection, Agent Behaviour Monitoring, **APEX BEHAVIOUR INTELLIGENCE** |
| Correlation & Intelligence | Risk Correlation Engine, Threat Scoring, SENTINEL AI Orchestrator |
| Investigation | APEX TRACE, DarkGuard APEX |
| Validation | APEX REDLAB, APEX EVALUATION |
| Presentation | SENTINEL Command Center |

## Implementation order

Build to prevention first, then widen coverage.

| Priority | Build | Why |
|----------|-------|-----|
| 1 | Tool Gateway + Guardian (verb scopes, pause, bypass detection) | Real prevention — problems 1, 5, 8 |
| 2 | Session Registry + capability manifest | Authorization boundary — problems 1, 4, 8 |
| 3 | APEX INJECTION GUARD (multi-format + obfuscation) | Problem 6 |
| 4 | APEX BEHAVIOUR INTELLIGENCE | Problem 4, and the correlation story |
| 5 | APEX TOOL TRUST | Problem 3 — best next module, demoable without a multi-agent setup |
| 6 | APEX MEMORY GUARD | Problem 2 |
| 7 | APEX AGENT TRUST | Problem 7 — largest gap, needs the most scaffolding |

## Validation: the one campaign that proves the thesis

A single controlled attack campaign that exercises the integration advantage:

1. Indirect prompt injection via a web fixture (problem 6).
2. The injected instruction drives an unauthorized tool call (problem 1).
3. The agent attempts an external data transfer (problem 5 / data leakage).
4. A poisoned memory write attempts to persist the behaviour (problem 2).
5. **Negative control:** the same agent on a clean page — no injection, no incident.

One incident rendered end to end, with the cause chain across all layers, demonstrates cross-layer correlation rather than a pile of separate modules.

## Claims discipline (keep this in the report)

- Say each module **reduces risk** and **prevents policy-violating actions**, not that it "stops every attack."
- Distinguish **architecture coverage** (this document) from **tested implementation**. Do not claim memory-poisoning detection until Memory Guard is integrated and tested; do not claim multi-agent protection until Agent Trust has identity, provenance, and authorization working.
- SENTINEL observes **evidence** — process activity, file access, tool calls, permissions, network, integrated memory, inter-agent messages. It does not claim to read an agent's internal reasoning.
- Verify every research citation and label benchmark papers (which test vulnerabilities) separately from detection systems (which detect attacks) before anything goes on a slide.

## Next steps

- [ ] Confirm this module split and layer grouping is the shape you want.
- [ ] Draft the Guardian YAML: verb-scoped manifest + the action policy matrix (problems 1, 5, 8).
- [ ] Define the consolidated event schema v2 as Pydantic models with `schema_version`.
- [ ] Stand up APEX TOOL TRUST inventory + trust registry (recommended next module).
- [ ] Build the single combined attack campaign fixture plus the clean negative control.
