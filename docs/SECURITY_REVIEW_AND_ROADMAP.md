# SENTINEL APEX — Security Review, Honest Claims & Roadmap

This document keeps the project honest for judging. It records a strict-reviewer Q&A, the
exact claims we make (and don't make), the flaws we fixed during the build, the APEX Injection
Guard design, and the upgrade roadmap. Sources: the team's "Technical & Architectural Upgrades"
note and "APEX Injection Guard" update (both Oct 30, 2026).

---

## 1. Claims to keep honest (say these exactly on a slide)

- **"We reduce risk; we do not stop all prompt injection or all exfiltration."** The boundary is
  the capability manifest and the tool gateway, not the detector.
- **Live payload visibility is bounded.** Over HTTPS we do **not** read arbitrary traffic. Visibility
  comes from plaintext sources: the browser extension (pre-encryption), local-LLM plaintext
  (Ollama on :11434), agent/tool-gateway hooks, and uploaded HAR/PCAP/logs. In the MVP the
  "outgoing payload" is a supplied fixture or a local plaintext source — the demo shows **detection
  logic**, not universal interception.
- **Guardian enforces only for managed agents.** For agents routed through the tool gateway we get
  real pre-execution allow/deny/warn/pause (**gateway mode**). For unmanaged shadow tools we get
  **detection + containment after the fact** (**observe mode**). Every incident is labelled with its
  mode so we never overstate protection.
- **DarkGuard / external exposure is enrichment, not a core claim.** A dark-web match is a *lead*,
  not proof of attribution or causation. Confidence is labelled (observed / exact_match / reported /
  correlated / hypothesis).
- **No number is claimed until measured** against a documented fixture set.

---

## 2. Flaws found by the reviewer → what we fixed in this build

| # | Flaw (reviewer) | Fix shipped | Status |
|---|---|---|---|
| 1 | Live exfiltration not truly detected (depends on fixtures/extensions/hooks) | Mode labelling (`gateway`/`observe`) on every incident; demo sources made explicit; canary token gives **ground-truth** exfil | Reworded + partial code |
| 2 | Guardian can't protect shadow agents | Reframed: **enforce** for managed (gateway), **detect+contain** for unmanaged (observe); both shown in the demo | Done |
| 3 | Evaluation is circular; score uncalibrated | **Canary token** (ground truth) + **HMAC fingerprint match** (provable file→payload link) + declarative YAML weights with ablatable rules | Done (code) |
| 4 | "Authorized objective" undefined | **Capability manifest + Session Registry** (`manifest.py`): an action outside the manifest is a deterministic violation; the LLM only annotates | Done (code) |
| 5 | No coverage for source code / documents | Named as a gap; planned content-fingerprinting (shingling/winnowing) in the roadmap | Roadmap |
| 6 | TRACE/DarkGuard weak causal link; "dataset fingerprint" undefined | Positioned as **optional enrichment** with typed confidence labels; not a core claim | Reworded |
| 7 | Agent not tamper-resistant; DNS/ECH evasion | Acknowledged; roadmap: service + heartbeats + signed binaries; DNS/SNI caveat documented | Roadmap |
| 8 | LLM dependency is an exfil path | Copilot gets **masked** evidence only, `temperature:0`, no tools, local-Ollama fallback; payload treated as untrusted (injection risk) | Done (design) |
| 9 | Scale/overhead unmeasured; no head-to-head | Roadmap: queue + Postgres/Timescale; benchmark harness; no comparative claims made | Roadmap |

---

## 3. Strict-reviewer Q&A (condensed, with honest ratings)

**Round 1 — Detection & telemetry**
- *Q1 psutil gives IPs not hostnames.* You can't identify a provider from IP alone; use DNS events
  (Sysmon 22 / ETW), TLS SNI, the browser extension, or an IP→hostname cache. **DoH + ECH can hide
  both.** → *Partial.*
- *Q2 How do you see HTTPS payloads?* You don't, on the wire. Visibility is pre-encryption sources
  only. In the MVP the payload is a fixture. → *Honest; coverage weak.*
- *Q3 `.env` read vs theft?* Fire only when the process is an agent, the file is outside the task
  manifest, **and** another signal is present. A lone `.env` read scores low. → *Now deterministic
  via the manifest.*
- *Q4 Source code / documents?* Regex can't; needs content fingerprinting + classifiers. → *Gap,
  on roadmap.*
- *Q5 Encoded/split secrets?* Add base64/hex/url/unicode normalisation before scanning; chunked
  exfil needs per-process stream state. → *Partial.*
- *Q6 Detect local LLMs?* Ports (11434), process names, model dirs — all trivially changed. →
  *Best-effort.*

**Round 2 — Correlation & scoring**
- *Q7 PID reuse / name collisions?* Key on `(endpoint, pid, process_start_time)` + parent lineage +
  window expiry + per-link confidence. → *Strong.*
- *Q8 Who chose the weights?* They're a prioritisation heuristic, **not** a probability. Weights now
  live in `scoring.yaml`, every fired rule cites its `event_ids`, and rules are ablatable. → *Improved.*
- *Q9 Toy agent self-reports — circular?* Yes, partly. Mitigated with canary ground truth, HMAC
  fingerprint linking, and public fixtures (gitleaks/detect-secrets corpora) written by someone
  outside the team. → *Improving.*

**Round 3 — Protection**
- *Q10 How does Guardian prevent?* Only via independent enforcement: pre-tool-use hooks / MCP
  gateway, OS controls, network egress policy. Hooks alone are bypassable by a raw shell. → *Partial;
  gateway mode implemented.*
- *Q11 How hook an unmanaged agent?* You can't — detection + coarse controls only. Reframed as
  gateway vs observe. → *Resolved by honest framing.*
- *Q12 Can a user kill the agent?* Yes; mitigate with heartbeats, a protected service account, signed
  binaries. User-space Python isn't tamper-resistant. → *Partial, roadmap.*

**Round 4 — AI, privacy, positioning**
- *Q13 Sending data to Featherless is an exfil path.* Send only redacted/minimised evidence; local
  Ollama option; treat payload as untrusted; give the model no tools. → *Partial, disclosed.*
- *Q14 Employee-monitoring legality.* Explicit authorisation + notice, minimisation, local redaction,
  RBAC, retention limits, audit log; check DPDP with counsel. → *Strong design, not legal advice.*
- *Q15 Why you vs Purview/Netskope/Zscaler/CrowdStrike?* Don't claim to beat their DLP/CASB. The
  pitch is **correlation into one incident with agent-intent context**. → *No head-to-head yet.*
- *Q16 TRACE dark-web "dataset fingerprint" without the data?* Only via hash/range lookups where the
  source supports it; else public metadata. Term now avoided / typed. → *Enrichment only.*
- *Q17 Why would a dark-web listing relate to an AI incident?* Usually it wouldn't; treat as a lead. →
  *Enrichment only.*
- *Q18 10,000 endpoints?* Needs queue, batching, Postgres/Timescale, per-endpoint rate limits —
  unmeasured. → *Roadmap.*

---

## 4. APEX Injection Guard (implemented)

A core module with **two integration points** and a shared **session taint state**:

- **Context ingress — Injection Guard (`injection_guard.py`)**: scans untrusted content entering an
  agent for injection indicators, raises the session's taint. It is a **signal producer, never a gate**.
- **Action egress — Guardian (`guardian.py`)**: the **sole decision authority**. `validate_action(tool,
  args, manifest, taint)` applies baseline policy always; taint only **tightens**, never loosens. A
  missed detection still leaves the baseline in force.
- **Session Registry + capability manifest (`manifest.py`)**: makes objective-deviation deterministic —
  an action outside the manifest is a violation by definition.
- **Outcome labelling**: incidents are **Contained** (Guardian denied pre-execution, gateway mode) or
  **Exposed** (data actually left, e.g. canary/fingerprint confirmed). Each carries its **mode**.

Demonstrated end-to-end: an indirect injection on a web page raises taint → the agent proposes
`read_file(.env)` → Guardian **denies** it → one **Contained** incident with the full cause chain,
plus a **clean-page negative control** that is allowed and produces no severity.

---

## 5. Upgrade roadmap

**Tier 1 — shipped in this build (makes claims provable):**
- ✅ Canary tokens in the bait `.env` (ground truth for precision/recall)
- ✅ Checksum-validated PII (Aadhaar/Verhoeff, PAN, card/Luhn)
- ✅ Keyed-hash (HMAC) secret fingerprints linking a file read to a payload leak without storing the secret
- ✅ Declarative YAML scoring with fired-rule + `event_ids` citations
- ◻ Evidence-cited LLM output (copilot is grounded; strict JSON-with-event_ids is next)

**Tier 2 — next phase:**
- Real pre-execution enforcement via agent pre-tool-use hooks / MCP gateway (gateway mode hardening)
- Event pipeline with a queue (`ingest → queue → detectors → correlator`), idempotent, HMAC-signed agent events
- Entity-graph correlation (process/file/destination/fingerprint nodes), incremental + stateful
- Data-flow taint tracking (sensitive source → network sink in the same lineage)
- Prompt-injection detection on agent inputs feeding "external manipulation suspected"
- Policy engine (OPA/Rego or Cedar) with audit/warn/enforce modes and explicit fail-closed

**Tier 3 — production:**
- Sensors: eBPF/fanotify (Linux), ETW/Sysmon (Windows), Endpoint Security (macOS); offline buffering,
  heartbeats, agent self-protection; consider Go/Rust
- Pre-encryption at scale: enterprise forward proxy with org CA on **managed** devices only, documented
  consent, policy toggle (stated openly as it conflicts with "no TLS interception" otherwise)
- Storage: Postgres row-level security, Timescale/ClickHouse, append-only hash-chained audit log, mTLS
  enrolment with per-endpoint certs
- Standards: OpenTelemetry GenAI traces, MITRE ATLAS + OWASP LLM Top 10 tagging, STIX 2.1 / MISP export

---

## 6. Engineering practice that backs the claims

- **Replayable fixtures**: each scenario is a JSONL event stream (`samples/`) replayable in CI, asserting
  the exact incident and score.
- **Benchmark harness**: labelled secret/PII/clean samples; print precision & recall each run.
- **Self-observability**: OpenTelemetry on the platform; track ingest latency and agent CPU/RAM.
- **Contract-first API**: publish the OpenAPI spec and a fake event generator so detectors and UI build
  in parallel.
