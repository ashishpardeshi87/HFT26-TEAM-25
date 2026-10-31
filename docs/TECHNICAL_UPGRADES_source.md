SENTINEL APEX: Technical & Architectural
Upgrades
 Oct 30, 2026  ·  @saif
Overview
The upgrades are ranked by payoff versus effort: Tier 1 is realistic tonight, while Tiers 2
and 3 belong in the roadmap and the pitch. If you pick only three for tonight, take canary
tokens, keyed-hash fingerprint linking and the evidence-cited score breakdown. Together
they make the correlation provable instead of just plausible.
Tier 1: cheap changes that make the demo stronger.
Tier 2: architecture changes for the next phase.
Tier 3: production-grade capabilities.
Engineering practice: habits that back up your claims with measurements.
Tier 1: cheap changes that strengthen the demo
Five small additions turn the pipeline from "plausible" into "provable", and each is doable
in hours.
Upgrade How it works Why it helps
Canary tokens in the
bait .env
Plant a unique fake credential (e.g.
AKIA  plus a random marker). If
that exact value appears in an
outbound payload, exfiltration is
near-certain.
Gives ground truth for your
precision/recall numbers.
Checksum-validated
PII detection
Validate Aadhaar with the
Verhoeff checksum, PAN by its
structural format, and cards with
Luhn.
Sharply cuts false positives,
which is easy to show to
judges.
Keyed-hash
fingerprints for
secrets
Redact locally but keep
HMAC(org_key, secret)  as a
fingerprint.
Links a file read to a payload
finding without storing the
secret.
SENTINEL APEX: Technical & Architectural Upgrades
Page 1 of 4
Treat redacted payloads as untrusted input to the LLM, because they can contain prompt
injection. Give the explainer no tools.
Tier 2: architecture changes for the next phase
The biggest gap versus the PRD is real pre-execution enforcement, because polling
sensors can only detect after the fact. The rest of this tier makes correlation structural
rather than time-window based.
Pre-execution enforcement via agent hooks and an MCP gateway. Many coding
agents expose pre-tool-use hooks (Claude Code's PreToolUse  is one). A Guardian
hook or MCP proxy can allow or deny a file read or shell command before it runs, and it
gives you structured intent (tool name, arguments) that is far richer than inferring from
OS events.
Event pipeline with a queue. Split ingest into ingest → queue → detectors →
correlator . An in-process asyncio.Queue  is fine now, with Redis Streams or NATS
later. Require idempotent ingestion (dedupe on event_id ), Pydantic v2 schemas with
schema_version , and HMAC-signed events from agents.
Correlation as an entity graph. Model processes, files, destinations and secret
fingerprints as nodes, and events as edges. Correlate by process lineage and
fingerprint overlap, not only time windows. Keep it stateful and incremental so
incidents can merge and update. It also gives the dashboard a process-tree and
incident-graph view (React Flow or Cytoscape).
Data-flow taint tracking. Tag data read from sensitive sources ( .env , SSH keys) and
flag it when it reaches a network sink within the same process lineage. This is the
technical core of agentic exfiltration and is stronger than counting suspicious events.
Prompt-injection detection on agent inputs. Scan what the agent ingests (web pages,
repo files, API responses) for injection patterns and correlate that with unexpected
behaviour afterward. This makes the "external manipulation suspected" classification
Upgrade How it works Why it helps
Declarative scoring
rules
Put weights in YAML (e.g.
sensitive_file: +30 ,
unapproved_provider: +25 ) and
store the fired rules on each
incident.
The explainable score
becomes data rather than UI
decoration.
Evidence-cited LLM
output
Force the Orchestrator to return
JSON where every claim carries
event_ids ; reject output that
cites nothing.
Keeps the LLM an explainer,
not a source of unsupported
claims.
SENTINEL APEX: Technical & Architectural Upgrades
Page 2 of 4
evidence-based rather than a label.
Policy engine. Replace hardcoded rules with OPA/Rego or Cedar. Support audit ,
warn  and enforce  modes per policy, set an explicit fail-open or fail-closed behaviour,
and log every decision with its policy version and inputs.
Tier 3: production-grade capabilities
These move SENTINEL from a convincing prototype to something deployable, and they
are best presented as roadmap items.
Area Upgrade
Sensors Replace psutil polling with eBPF/fanotify (Linux),
ETW or Sysmon (Windows) and Endpoint Security
(macOS); ingesting Sysmon logs is a fast Windows
win. Add offline buffering with a local SQLite
queue, retry, heartbeats and agent self-protection.
Consider Go or Rust for footprint and tamper
resistance.
Pre-encryption visibility Beyond the browser extension, use an enterprise
forward proxy with an organization-installed CA on
managed devices. This conflicts with the "no TLS
interception" principle unless scoped explicitly:
managed devices only, documented consent, and a
policy toggle. State that openly if you include it.
Storage and enrollment Postgres with row-level security for multi-tenancy,
and Timescale or ClickHouse for high-volume
events. Keep the audit log append-only and hash-
chained so response actions are tamper-evident.
Enroll endpoints with one-time tokens that mint
per-endpoint client certificates (mTLS) instead of
a shared JWT.
Standards alignment Emit agent traces using OpenTelemetry GenAI
semantic conventions. Tag incidents with MITRE
ATLAS and OWASP LLM Top 10 categories. Export
TRACE indicators as STIX 2.1 or to MISP so
DarkGuard output is interoperable.
SENTINEL APEX: Technical & Architectural Upgrades
Page 3 of 4
Engineering practice that supports your claims
Your PRD says no number should be claimed until it is measured, and these four habits
produce the measurements.
Replayable scenario fixtures: store each demo scenario as a JSONL event stream and
replay it in CI, asserting the exact incident and score.
Benchmark harness: keep labeled secrets, PII and clean samples, and print precision
and recall on every run.
Self-observability: use OpenTelemetry on the platform itself and track ingest latency
and agent CPU/RAM, which are your own stated success metrics.
Contract-first API: publish the OpenAPI spec and a fake event generator so the
frontend and detectors can be built in parallel.
Next steps
Start with the three tonight picks, then draft the two artifacts that unblock the rest.
Area Upgrade
TRACE/DarkGuard connectors Use an async job queue and a common connector
interface with rate limits. Enforce typed
confidence labels ( observed , exact_match ,
reported , correlated , hypothesis ) in the
schema so the UI cannot overstate a lead. Look up
sensitive indicators by hash rather than plaintext
wherever the source supports it.
Add canary tokens to the bait .env  and the toy-agent scenario.
Add HMAC fingerprints so file reads and payload findings link without storing secrets.
Build the evidence-cited score breakdown from declarative YAML rules.
Draft event schema v2 with fingerprint fields.
Draft the scoring YAML with weights and fired-rule output.
SENTINEL APEX: Technical & Architectural Upgrades
Page 4 of 4