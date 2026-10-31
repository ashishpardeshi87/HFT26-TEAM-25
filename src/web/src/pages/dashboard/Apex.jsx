import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../lib/api.js";
import { STANDARDS, standardsSummary, HANDLING } from "../../lib/reportStandards.js";

const STD = standardsSummary();

// Mirrors GET /attribution/status cannotDo. Duplicated deliberately so the limits
// survive a failed request — see the render site for why that matters.
const CANNOT_DO_FALLBACK = [
  "De-anonymize a competently operated hidden service. Published origin-recovery rates are roughly 5%; this finds the erring minority.",
  "Follow Monero. This is the largest structural erosion of the financial signal.",
  "Access gated communities autonomously. That requires human covert personas under lawful authority and is out of scope.",
  "Establish identity from stylometry alone, which degrades toward chance under deliberate obfuscation.",
  "Produce a verdict. The output is an investigative lead with quantified confidence for human adjudication.",
];

// ── DarkGuard APEX — capability console ─────────────────────────────────────
//
// A dedicated section for SIH26151, structured to the problem statement rather
// than to our own code layout. The PS names three core capabilities, an analytical
// front end, an autonomous mode, a stored field list and three export formats, so
// those are the headings — in that order — and each one states what is built,
// what is not, and what it cannot do.
//
// Status is READ FROM THE API (/attribution/status), never hardcoded here. That is
// deliberate: if the UI carried its own claims it would drift ahead of the
// implementation, which is exactly the failure this section exists to prevent.

// ── Info button ─────────────────────────────────────────────────────────────
// Click to pin open. Hover tooltips are unreachable by keyboard and vanish while
// you are still reading a two-sentence explanation.
function Info({ text, label = "Explain this" }) {
  const [open, setOpen] = useState(false);
  return (
    <span style={{ position: "relative", display: "inline-flex", verticalAlign: "middle" }}>
      <button
        type="button"
        aria-label={label}
        aria-expanded={open}
        onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
        style={{
          cursor: "pointer", width: 15, height: 15, lineHeight: "13px", padding: 0,
          marginLeft: 6, borderRadius: "50%", fontSize: ".64rem", fontWeight: 700,
          background: "transparent", border: `1px solid ${open ? "var(--acid)" : "var(--line-hard)"}`,
          color: open ? "var(--acid)" : "var(--ink-faint)", flex: "0 0 auto",
        }}
      >
        i
      </button>
      {open && (
        <span
          role="note"
          style={{
            position: "absolute", top: 21, left: 0, zIndex: 50, width: 300,
            padding: "10px 12px", background: "var(--panel, #12151c)",
            border: "1px solid var(--line-hard)", borderRadius: 4,
            fontSize: ".71rem", lineHeight: 1.55, color: "var(--ink-dim)",
            boxShadow: "0 8px 24px rgba(0,0,0,.5)", fontWeight: 400,
            whiteSpace: "normal", textAlign: "left",
          }}
        >
          {text}
        </span>
      )}
    </span>
  );
}

// ── Process canvas ──────────────────────────────────────────────────────────
// Six stages, in the order data actually moves. The confidence engine is drawn
// wider because it is the product rather than a step. Clicking a stage explains
// it, so the canvas is the explanation surface and not decoration.
const STAGES = [
  {
    id: "collect", n: 1, name: "Collect", tint: "var(--info)",
    sub: "Tor + clearnet, scheduled",
    what:
      "Harvests marketplace and forum links from public directories (dark.fail, tor.taxi, onion.live), then crawls them over our own bundled Tor daemon. Sweeps are scheduled and non-overlapping, with per-target circuit isolation. Passive retrieval only — no logins, no exploitation, no purchases.",
  },
  {
    id: "filter", n: 2, name: "Safety filter", tint: "var(--alert)",
    sub: "before any fetch",
    what:
      "A deterministic two-stage classifier runs BEFORE the request is made, so hard-blocked material is never requested and never lands on disk. For that category we retain nothing, not even the URL, and that is a rule in code rather than a model decision. Credentials and card numbers are counted, never stored.",
  },
  {
    id: "store", n: 3, name: "Store", tint: "var(--violet)",
    sub: "hashed at capture",
    what:
      "Every artefact is SHA-256 hashed at the moment of acquisition, over the raw response bytes before any normalisation, then Merkle-chained. Later alteration is therefore detectable. A contract test enforces that no assertion can exist without a resolvable evidence record — three fabrication attempts are rejected in CI.",
  },
  {
    id: "signals", n: 4, name: "Signals", tint: "var(--ok)",
    sub: "4 families, 6 types",
    what:
      "Infrastructure, identifiers, timing and writing style. Six signal types across four independent families — the families matter because they fail independently, which is what makes combining them informative rather than merely repetitive.",
  },
  {
    id: "decide", n: 5, name: "Confidence engine", tint: "var(--acid)", wide: true,
    sub: "LLR → dependence → calibration → ICD 203",
    what:
      "Each signal becomes a log-likelihood ratio and they sum in log-odds onto an open-set prior. Correlated signals are discounted so confidence is not double-counted. The result carries an ODNI ICD 203 band, an Admiralty source grade, and one of five tiers including INSUFFICIENT and CONTRADICTED. Calibration is applied and disclosed as its own row.",
  },
  {
    id: "deliver", n: 6, name: "Deliver", tint: "var(--warn)",
    sub: "dossier · CSV/JSON/report · re-tasking",
    what:
      "The analyst surface, the three export formats the PS requires, and the Next-Best-Evidence queue. That queue ranks the unobserved signal that would most reduce uncertainty and emits it as a collection task, which is what closes the loop from analysis back to collection.",
  },
];

function ProcessCanvas() {
  const [sel, setSel] = useState("decide");
  const active = STAGES.find((s) => s.id === sel);

  return (
    <div className="panel">
      <div className="panel-head">
        <span>
          // Pipeline
          <Info
            label="About the pipeline"
            text="The six stages in the order data moves. Tasking also flows backwards, from the confidence engine to collection, which is what makes this a loop rather than a one-way pipe. Click any stage for detail."
          />
        </span>
        <span className="tag">click a stage</span>
      </div>

      <div className="panel-pad">
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "stretch" }}>
          {STAGES.map((s, i) => {
            const on = s.id === sel;
            return (
              <div key={s.id} className="row center" style={{ gap: 8, flex: s.wide ? "1 1 240px" : "1 1 140px" }}>
                <button
                  onClick={() => setSel(s.id)}
                  aria-pressed={on}
                  style={{
                    cursor: "pointer", width: "100%", textAlign: "left",
                    padding: "10px 11px", borderRadius: 4,
                    background: on ? "color-mix(in srgb, var(--acid) 8%, transparent)" : "transparent",
                    border: `1px solid ${on ? s.tint : "var(--line)"}`,
                    borderLeft: `3px solid ${s.tint}`,
                  }}
                >
                  <div className="mono-label" style={{ fontSize: ".6rem", color: "var(--ink-faint)" }}>STEP {s.n}</div>
                  <div style={{ fontSize: ".8rem", fontWeight: 600, color: on ? "var(--ink)" : "var(--ink-dim)", marginTop: 2 }}>
                    {s.name}
                  </div>
                  <div className="snip" style={{ marginTop: 3, color: s.tint, fontSize: ".66rem" }}>{s.sub}</div>
                </button>
                {i < STAGES.length - 1 && (
                  <span aria-hidden="true" style={{ color: "var(--line-hard)", flex: "0 0 auto" }}>&#8594;</span>
                )}
              </div>
            );
          })}
        </div>

        <div
          style={{
            marginTop: 14, padding: "12px 14px", borderRadius: 4,
            background: "var(--bg)", borderLeft: `3px solid ${active.tint}`,
          }}
        >
          <b style={{ fontSize: ".82rem", color: active.tint }}>Step {active.n} — {active.name}</b>
          <div className="snip" style={{ marginTop: 6, lineHeight: 1.6 }}>{active.what}</div>
        </div>

        <div className="snip" style={{ marginTop: 10, color: "var(--ink-faint)" }}>
          Tasking flows backwards from step 5 to step 1. Nothing reaches step 3 without passing step 2.
        </div>
      </div>
    </div>
  );
}

// ── PS requirement blocks ───────────────────────────────────────────────────
const CAPABILITIES = [
  {
    key: "cap1",
    title: "Capability 1 — Hidden service misconfiguration",
    ps: "Finding misconfigurations in Tor hidden services — exposed server-status pages, SSL certificates tied to clearnet domains, default service banners, descriptor inconsistencies — and matching them with clearnet infrastructure to point to likely origin servers.",
    how:
      "Seven signals read passively from whatever the service already serves any anonymous visitor: TLS leaf certificate hash, response header ORDER, favicon hash, custom error-page hash, server banner, clock skew, and exposed status endpoints (/server-status, /nginx_status, /.env, /.git/config). Header order is the strong one because it reflects the server build rather than its configuration, so it is hard to match by coincidence.",
    limit:
      "This establishes SHARED HOSTING, which is an observable fact. It does not establish shared identity, which is an inference a human makes. A competently configured service may leak nothing and we report that rather than guessing.",
  },
  {
    key: "cap2-graph",
    title: "Capability 2 — Cross-marketplace identity graph",
    ps: "Mapping threat actors across multiple marketplaces into a single relationship graph of handles, PGP keys, wallets and trust links.",
    how:
      "Handles, PGP fingerprints, crypto addresses and trust links are first-class graph entities. Exact identifier matches score as hard evidence. When a handle rotates, the engine can compare whether its structure survived: provider, stem, separator convention and numbering. Entity resolution uses contradiction constraints so one weak bridge cannot silently fuse two actors.",
    limit:
      "Wallet clustering is not built. A shared address links payment flows but clusters derived from it are hypotheses, and CoinJoin-shaped transactions must be quarantined before merging or a false merge silently fuses two actors.",
  },
  {
    key: "cap3-temporal",
    title: "Capability 3a — Behavioural profiling",
    ps: "Behavioural profiling to link rebranded or migrated personas to known threat actors.",
    how:
      "Log-binned inter-event histograms compared by Jensen–Shannon divergence, circadian histograms for timezone inference, burstiness and absence-gap structure. This needs no labels and no training, and it is the only modality that survives identity mutation — people change handles far more easily than they change their sleep schedule. A crawl-coverage calendar masks collection gaps so an outage is never read as actor inactivity.",
    limit:
      "Below a 40-event threshold it emits UNKNOWN with the actual count rather than a weak score. Over-regular intervals are detected as automation rather than mistaken for a circadian rhythm.",
  },
  {
    key: "cap3-stylometric",
    title: "Capability 3b — Stylometric persona identification",
    ps: "AI-based stylometric persona identification.",
    how:
      "Vector comparison with bounded ratios, plus sign-off habits, price notation and category mix as interpretable operational features.",
    limit:
      "The dedicated two-model approach — interpretable features for the courtroom alongside a neural authorship embedding — is outstanding. General sentence embeddings are deliberately NOT used for authorship: they capture topic, and authorship needs style. Stylometry can never establish identity alone and degrades toward chance under deliberate obfuscation.",
  },
];

const DELIVERABLES = [
  {
    key: "confidence",
    title: "Attribution confidence",
    ps: "…attribution confidence…",
    how: "Log-likelihood ratios summed in log-odds over an open-set prior, with a dependence correction across correlated groups, isotonic-style calibration disclosed as its own waterfall row, an ODNI ICD 203 band, a two-axis Admiralty source grade, and five tiers. CONTRADICTED and INSUFFICIENT are real verdicts, not failure states.",
    limit: "Weights are reasoned, not fitted — there is no labelled corpus on disk yet, so every response returns calibration.validated = false. Fitting them requires public research archives, which is the declared next step.",
  },
  {
    key: "categories",
    title: "Category",
    ps: "…category…",
    how: "Zero-shot classification over the nine categories the PS names, using a pretrained MiniLM sentence model quantised to int8 and run on-device via ONNX Runtime. Each candidate is embedded once and assigned to the nearest category prototype, with an abstain floor of 0.35 so it declines rather than guesses.",
    limit: "Runtime readiness comes from DarkGuard. No evaluation figure is shown here unless it is supplied by a retained, versioned evaluation artifact.",
  },
  {
    key: "evidence",
    title: "Storage, source and last scan date",
    ps: "…collection, storage… last scan date and source.",
    how: "Acquisition-time SHA-256 over raw bytes, Merkle-chained, with a Bharatiya Sakshya Adhiniyam 2023 §63(4) Part A manifest generated automatically. Part B is left to a human expert as the statute requires. Source reliability is computed from provenance on the Admiralty scale, not hardcoded.",
    limit: "WARC capture and post-quantum signatures (ML-DSA) are scoped but not built. Today the integrity guarantee is the hash chain.",
  },
  {
    key: "export",
    title: "Export — CSV, JSON, report",
    ps: "The system shall also provide the facility to export the result set in CSV, JSON and report formats.",
    how: "Exports must be generated from the same live response object and retain unknowns, contradictions, provenance, collection mode and calibration status. No export may read more confidently than the screen.",
    limit: "STIX 2.1 bundle export for MISP/TAXII interoperability is not built.",
  },
];

export default function Apex() {
  const [status, setStatus] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    api("/attribution/status")
      .then(setStatus)
      .catch((e) => setErr(e?.message ?? "could not load status"));
  }, []);

  const scoreFor = (key) => status?.capabilities?.find((c) => c.id === key) ?? null;

  const Block = ({ item }) => {
    const sc = scoreFor(item.key);
    const pct = sc ? Math.round((sc.built / sc.of) * 100) : null;
    const tint = pct == null ? "var(--line-hard)" : pct >= 80 ? "var(--acid)" : pct >= 50 ? "var(--warn)" : "var(--alert)";

    return (
      <div className="panel" style={{ marginTop: 14 }}>
        <div className="panel-head" style={{ gap: 8, flexWrap: "wrap" }}>
          <span style={{ display: "inline-flex", alignItems: "center" }}>
            {item.title}
            <Info label={item.title} text={item.how} />
          </span>
          <span className="row center" style={{ gap: 8, marginLeft: "auto" }}>
            {status?.status === "ready" && item.key === "cap1" && <span className="chip" style={{ borderColor: "var(--info)", color: "var(--info)" }}>live bridge ready</span>}
            {sc && (
              <span className="chip" style={{ borderColor: tint, color: tint }} title={sc.note}>
                {sc.built} / {sc.of} built
              </span>
            )}
          </span>
        </div>

        <div className="panel-pad">
          <div
            className="snip"
            style={{ paddingLeft: 10, borderLeft: "2px solid var(--line-hard)", color: "var(--ink-faint)", fontStyle: "italic" }}
          >
            PS: {item.ps}
          </div>

          <div style={{ marginTop: 12 }}>
            <div className="mono-label" style={{ fontSize: ".62rem", color: "var(--acid)" }}>HOW IT WORKS</div>
            <div className="snip" style={{ marginTop: 4, lineHeight: 1.6 }}>{item.how}</div>
          </div>

          <div style={{ marginTop: 12 }}>
            <div className="mono-label" style={{ fontSize: ".62rem", color: "var(--warn)" }}>
              LIMITS AND WHAT IS OUTSTANDING
              <Info
                label="Why limits are shown"
                text="Stated before anyone asks. A system that reports its own gaps is auditable; one that reports only successes cannot be checked. Every figure on this page is either cited or marked as our own measurement with its conditions."
              />
            </div>
            <div className="snip" style={{ marginTop: 4, lineHeight: 1.6 }}>{item.limit}</div>
          </div>

          {sc && (
            <div className="snip" style={{ marginTop: 12, paddingTop: 8, borderTop: "1px dashed var(--line)", color: "var(--ink-faint)" }}>
              Self-reported status from the API: {sc.note}
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <>
      {/* ── Header ── */}
      <div className="panel">
        <div className="panel-head">
          <span>
            // DarkGuard APEX
            <Info
              label="About this section"
              text="Threat-actor attribution for SIH26151 (NTRO). This section is laid out to the problem statement rather than to our code, so each requirement can be checked against what is actually implemented. Every status figure is read from the API, never written here."
            />
          </span>
          <span className="tag">SIH26151 · NTRO</span>
        </div>
        <div className="panel-pad">
          <h2 style={{ fontSize: "1.05rem", margin: 0 }}>Detect the actor behind the changing identity</h2>
          <p className="snip" style={{ marginTop: 8, lineHeight: 1.65, maxWidth: 760 }}>
            The mandate asks the system to <b>store attribution confidence</b> and link actors to <b>suspect</b> real-world
            entities. Read precisely, that specifies auditable leads with quantified reliability — not a machine that
            names people. So the confidence engine is the product here, and collection is plumbing.
          </p>

          <div className="row center" style={{ gap: 8, flexWrap: "wrap", marginTop: 12 }}>
            <Link to="../attribution" className="chip" style={{ borderColor: "var(--acid)", color: "var(--acid)" }}>
              Open attribution console &#8594;
            </Link>
            {status && (
              <span className="chip" style={{ borderColor: status.status === "ready" ? "var(--ok)" : "var(--warn)", color: status.status === "ready" ? "var(--ok)" : "var(--warn)" }} title={status.corpus}>
                live mode: {status.status}
              </span>
            )}
          </div>

          {err && (
            <div className="snip" style={{ marginTop: 10, color: "var(--alert)" }}>
              Could not reach the status endpoint ({err}). The figures below are unavailable rather than assumed.
            </div>
          )}
        </div>
      </div>

      {/* ── Process ── */}
      <div style={{ marginTop: 14 }}>
        <ProcessCanvas />
      </div>

      {/* ── Three core capabilities ── */}
      <div className="panel-head" style={{ marginTop: 22, border: 0 }}>
        <span>
          // Three core capabilities
          <Info
            label="About the capabilities"
            text="The PS names three. They are kept separate on purpose: they fail independently, and that independence is what makes combining their evidence informative rather than merely repetitive. Behavioural signals alone can never reach the top confidence tier."
          />
        </span>
      </div>
      {CAPABILITIES.map((c) => <Block key={c.key} item={c} />)}

      {/* ── Expected solution ── */}
      <div className="panel-head" style={{ marginTop: 22, border: 0 }}>
        <span>
          // Expected solution — stored fields and export
          <Info
            label="About the stored field list"
            text="The PS names the fields that must be stored and queryable: attribution confidence, category, last scan date, source, and links to suspect entities. They appear in that order in the Actor Dossier tab of the attribution console."
          />
        </span>
      </div>
      {DELIVERABLES.map((d) => <Block key={d.key} item={d} />)}

      {/* ── Standards conformance ── */}
      <div className="panel" style={{ marginTop: 22 }}>
        <div className="panel-head" style={{ flexWrap: "wrap", gap: 8 }}>
          <span>
            // Standards conformance
            <Info
              label="About standards conformance"
              text="Every exported report names the standards it was produced to, and states the gap wherever conformance is partial. A conformance claim that hides its exceptions is not a conformance claim. Each identifier here was checked against the publisher rather than quoted from memory."
            />
          </span>
          <span className="chip" style={{ marginLeft: "auto", borderColor: "var(--line-hard)" }}>
            {STD.line}
          </span>
        </div>
        <div className="panel-pad">
          <table>
            <thead>
              <tr><th style={{ width: 210 }}>Standard</th><th>Applied to</th><th style={{ width: 96 }}>Status</th></tr>
            </thead>
            <tbody>
              {STANDARDS.map((s) => {
                const tint = s.status === "conformant" ? "var(--acid)" : s.status === "partial" ? "var(--warn)" : "var(--ink-faint)";
                return (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontSize: ".78rem" }}>{s.id}</div>
                      <div className="snip" style={{ fontSize: ".68rem" }}>{s.title}</div>
                    </td>
                    <td>
                      <div className="snip" style={{ marginTop: 0, lineHeight: 1.55 }}>{s.applies}</div>
                      {s.gap && (
                        <div className="snip" style={{ marginTop: 6, color: "var(--warn)", lineHeight: 1.5 }}>
                          Gap: {s.gap}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="chip" style={{ borderColor: tint, color: tint }}>{s.status}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <div className="snip" style={{ marginTop: 14, paddingTop: 10, borderTop: "1px dashed var(--line)" }}>
            <b style={{ color: "var(--ink)" }}>Handling.</b> {HANDLING.marking} — {HANDLING.note}
          </div>
        </div>
      </div>

      {/* ── What it cannot do ──
          Rendered from the API when reachable, from the constant below when not.
          This section is the one part of the page that must never be missing: a
          limits list that disappears when a request fails would leave the page
          reading as an unqualified capability claim. */}
      {(
        <div className="panel" style={{ marginTop: 22 }}>
          <div className="panel-head">
            <span>
              // What this system cannot do
              <Info
                label="Why this list exists"
                text="Volunteered rather than discovered. Read from the API so it cannot drift from the implementation. Knowing where the line sits is itself a technical credential."
              />
            </span>
          </div>
          <div className="panel-pad">
            {(status?.cannotDo ?? CANNOT_DO_FALLBACK).map((t, i) => (
              <div key={i} className="snip" style={{ padding: "7px 0", borderBottom: "1px dashed var(--line)", lineHeight: 1.6 }}>
                <span style={{ color: "var(--alert)", marginRight: 7 }}>&#215;</span>{t}
              </div>
            ))}
            <div className="snip" style={{ marginTop: 12, color: "var(--ink-faint)" }}>
              The output is an investigative lead with quantified confidence for human adjudication, never a verdict.
            </div>
          </div>
        </div>
      )}
    </>
  );
}
