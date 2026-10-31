import { useMemo } from "react";

// ── Live infrastructure collection canvas ───────────────────────────────────
//
// Replaces the generic six-modality canvas for live mode, which was simply the
// wrong diagram: it showed IDENTIFIER / TEMPORAL / STYLE / OPERATIONAL /
// RELATIONAL nodes that live collection never gathers, so they sat "queued"
// forever while real work happened elsewhere.
//
// This renders the pipeline live mode actually runs, as a left-to-right flow:
//
//   SERVICE A ──┐
//   (12 probes) ├──> SIGNAL COMPARISON ──> FUSION ──> VERDICT
//   SERVICE B ──┘
//
// Each service column lists every individual probe with its own state and result,
// because "what is happening right now" is the question the panel exists to
// answer. A spinner would answer it worse.
//
// Built with DOM rather than canvas: the content is a list of labelled rows with
// live text, which HTML lays out and makes selectable, and there is no free-form
// geometry that would justify pixel work.

// The probe sequence, in the order fingerprint.py performs it.
const PROBES = [
  { id: "root",        label: "Root page",        detail: "banner, header order, title, clock skew" },
  { id: "favicon",     label: "Favicon",          detail: "SHA-256 — rarely changed, often forgotten when cloning" },
  { id: "error_page",  label: "Error page",       detail: "SHA-256 of a 404 body — highly operator-specific" },
  { id: "status",      label: "Status endpoints", detail: "9 public paths: /server-status, /.env, /.git/config …" },
  { id: "tls",         label: "TLS certificate",  detail: "leaf SHA-256 — a shared cert is near-conclusive" },
];

const STAGE = { pending: "pending", active: "active", done: "done", failed: "failed", skipped: "skipped" };

const DOT = {
  pending: "var(--line-hard)",
  active: "var(--acid)",
  done: "var(--ok)",
  failed: "var(--alert)",
  skipped: "var(--ink-faint)",
};

/**
 * Derive per-probe state for both services from the event stream.
 * Pure, so it memoizes on the events array.
 */
function derive(events, hosts) {
  const side = (s) => ({
    host: hosts?.[s] || null,
    started: false,
    done: false,
    reachable: null,
    probes: Object.fromEntries(PROBES.map((p) => [p.id, { state: STAGE.pending, note: null }])),
    findings: [],
  });
  const st = { a: side("a"), b: side("b"), comparing: false, compared: false, summary: null };

  for (const e of events) {
    const s = e.side ? st[e.side] : null;

    switch (e.step) {
      case "service_start":
        if (s) s.started = true;
        break;

      case "connecting":
        if (s) s.probes.root = { state: STAGE.active, note: "building Tor circuit…" };
        break;

      case "fetched":
        if (s) {
          s.reachable = true;
          s.probes.root = {
            state: STAGE.done,
            note: `HTTP ${e.status} in ${e.seconds}s — ${e.detail || ""}`,
          };
        }
        break;

      case "probing": {
        if (!s) break;
        const d = String(e.detail || "");
        const id = d.includes("favicon") ? "favicon"
          : d.includes("error page") ? "error_page"
          : d.includes("status endpoint") ? "status"
          : d.includes("TLS") ? "tls" : null;
        if (id) {
          s.probes[id] = {
            state: STAGE.active,
            note: id === "status" ? d.replace("status endpoint ", "") : "reading…",
          };
        }
        break;
      }

      case "leak_found":
        if (s) {
          s.probes.status = { state: STAGE.done, note: `${e.path} exposed (${e.length} bytes)` };
          s.findings.push({ kind: "leak", text: `${e.path} — ${e.length} bytes` });
        }
        break;

      case "tls_found":
        if (s) {
          s.probes.tls = { state: STAGE.done, note: e.subject ? `subject ${e.subject}` : "certificate captured" };
          s.findings.push({ kind: "tls", text: "TLS leaf certificate captured" });
        }
        break;

      case "offline":
        if (s) {
          s.reachable = false;
          s.done = true;
          s.probes.root = { state: STAGE.failed, note: e.reason || "no response over Tor" };
          for (const p of PROBES.slice(1)) s.probes[p.id] = { state: STAGE.skipped, note: "service unreachable" };
        }
        break;

      case "blocked":
        if (s) {
          s.reachable = false;
          s.done = true;
          s.probes.root = { state: STAGE.failed, note: e.reason || "dropped by safety filter" };
          for (const p of PROBES.slice(1)) s.probes[p.id] = { state: STAGE.skipped, note: "not requested" };
        }
        break;

      case "fingerprinted":
      case "service_done":
        if (s) {
          s.done = true;
          if (e.reachable === false) s.reachable = false;
          // Anything still pending or active finished without a result.
          for (const p of PROBES) {
            const cur = s.probes[p.id];
            if (cur.state === STAGE.active || cur.state === STAGE.pending) {
              s.probes[p.id] = {
                state: s.reachable === false ? STAGE.skipped : STAGE.done,
                note: cur.note && cur.state === STAGE.active ? cur.note : "no result",
              };
            }
          }
        }
        break;

      case "comparing":
        st.comparing = true;
        break;

      case "compared":
        st.comparing = false;
        st.compared = true;
        st.summary = { observable: e.observable, matched: e.matched, detail: e.detail };
        break;

      default:
        break;
    }
  }
  return st;
}

export default function LiveInfraCanvas({ events = [], hosts = null, status = "running", verdict = null }) {
  const st = useMemo(() => derive(events, hosts), [events, hosts]);
  const running = status === "running";

  return (
    <div className="liveflow">
      {/* Stage rail */}
      <div className="liveflow-rail">
        {[
          ["Service A", st.a.done ? STAGE.done : st.a.started ? STAGE.active : STAGE.pending],
          ["Service B", st.b.done ? STAGE.done : st.b.started ? STAGE.active : STAGE.pending],
          ["Compare signals", st.compared ? STAGE.done : st.comparing ? STAGE.active : STAGE.pending],
          ["Fuse & grade", verdict ? STAGE.done : st.compared ? STAGE.active : STAGE.pending],
        ].map(([label, state], i, arr) => (
          <div key={label} className="liveflow-stage">
            <span className="liveflow-dot" style={{ background: DOT[state], boxShadow: state === STAGE.active ? `0 0 0 4px rgba(198,255,58,.15)` : "none" }} />
            <span style={{ color: state === STAGE.active ? "var(--acid)" : state === STAGE.done ? "var(--ok)" : "var(--ink-faint)" }}>
              {label}
            </span>
            {i < arr.length - 1 && <span className="liveflow-arrow">→</span>}
          </div>
        ))}
      </div>

      {/* Two service columns */}
      <div className="liveflow-cols">
        {["a", "b"].map((k) => {
          const s = st[k];
          return (
            <div className="liveflow-col" key={k}>
              <div className="liveflow-colhead">
                <span className="mono-label">SERVICE {k.toUpperCase()}</span>
                <span
                  className="mono-label"
                  style={{ color: s.reachable === true ? "var(--ok)" : s.reachable === false ? "var(--alert)" : "var(--ink-faint)" }}
                >
                  {s.reachable === true ? "reachable" : s.reachable === false ? "unreachable" : s.started ? "connecting…" : "queued"}
                </span>
              </div>
              <div className="brk snip" style={{ marginBottom: 10 }}>{s.host || "—"}</div>

              {PROBES.map((p) => {
                const pr = s.probes[p.id];
                return (
                  <div className="liveflow-probe" key={p.id}>
                    <span className="liveflow-dot" style={{
                      background: DOT[pr.state],
                      animation: pr.state === STAGE.active ? "pulse 1.1s ease-in-out infinite" : "none",
                    }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="row between" style={{ gap: 8 }}>
                        <b style={{
                          fontSize: ".78rem",
                          color: pr.state === STAGE.active ? "var(--acid)"
                            : pr.state === STAGE.done ? "var(--ink)"
                            : pr.state === STAGE.failed ? "var(--alert)" : "var(--ink-faint)",
                        }}>{p.label}</b>
                        {pr.state === STAGE.active && <span className="mono-label" style={{ color: "var(--acid)" }}>reading</span>}
                      </div>
                      <div className="snip" style={{ marginTop: 1 }}>{pr.note || p.detail}</div>
                    </div>
                  </div>
                );
              })}

              {!!s.findings.length && (
                <div style={{ marginTop: 8, paddingTop: 8, borderTop: "1px dashed var(--line)" }}>
                  {s.findings.map((f, i) => (
                    <div key={i} className="snip" style={{ color: f.kind === "leak" ? "var(--alert)" : "var(--warn)" }}>
                      ▸ {f.text}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Comparison + fusion */}
      <div className="liveflow-merge">
        <div className="liveflow-mergebox" style={{ borderColor: st.compared ? "var(--ok)" : st.comparing ? "var(--acid)" : "var(--line-hard)" }}>
          <div className="mono-label" style={{ color: st.comparing ? "var(--acid)" : st.compared ? "var(--ok)" : "var(--ink-faint)" }}>
            SIGNAL COMPARISON
          </div>
          <div className="snip" style={{ marginTop: 4 }}>
            {st.summary
              ? st.summary.detail
              : st.comparing
                ? "scoring agreement across both fingerprints…"
                : "waiting for both fingerprints"}
          </div>
        </div>

        <span className="liveflow-arrow" style={{ fontSize: "1.1rem" }}>→</span>

        <div className="liveflow-mergebox" style={{ borderColor: verdict ? "var(--acid)" : "var(--line-hard)" }}>
          <div className="mono-label" style={{ color: verdict ? "var(--acid)" : "var(--ink-faint)" }}>FUSION</div>
          <div className="snip" style={{ marginTop: 4 }}>
            {verdict
              ? `${verdict.tier} · ${verdict.icd203.band} · ${(verdict.posterior * 100).toFixed(1)}%`
              : "likelihood ratios → dependence correction → calibration"}
          </div>
        </div>
      </div>

      <div className="liveflow-foot">
        {running
          ? `Collecting over Tor — ${events.length} step(s) so far. Roughly 12 requests per service, so this takes minutes.`
          : status === "failed"
            ? "Collection failed."
            : `Collection complete — ${events.length} steps.`}
      </div>
    </div>
  );
}
