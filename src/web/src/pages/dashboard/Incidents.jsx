import { useOutletContext } from "react-router-dom";
import { useState, useEffect } from "react";
import EvidenceGraph from "../../components/EvidenceGraph.jsx";
import AttackGraphCanvas from "../../components/AttackGraphCanvas.jsx";
import { postJSON, getJSON } from "../../lib/api.js";

const PROBLEM_NAMES = {
  1: "Unauthorized tool usage", 2: "Memory poisoning", 3: "Malicious plugins/tools",
  4: "Goal manipulation", 5: "Harmful autonomous actions", 6: "Indirect prompt injection",
  7: "Multi-agent comms attacks", 8: "Identity & permission misuse",
};
const statusColor = (st) => st === "exposed" ? "var(--alert)" : st === "contained" ? "var(--ok)" : "var(--ink-dim)";

export default function Incidents() {
  const feed = useOutletContext();
  const [sel, setSel] = useState(null);
  const selected = feed.incidents.find((i) => i.incident_id === sel) || feed.incidents[0] || null;

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Investigations</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Incidents</h1>
        </div>
        <span className="mono-label">{feed.incidents.length} total</span>
      </div>

      {feed.incidents.length === 0 ? (
        <div className="panel ticked" style={{ marginTop: 18 }}>
          <div className="panel-pad"><div className="empty">No incidents yet. SENTINEL is waiting for authenticated sensor or Guardian-gateway telemetry from the active session.</div></div>
        </div>
      ) : (
        <div className="grid" style={{ marginTop: 18, gridTemplateColumns: "minmax(280px,1fr) 1.6fr", gap: 18, alignItems: "start" }}>
          {/* list */}
          <div style={{ display: "grid", gap: 10, maxHeight: "78vh", overflow: "auto" }}>
            {feed.incidents.map((inc) => (
              <button key={inc.incident_id} onClick={() => setSel(inc.incident_id)}
                className="panel ticked" style={{
                  textAlign: "left", cursor: "pointer", padding: 14,
                  outline: selected?.incident_id === inc.incident_id ? "2px solid var(--acid)" : "none",
                }}>
                <div className="row between center" style={{ gap: 8 }}>
                  <span className={`sev sev-${inc.level}`}>{inc.level}</span>
                  <b className="display" style={{ fontSize: "1.3rem", color: statusColor(inc.status) }}>{inc.score}</b>
                </div>
                <div style={{ marginTop: 8, fontSize: ".86rem", color: "var(--ink)" }}>{inc.title}</div>
                <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                  <span className="pill" style={{ color: statusColor(inc.status), borderColor: statusColor(inc.status) }}>{inc.status}</span>
                  <span className="pill">{inc.mode}</span>
                  {(inc.problems || []).map((p) => <span key={p} className="pill" title={PROBLEM_NAMES[p]}>P{p}</span>)}
                </div>
              </button>
            ))}
          </div>

          {/* detail */}
          {selected && <IncidentDetail inc={selected} />}
        </div>
      )}
    </div>
  );
}

function IncidentDetail({ inc }) {
  const [q, setQ] = useState("");
  const [ans, setAns] = useState(null);
  const [loading, setLoading] = useState(false);
  const [graph, setGraph] = useState(null);     // Feature A
  const [report, setReport] = useState(null);    // Feature C
  const [zt, setZt] = useState([]);              // Feature B

  useEffect(() => {
    setAns(null); setQ(""); setGraph(null); setReport(null); setZt([]);
    const id = inc.incident_id;
    getJSON(`/api/incidents/${id}/graph`).then(setGraph).catch(() => {});
    getJSON(`/api/incidents/${id}/report`).then(setReport).catch(() => {});
    getJSON(`/api/incidents/${id}/zerotrust`).then((r) => setZt(r.decisions || [])).catch(() => {});
  }, [inc.incident_id]);

  async function ask() {
    setLoading(true);
    const r = await postJSON("/api/copilot", { question: q || "Explain this incident and how to fix it.", incident_id: inc.incident_id });
    setAns(r); setLoading(false);
  }

  return (
    <div className="panel ticked" style={{ position: "sticky", top: 16 }}>
      <div className="panel-head">
        <span>Incident · {inc.host}</span>
        <span className="tag" style={{ color: statusColor(inc.status) }}>{inc.status} · {inc.mode}</span>
      </div>
      <div className="panel-pad">
        <div className="row wrap center" style={{ gap: 8 }}>
          <span className={`sev sev-${inc.level}`}>{inc.level}</span>
          {inc.taint > 0 && <span className="pill" style={{ color: "var(--violet)", borderColor: "var(--violet)" }}>taint {inc.taint}</span>}
          {(inc.problems || []).map((p) => <span key={p} className="pill" style={{ color: "var(--acid)", borderColor: "var(--acid)" }} title={PROBLEM_NAMES[p]}>P{p} {PROBLEM_NAMES[p]}</span>)}
        </div>
        <h2 className="display" style={{ fontSize: "1.3rem", marginTop: 12 }}>{inc.title}</h2>

        <div className="row center" style={{ gap: 16, marginTop: 14, padding: 14, border: "1.5px solid var(--line-hard)", background: "var(--bg)" }}>
          <div className="display" style={{ fontSize: "2.6rem", color: statusColor(inc.status) }}>{inc.score}</div>
          <div>
            <div className="mono-label">Illustrative risk · supporting signal only · 0–100</div>
            <div className="snip" style={{ marginTop: 4, color: "var(--ink)" }}>{inc.ai_explanation}</div>
          </div>
        </div>

        {inc.guardian?.length > 0 && (
          <>
            <div className="mono-label" style={{ marginTop: 18 }}>APEX Guardian · pre-execution decisions</div>
            {inc.guardian.map((g, i) => (
              <div key={i} style={{ marginTop: 8, padding: 10, border: "1.5px solid", borderColor: g.decision === "deny" || g.decision === "pause" ? "var(--alert)" : "var(--ok)", background: g.decision === "deny" || g.decision === "pause" ? "rgba(255,69,58,.08)" : "rgba(61,220,151,.08)" }}>
                <b style={{ color: g.decision === "deny" || g.decision === "pause" ? "var(--alert)" : "var(--ok)", textTransform: "uppercase" }}>{g.decision}</b>
                <span className="snip" style={{ marginLeft: 8 }}>{g.reason}</span>
              </div>
            ))}
          </>
        )}

        {/* Feature A — attack graph (event lineage, B2 causality labels) */}
        <div className="mono-label" style={{ marginTop: 18 }}>Attack graph · event lineage</div>
        <div style={{ marginTop: 8 }}>{graph ? <AttackGraphCanvas data={graph} /> : <div className="empty">loading graph…</div>}</div>

        {/* Feature B — zero-trust four-axis re-check */}
        {zt.length > 0 && (
          <>
            <div className="mono-label" style={{ marginTop: 18 }}>Zero-trust re-check · every sensitive action, stateless</div>
            <div style={{ marginTop: 8, display: "grid", gap: 10 }}>
              {zt.map((d, i) => {
                const bad = d.decision === "deny";
                const col = bad ? "var(--alert)" : d.decision === "require_approval" ? "var(--warn)" : "var(--ok)";
                return (
                  <div key={i} style={{ border: `1.5px solid ${col}`, background: "var(--bg)", padding: 10 }}>
                    <div className="row between center" style={{ gap: 8, flexWrap: "wrap" }}>
                      <span className="snip" style={{ color: "var(--ink)" }}><b>{d.tool}</b>({d.args}) · <span className="muted">{d.category}</span></span>
                      <b style={{ color: col, textTransform: "uppercase" }}>{d.decision.replace("_", " ")}</b>
                    </div>
                    <div className="grid" style={{ gridTemplateColumns: "repeat(2,1fr)", gap: 6, marginTop: 8 }}>
                      {d.axes.map((a) => (
                        <div key={a.axis} className="snip" style={{ color: a.ok ? "var(--ok)" : "var(--alert)" }}>
                          {a.ok ? "✓" : "✗"} <b style={{ textTransform: "uppercase" }}>{a.axis}</b> — <span style={{ color: "var(--ink-dim)" }}>{a.detail}</span>
                        </div>
                      ))}
                    </div>
                    <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                      {(d.ag_rules || []).map((r) => <span key={r} className="pill" style={{ color: "var(--acid)", borderColor: "var(--acid)" }}>{r}</span>)}
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}

        {/* Feature C — investigation assistant (evidence-only) */}
        {report && (
          <>
            <div className="row between center" style={{ marginTop: 18, gap: 8 }}>
              <span className="mono-label">Investigation report · evidence-only</span>
              <span className="pill" style={{ color: report.evidence_only ? "var(--ok)" : "var(--alert)", borderColor: report.evidence_only ? "var(--ok)" : "var(--alert)" }}>
                {report.evidence_only ? "every line cites an event" : "uncited claim!"}
              </span>
            </div>
            <div style={{ marginTop: 8, padding: 12, border: "1.5px solid var(--line-hard)", background: "var(--bg)" }}>
              <p className="snip" style={{ color: "var(--ink)" }}>{report.summary}</p>

              {report.cause_chain?.steps?.length > 0 && (
                <div className="row wrap center" style={{ gap: 6, marginTop: 10 }}>
                  <span className="mono-label">CAUSE CHAIN</span>
                  {report.cause_chain.steps.map((s, i) => (
                    <span key={s.event_id} className="row center" style={{ gap: 6 }}>
                      {i > 0 && <span style={{ color: "var(--acid)" }}>→</span>}
                      <span className="pill" style={{ color: s.outcome === "blocked" ? "var(--alert)" : "var(--ink)" }}>{s.label}</span>
                    </span>
                  ))}
                </div>
              )}

              <div className="mono-label" style={{ marginTop: 14 }}>TIMELINE</div>
              <div style={{ marginTop: 6, display: "grid", gap: 4 }}>
                {report.timeline.map((t) => (
                  <div key={t.event_id} className="snip" style={{ color: "var(--ink-dim)" }}>
                    <span style={{ color: "var(--acid)" }}>{t.ts.slice(11, 19)}</span> {t.text}
                    <span className="muted" style={{ marginLeft: 6 }}>#{t.event_id.slice(-6)}</span>
                  </div>
                ))}
              </div>

              <div className="mono-label" style={{ marginTop: 14 }}>FINDINGS · each tied to an event</div>
              <div style={{ marginTop: 6, display: "grid", gap: 4 }}>
                {report.findings.map((f, i) => (
                  <div key={i} className="snip">
                    <span className={`sev sev-${f.severity}`} style={{ marginRight: 6 }}>{f.severity}</span>
                    <span style={{ color: "var(--ink)" }}>{f.text}</span>
                    <span className="muted" style={{ marginLeft: 6 }}>#{f.event_id.slice(-6)}</span>
                  </div>
                ))}
              </div>

              <div className="mono-label" style={{ marginTop: 14 }}>RECOMMENDED RESPONSE</div>
              <ul style={{ marginTop: 6, paddingLeft: 2, listStyle: "none", display: "grid", gap: 5 }}>
                {report.recommended_action.map((r, i) => (
                  <li key={i} className="snip" style={{ color: "var(--ink)" }}>▸ {r.text}
                    <span className="muted" style={{ marginLeft: 6 }}>{r.event_ids.map((e) => "#" + e.slice(-6)).join(" ")}</span>
                  </li>
                ))}
              </ul>
              <div className="snip" style={{ marginTop: 10, color: "var(--ink-faint)" }}>{report.causality_note}</div>
            </div>
          </>
        )}

        {/* entity correlation view (kept) */}
        <div className="mono-label" style={{ marginTop: 18 }}>Evidence graph · entities</div>
        <div style={{ marginTop: 8, border: "1.5px solid var(--line-hard)", padding: 8 }}><EvidenceGraph graph={inc.graph} /></div>

        <div className="mono-label" style={{ marginTop: 18 }}>Why this score · every rule cites its events</div>
        <div style={{ marginTop: 8, display: "grid", gap: 6 }}>
          {(inc.fired_rules || []).map((r, i) => (
            <div key={i} className="row between center" style={{ gap: 8, borderLeft: "3px solid var(--acid)", padding: "5px 10px", background: "var(--bg)" }}>
              <span className="snip" style={{ color: "var(--ink)" }}><b style={{ color: "var(--alert)" }}>+{r.points}</b> {r.detail}</span>
              {r.event_ids?.length > 0 && <span className="snip">{r.event_ids.length} evt</span>}
            </div>
          ))}
        </div>

        {inc.darkguard && (
          <div style={{ marginTop: 18, padding: 12, border: "1.5px solid var(--info)", background: "rgba(76,201,240,.07)" }}>
            <div className="row center" style={{ gap: 12 }}>
              <div className="display" style={{ fontSize: "1.8rem", color: "var(--info)" }}>{inc.darkguard.exposure_score}</div>
              <div className="snip">DarkGuard live evidence: {(inc.darkguard.sources || []).join(", ") || "no sources returned"}</div>
            </div>
          </div>
        )}

        <div className="mono-label" style={{ marginTop: 18 }}>Remediation</div>
        <ul style={{ marginTop: 8, paddingLeft: 2, listStyle: "none", display: "grid", gap: 5 }}>
          {(inc.remediation || []).map((r, i) => <li key={i} className="snip" style={{ color: "var(--ink)" }}>▸ {r}</li>)}
        </ul>

        <div className="mono-label" style={{ marginTop: 18 }}>Ask the Featherless copilot</div>
        <div className="row" style={{ marginTop: 8, gap: 8 }}>
          <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Why is this critical? What do we fix first?" onKeyDown={(e) => { if (e.key === "Enter") ask(); }} />
          <button className="btn btn-sm btn-primary" onClick={ask} disabled={loading}>{loading ? "…" : "Ask"}</button>
        </div>
        {ans && (
          <div style={{ marginTop: 10, padding: 12, border: "1.5px solid var(--line-hard)", background: "var(--bg)" }}>
            <div className="mono-label" style={{ color: "var(--acid)" }}>Copilot {ans.used_llm ? "· Featherless summary" : "· deterministic citation guard"}</div>
            <p className="snip" style={{ marginTop: 6, color: "var(--ink)", lineHeight: 1.6 }}>{ans.answer}</p>
          </div>
        )}
      </div>
    </div>
  );
}
