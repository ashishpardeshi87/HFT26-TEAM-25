import { useEffect, useState } from "react";
import { getJSON } from "../../lib/api.js";

const sevRank = { critical: 0, high: 1, medium: 2 };

export default function Policy() {
  const [data, setData] = useState(null);
  const [cat, setCat] = useState("all");
  useEffect(() => { getJSON("/api/policy").then(setData).catch(() => {}); }, []);
  if (!data) return <div className="empty" style={{ marginTop: 18 }}>Loading policy…</div>;

  const s = data.summary;
  const cats = s.categories || {};
  const rules = (data.rules || []).filter((r) => cat === "all" || r.category === cat)
    .sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || a.id.localeCompare(b.id));

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Baseline floor · Guardian source of truth</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>AI Agent Security Policy</h1>
        </div>
        <span className="mono-label">v{s.policy_version} · {s.total} rules · {s.floor} floor</span>
      </div>

      <div className="grid g4" style={{ marginTop: 18 }}>
        <div className="panel panel-pad ticked"><div className="mono-label">Rules</div><div className="display" style={{ fontSize: "2.2rem" }}>{s.total}</div></div>
        <div className="panel panel-pad ticked"><div className="mono-label">Critical</div><div className="display" style={{ fontSize: "2.2rem", color: "var(--alert)" }}>{s.by_severity?.critical || 0}</div></div>
        <div className="panel panel-pad ticked"><div className="mono-label">Tighten-only floor</div><div className="display" style={{ fontSize: "2.2rem", color: "var(--acid)" }}>{s.floor}</div></div>
        <div className="panel panel-pad ticked"><div className="mono-label">Invariant</div><div className="snip" style={{ marginTop: 6, color: "var(--ink)" }}>{s.design_invariant}</div></div>
      </div>

      <div className="row wrap" style={{ gap: 8, marginTop: 16 }}>
        <button className="chip" style={{ cursor: "pointer", borderColor: cat === "all" ? "var(--acid)" : "var(--line-hard)", color: cat === "all" ? "var(--acid)" : "var(--ink-dim)" }} onClick={() => setCat("all")}>all</button>
        {Object.entries(cats).map(([k, v]) => (
          <button key={k} className="chip" style={{ cursor: "pointer", borderColor: cat === k ? "var(--acid)" : "var(--line-hard)", color: cat === k ? "var(--acid)" : "var(--ink-dim)" }} onClick={() => setCat(k)} title={v}>{k}</button>
        ))}
      </div>

      <div className="panel ticked" style={{ marginTop: 14 }}>
        <div className="panel-pad">
          <table>
            <thead>
              <tr><th style={{ width: 64 }}>ID</th><th>Rule</th><th style={{ width: 84 }}>Severity</th><th style={{ width: 128 }}>Enforcement</th><th style={{ width: 70 }}>Floor</th></tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td className="mono-label" style={{ color: "var(--acid)" }}>{r.id}</td>
                  <td><div style={{ fontSize: ".82rem", color: "var(--ink)" }}>{r.title}</div>
                      <div className="snip" style={{ fontSize: ".66rem" }}>{r.module} · CIS {(r.cis_controls || []).join(",")}</div></td>
                  <td><span className={`sev sev-${r.severity}`}>{r.severity}</span></td>
                  <td><span className="pill">{r.enforcement.replace("_", " ")}</span></td>
                  <td>{r.floor ? <span title="tighten-only" style={{ color: "var(--acid)" }}>🔒 floor</span> : <span className="snip">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
