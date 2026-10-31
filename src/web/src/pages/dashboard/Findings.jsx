import { useEffect, useMemo, useState } from "react";
import { darkguardApi as api, downloadDarkguardFile } from "../../lib/darkguardApi.js";
import { useToast } from "../../lib/ui.jsx";

export default function Findings() {
  const toast = useToast();
  const [all, setAll] = useState(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const { scans } = await api("/scans");
        const rows = [];
        const failures = [];
        for (const s of (scans || []).filter((x) => x.status === "completed")) {
          try {
            const { scan } = await api(`/scans/${s.id}`);
            for (const f of scan?.findings || []) rows.push({ ...f, _target: scan.target_url || scan.query, _sid: s.id });
          } catch (detailError) {
            failures.push(detailError.message || `Could not load scan ${s.id}.`);
          }
        }
        if (!active) return;
        setAll(rows);
        setError(failures.length ? failures.join("; ") : "");
      } catch (loadError) {
        if (!active) return;
        setAll([]);
        setError(loadError.message || "Findings are unavailable.");
      }
    })();
    return () => { active = false; };
  }, []);

  const rows = useMemo(() => (all || []).filter((f) => !filter || f.severity === filter), [all, filter]);

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Findings</div>
          <h1 className="display">All exposure</h1>
          <p>Every finding across your scans, all sources.</p>
        </div>
        <button className="btn btn-sm" onClick={() => downloadDarkguardFile("/export/findings.csv", "darkguard-findings.csv").catch((e) => toast(e.message, "error"))}>↓ Export CSV</button>
      </div>

      <div className="toolbar">
        <span className="mono-label">Severity</span>
        <select className="input" style={{ width: "auto" }} value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="">All</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {error && (
        <div className="banner" style={{ marginBottom: 16, borderColor: "var(--alert)", color: "var(--alert)" }}>
          <span>// Findings unavailable or incomplete: {error}</span>
        </div>
      )}

      <div className="panel">
        <div className="panel-head"><span>Findings</span><span className="tag">{rows.length}</span></div>
        {all === null ? <div className="empty">Loading…</div> : rows.length === 0 ? <div className="empty">No findings are available.</div> : (
          <table>
            <thead><tr><th>Severity</th><th>Category</th><th>Detail</th><th>Source</th><th>Scan</th></tr></thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={i}>
                  <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                  <td className="muted">{f.category}</td>
                  <td>{f.title || "—"}<div className="snip brk">{f.onion_url || ""}</div></td>
                  <td className="muted">{f.engine}</td>
                  <td className="muted brk">{f._target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
