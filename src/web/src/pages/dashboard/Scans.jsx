import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../lib/api.js";

const fmt = (d) => { try { return new Date(d + "Z").toLocaleString(); } catch { return d; } };

export default function Scans() {
  const nav = useNavigate();
  const [scans, setScans] = useState(null);

  useEffect(() => { api("/scans").then(({ scans }) => setScans(scans)).catch(() => setScans([])); }, []);

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Scans</div>
          <h1 className="display">Scan history</h1>
        </div>
        <Link to="/app/scan" className="btn btn-primary btn-sm">+ New scan</Link>
      </div>

      <div className="panel">
        <div className="panel-head"><span>All scans</span><span className="tag">{scans?.length ?? 0}</span></div>
        {scans === null ? <div className="empty">Loading…</div> : scans.length === 0 ? <div className="empty">No scans yet.</div> : (
          <table>
            <thead><tr><th>Target</th><th>Status</th><th>Risk</th><th>Findings</th><th>When</th></tr></thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => nav(`/app/scans/${s.id}`)}>
                  <td className="brk">{s.target_url || s.query}</td>
                  <td><span className={`pill pill-${s.status}`}>{s.status}</span></td>
                  <td>{s.risk_score ?? "—"}</td>
                  <td>{s.stats?.kept ?? "—"}</td>
                  <td className="muted">{fmt(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
