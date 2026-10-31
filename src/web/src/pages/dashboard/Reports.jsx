import { useEffect, useMemo, useRef, useState } from "react";
import { darkguardApi as api, downloadDarkguardFile } from "../../lib/darkguardApi.js";
import { BarChart, DoughnutChart, SEV_COLORS } from "../../components/Charts.jsx";
import ExposureGraph3D from "../../components/ExposureGraph3D.jsx";
import { generateScanReport } from "../../lib/pdf.js";
import { useToast } from "../../lib/ui.jsx";

const fmt = (d) => { try { return new Date(d + "Z").toLocaleString(); } catch { return d; } };
const countBy = (arr, k) => arr.reduce((a, x) => { const v = x[k] || "other"; a[v] = (a[v] || 0) + 1; return a; }, {});

export default function Reports() {
  const toast = useToast();
  const [scans, setScans] = useState([]);
  const [sel, setSel] = useState("");
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const reportRef = useRef(null);

  useEffect(() => {
    let active = true;
    api("/scans").then(({ scans: upstreamScans }) => {
      if (!active) return;
      const done = (upstreamScans || []).filter((s) => s.status === "completed");
      setScans(done);
      setSel(done[0]?.id || "");
      setError("");
      if (!done.length) setLoading(false);
    }).catch((loadError) => {
      if (!active) return;
      setError(loadError.message || "Reports are unavailable.");
      setLoading(false);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!sel) return undefined;
    let active = true;
    setLoading(true);
    setScan(null);
    api(`/scans/${sel}`).then(({ scan: selectedScan }) => {
      if (!active) return;
      setScan(selectedScan || null);
      setError("");
    }).catch((loadError) => {
      if (!active) return;
      setError(loadError.message || "The selected report is unavailable.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [sel]);

  const findings = scan?.findings || [];
  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sev = useMemo(() => countBy(findings, "severity"), [findings]);
  const cat = useMemo(() => countBy(findings, "category"), [findings]);
  const src = useMemo(() => countBy(findings, "engine"), [findings]);
  const risk = scan?.risk_score ?? 0;
  const classification = risk >= 70 ? "CRITICAL" : risk >= 40 ? "ELEVATED" : risk > 0 ? "MODERATE" : "CLEAR";

  const downloadPdf = () => {
    if (!scan) return;
    const canvases = reportRef.current?.querySelectorAll("canvas") || [];
    const images = [];
    canvases.forEach((c, i) => {
      try { images.push({ title: `chart-${i}`, dataUrl: c.toDataURL("image/png", 1.0) }); } catch { /* skip 3d */ }
    });
    generateScanReport(scan, images.slice(0, 2));
  };

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Reports</div>
          <h1 className="display">Threat report</h1>
          <p>Consolidated surface web, deep web &amp; dark web analysis — export-ready.</p>
        </div>
        <div className="row">
          <select className="input" style={{ width: "auto" }} value={sel} onChange={(e) => setSel(e.target.value)}>
            {scans.length === 0 && <option>No completed scans</option>}
            {scans.map((s) => <option key={s.id} value={s.id}>{(s.target_url || s.query)} — {fmt(s.created_at)}</option>)}
          </select>
          <button className="btn" onClick={() => downloadDarkguardFile("/export/json", "darkguard-export.json").catch((e) => toast(e.message, "error"))}>↓ Export all (JSON)</button>
          <button className="btn btn-primary" disabled={!scan} onClick={downloadPdf}>↓ Download PDF</button>
        </div>
      </div>

      {error && (
        <div className="banner" style={{ marginBottom: 16, borderColor: "var(--alert)", color: "var(--alert)" }}>
          <span>// Reports unavailable: {error}</span>
        </div>
      )}

      {!scan ? <div className="empty">{loading ? "Loading reports…" : error ? "Report data could not be loaded." : "No completed DarkGuard scans are available."}</div> : (
        <div ref={reportRef}>
          {/* Report header band */}
          <div className="panel ticked" style={{ background: risk >= 40 ? "rgba(255,69,58,.06)" : "var(--surface)" }}>
            <div className="panel-pad row between wrap center">
              <div>
                <div className="mono-label">CLASSIFICATION</div>
                <div className="display" style={{ fontSize: "2rem", color: risk >= 40 ? "var(--alert)" : "var(--acid)" }}>{classification}</div>
                <div className="muted brk" style={{ marginTop: 6 }}>{scan.target_url || scan.email || scan.query}</div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div className="mono-label">RISK SCORE</div>
                <div className="metric" style={{ color: risk >= 40 ? "var(--alert)" : "var(--acid)" }}>{risk}<span style={{ fontSize: "1rem", color: "var(--ink-dim)" }}>/100</span></div>
              </div>
            </div>
          </div>

          {/* Summary metrics */}
          <div className="grid g4" style={{ marginTop: 16 }}>
            <Metric label="Findings" value={findings.length} />
            <Metric label="Critical" value={sev.critical || 0} alert />
            <Metric label="Sources hit" value={Object.keys(src).length} />
            <Metric label="DW links crawled" value={scan.stats?.crawled ?? "—"} />
          </div>

          {/* Charts row */}
          <div className="grid g3" style={{ marginTop: 16 }}>
            <Panel title="By Severity"><div style={{ height: 220 }}><DoughnutChart labels={sevOrder} data={sevOrder.map((s) => sev[s] || 0)} colors={sevOrder.map((s) => SEV_COLORS[s])} showLegend /></div></Panel>
            <Panel title="By Category"><div style={{ height: 220 }}><BarChart labels={Object.keys(cat)} data={Object.values(cat)} /></div></Panel>
            <Panel title="By Source"><div style={{ height: 220 }}><BarChart labels={Object.keys(src)} data={Object.values(src)} color="#4cc9f0" /></div></Panel>
          </div>

          {/* 3D exposure graph */}
          <div className="panel" style={{ marginTop: 16 }}>
            <div className="panel-head"><span>// Exposure map — 3D</span><span className="tag">drag to rotate · scroll to zoom</span></div>
            <ExposureGraph3D scan={scan} />
          </div>

          {/* Findings */}
          <div className="panel" style={{ marginTop: 16 }}>
            <div className="panel-head"><span>Detailed findings</span><span className="tag">{findings.length}</span></div>
            {findings.length ? (
              <table>
                <thead><tr><th>Severity</th><th>Category</th><th>Detail</th><th>Source</th></tr></thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr key={i}>
                      <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                      <td className="muted">{f.category}</td>
                      <td>{f.title || "—"}<div className="snip brk">{f.snippet || f.onion_url || ""}</div></td>
                      <td className="muted">{f.engine}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <div className="empty">No exposure found.</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, alert }) {
  return <div className="panel panel-pad"><div className="mono-label">{label}</div><div className={`metric ${alert ? "alert" : "acid"}`} style={{ marginTop: 8 }}>{value}</div></div>;
}
function Panel({ title, children }) {
  return <div className="panel"><div className="panel-head"><span>{title}</span></div><div className="panel-pad">{children}</div></div>;
}
