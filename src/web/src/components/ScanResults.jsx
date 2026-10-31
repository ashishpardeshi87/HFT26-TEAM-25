import { lazy, Suspense } from "react";
import { BarChart, DoughnutChart, SEV_COLORS } from "./Charts.jsx";
import Terminal from "./Terminal.jsx";
import FindingEvidence from "./FindingEvidence.jsx";

// three.js is heavy — code-split it so it loads only when a report is viewed.
const ExposureGraph3D = lazy(() => import("./ExposureGraph3D.jsx"));

const countBy = (arr, key) =>
  arr.reduce((a, x) => { const k = x[key] || "other"; a[k] = (a[k] || 0) + 1; return a; }, {});

export default function ScanResults({ scan }) {
  const findings = scan.findings || [];
  const stats = scan.stats || {};
  const risk = scan.risk_score ?? 0;

  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sevCounts = countBy(findings, "severity");
  const catCounts = countBy(findings, "category");
  const srcCounts = countBy(findings, "engine");

  return (
    <div className="grid" style={{ gridTemplateColumns: "repeat(12,1fr)" }}>
      <div className="panel" style={{ gridColumn: "span 3" }}>
        <div className="panel-head"><span>Risk Score</span><span className="tag">0–100</span></div>
        <div className="panel-pad ring-wrap" style={{ height: 200 }}>
          <DoughnutChart labels={["risk", ""]} data={[risk, 100 - risk]} colors={[risk > 60 ? "#ff453a" : "#c6ff3a", "rgba(255,255,255,.05)"]} />
          <div className="rv" style={{ color: risk > 60 ? "var(--alert)" : "var(--acid)" }}>{risk}</div>
        </div>
      </div>

      <div className="panel" style={{ gridColumn: "span 3" }}>
        <div className="panel-head"><span>Findings</span></div>
        <div className="panel-pad">
          <div className="metric acid">{stats.kept ?? findings.length}</div>
          <div className="mono-label" style={{ marginTop: 10 }}>
            INTEL {stats.intel ?? "—"} · DARKWEB {stats.crawled ?? "—"}<br />
            BLOCKED <span style={{ color: "var(--alert)" }}>{stats.blocked ?? 0}</span>
          </div>
        </div>
      </div>

      <div className="panel" style={{ gridColumn: "span 3" }}>
        <div className="panel-head"><span>By Severity</span></div>
        <div className="panel-pad" style={{ height: 200 }}>
          <DoughnutChart labels={sevOrder} data={sevOrder.map((s) => sevCounts[s] || 0)} colors={sevOrder.map((s) => SEV_COLORS[s])} showLegend />
        </div>
      </div>

      <div className="panel" style={{ gridColumn: "span 3" }}>
        <div className="panel-head"><span>By Category</span></div>
        <div className="panel-pad" style={{ height: 200 }}>
          <BarChart labels={Object.keys(catCounts)} data={Object.values(catCounts)} />
        </div>
      </div>

      {findings.length > 0 && (
        <div className="panel" style={{ gridColumn: "span 12" }}>
          <div className="panel-head"><span>// Exposure graph · 3D</span><span className="tag">drag to orbit · scroll to zoom · click a node</span></div>
          <div className="proccanvas">
            <Suspense fallback={<div className="empty" style={{ minHeight: 440, display: "grid", placeItems: "center" }}>rendering 3D exposure graph…</div>}>
              <ExposureGraph3D scan={scan} />
            </Suspense>
          </div>
        </div>
      )}

      <div className="panel" style={{ gridColumn: "span 12" }}>
        <div className="panel-head"><span>Findings by source</span></div>
        <div className="panel-pad" style={{ height: 130 }}>
          <BarChart labels={Object.keys(srcCounts)} data={Object.values(srcCounts)} horizontal color="#4cc9f0" />
        </div>
      </div>

      <div className="panel" style={{ gridColumn: "span 12" }}>
        <div className="panel-head"><span>// Process log</span><span className="tag">{(scan.logs || []).length} lines</span></div>
        <div className="panel-pad"><Terminal logs={scan.logs} /></div>
      </div>

      <div className="panel" style={{ gridColumn: "span 12" }}>
        <div className="panel-head"><span>Findings</span><span className="tag">{findings.length}</span></div>
        {findings.length ? (
          <table>
            <thead><tr><th>Severity</th><th>Conf.</th><th>Category</th><th>Detail</th><th>Link</th><th>Source</th></tr></thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                  <td><span className="muted" style={{ fontSize: ".68rem", textTransform: "uppercase", letterSpacing: ".06em", color: f.confidence === "high" ? "var(--ok)" : f.confidence === "low" ? "var(--ink-faint)" : "var(--info)" }}>{f.confidence || "med"}</span></td>
                  <td className="muted">{f.category}</td>
                  <td>
                    {f.title || "—"}
                    {/* Why the verdict is what it is, and what evidence backs it. */}
                    <FindingEvidence finding={f} />
                    <div className="snip">{f.snippet || ""}</div>
                  </td>
                  <td className="acid brk" style={{ fontSize: ".74rem", maxWidth: 220 }}>
                    {f.onion_url ? <a href={f.onion_url} target="_blank" rel="noreferrer">{f.onion_url}</a> : "—"}
                  </td>
                  <td className="muted">{f.engine || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div className="empty">No exposure found. That&apos;s good news.</div>}
      </div>
    </div>
  );
}
