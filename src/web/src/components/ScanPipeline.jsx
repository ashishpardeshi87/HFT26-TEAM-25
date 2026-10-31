import { useMemo } from "react";

// ── Exposure scan pipeline canvas ───────────────────────────────────────────
//
// Animated left-to-right topology of the REAL sweep, derived entirely from the
// scan record the backend streams (status + logs + findings + risk_score) — so
// the canvas can never disagree with the process log beside it.
//
//   TARGET → SOURCE QUERY → PARSE → CLASSIFY → SCORE → REPORT
//
// Particles travel along an edge only while its downstream node is actively
// working; a brutalist hard-shadow node system matches the rest of the UI.

const NW = 150;
const NH = 58;
const VW = 1140;
const VH = 150;
const ROW = (VH - NH) / 2;
const GAP = (VW - NW - 24) / 5;
const colX = (i) => 12 + i * GAP;

const COLOR = {
  idle:    { stroke: "var(--line-hard)", text: "var(--ink-faint)", fill: "var(--surface)" },
  running: { stroke: "var(--acid)",      text: "var(--ink)",       fill: "var(--surface-2)" },
  done:    { stroke: "var(--ok)",        text: "var(--ink)",       fill: "var(--surface)" },
  failed:  { stroke: "var(--alert)",     text: "var(--alert)",     fill: "var(--surface)" },
};

// Which stage the scan is at, from status + the real log lines.
function stageOf(scan) {
  if (!scan) return 0;
  if (scan.status === "completed") return 6;
  if (scan.status === "failed") return -1;
  const logs = (scan.logs || []).join(" ");
  if (/distinct data class|unique subdomain|distinct hostname|returned \d/.test(logs)) return 3;
  if (/querying|searching/.test(logs)) return 2;
  if (scan.status === "running") return 1;
  return 0;
}

function edgePath(x1, y1, x2, y2) {
  const dx = Math.max(30, (x2 - x1) * 0.5);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function Flow({ d, active, color = "var(--acid)" }) {
  if (!active) return null;
  return (
    <>
      {[0, 0.5, 1.0].map((off) => (
        <circle key={off} r={2.6} fill={color}>
          <animateMotion dur="1.5s" repeatCount="indefinite" path={d} begin={`${off}s`} />
          <animate attributeName="opacity" values="0;1;1;0" dur="1.5s" repeatCount="indefinite" begin={`${off}s`} />
        </circle>
      ))}
    </>
  );
}

function Node({ x, state, title, sub, badge, badgeColor, accent }) {
  const c = COLOR[state] || COLOR.idle;
  const live = state === "running";
  return (
    <g>
      <rect x={x + 4} y={ROW + 4} width={NW} height={NH} fill="#000" />
      <rect x={x} y={ROW} width={NW} height={NH} fill={c.fill} stroke={c.stroke} strokeWidth={accent ? 2.5 : 1.5}>
        {live && <animate attributeName="stroke-opacity" values="1;0.35;1" dur="1.3s" repeatCount="indefinite" />}
      </rect>
      <rect x={x} y={ROW} width={5} height={NH} fill={c.stroke} opacity={state === "idle" ? 0.35 : 1} />
      <text x={x + 15} y={ROW + 24} fill={c.text} style={{ font: "700 11px var(--mono)", letterSpacing: ".02em" }}>{title}</text>
      <text x={x + 15} y={ROW + 41} fill="var(--ink-faint)" style={{ font: "9.5px var(--mono)", letterSpacing: ".06em" }}>{sub}</text>
      {badge != null && (
        <>
          <rect x={x + NW - 44} y={ROW + 11} width={34} height={17} fill={badgeColor || c.stroke} />
          <text x={x + NW - 27} y={ROW + 23.5} textAnchor="middle" fill="#000" style={{ font: "700 10.5px var(--mono)" }}>{badge}</text>
        </>
      )}
    </g>
  );
}

export default function ScanPipeline({ scan }) {
  const stage = useMemo(() => stageOf(scan), [scan]);
  const failed = stage === -1;
  const st = (i) => (failed ? (i === 0 ? "done" : "failed") : stage >= 6 ? "done" : i < stage ? "done" : i === stage ? "running" : "idle");

  const findings = scan?.findings || [];
  const stats = scan?.stats || {};
  const kind = scan?.kind || "—";
  const src = kind === "email" ? "xposedornot" : "crt.sh";
  const critHigh = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const done = stage >= 6;

  const NODES = [
    { title: "TARGET", sub: kind, badge: null },
    { title: "SOURCE QUERY", sub: src, badge: done ? (stats.intel ?? null) : null, accent: true },
    { title: "PARSE", sub: "extract records", badge: done ? findings.length : null },
    { title: "CLASSIFY", sub: "severity · category", badge: done ? critHigh : null, badgeColor: critHigh ? "var(--alert)" : "var(--ok)", accent: true },
    { title: "SCORE", sub: "0–100 risk", badge: done ? (scan?.risk_score ?? null) : null, badgeColor: (scan?.risk_score ?? 0) >= 60 ? "var(--alert)" : "var(--ok)" },
    { title: "REPORT", sub: "findings table", badge: null },
  ];

  return (
    <div className="flowcanvas">
      <svg viewBox={`0 0 ${VW} ${VH}`} width="100%" style={{ display: "block" }}>
        <defs>
          <pattern id="spgrid" width="22" height="22" patternUnits="userSpaceOnUse">
            <path d="M22 0 L0 0 0 22" fill="none" stroke="rgba(255,255,255,.028)" strokeWidth="1" />
          </pattern>
        </defs>
        <rect x="0" y="0" width={VW} height={VH} fill="url(#spgrid)" />

        {NODES.slice(0, -1).map((_, i) => {
          const d = edgePath(colX(i) + NW, ROW + NH / 2, colX(i + 1), ROW + NH / 2);
          const downstream = st(i + 1);
          const on = st(i) !== "idle";
          return (
            <g key={i}>
              <path d={d} fill="none" stroke={on ? "var(--line-hard)" : "var(--line)"} strokeWidth="1.5" />
              <Flow d={d} active={downstream === "running"} />
            </g>
          );
        })}

        {NODES.map((n, i) => (
          <Node key={i} x={colX(i)} state={st(i)} title={n.title} sub={n.sub} badge={n.badge} badgeColor={n.badgeColor} accent={n.accent} />
        ))}
      </svg>

      <div className="flowlegend">
        <span><i className="dot" style={{ background: "var(--acid)" }} /> running</span>
        <span><i className="dot" style={{ background: "var(--ok)" }} /> complete</span>
        <span><i className="dot" style={{ background: "var(--line-hard)" }} /> idle</span>
        <span className="grow" />
        <span className="mono-label">
          {scan?.status || "idle"}
          {done ? ` · ${findings.length} finding${findings.length === 1 ? "" : "s"} · risk ${scan?.risk_score ?? 0}` : ""}
        </span>
      </div>
    </div>
  );
}
