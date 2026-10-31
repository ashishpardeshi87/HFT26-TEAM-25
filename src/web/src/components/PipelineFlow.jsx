import { useMemo } from "react";
import { derive, PHASES } from "../lib/pipelineState.js";

// ── Investigation pipeline canvas ───────────────────────────────────────────
//
// Renders the live topology of an investigation: seed → five parallel source
// phases → exposure classifier → attack-path correlation → report.
//
// State is DERIVED FROM THE LOG STREAM the backend already emits, rather than
// from a second progress channel. osint.js logs a HEAD line per phase
// ("[3/5] INFRASTRUCTURE FOOTPRINT") and a result line per source
// ("  GitHub — code, configs & secrets: 2 finding(s)."), which is enough to
// drive node status and per-phase counts. No backend change, and the canvas can
// never disagree with the terminal beside it because both read the same lines.

// Geometry. Fixed viewBox, scaled responsively by the parent.
const NW = 196;   // node width
const NH = 56;    // node height
const COL = { seed: 24, phase: 268, clf: 556, corr: 812, rep: 1068 };
const ROW0 = 34;  // first phase row
const ROWH = 74;  // phase row pitch
const MIDY = ROW0 + (ROWH * (PHASES.length - 1)) / 2;
const VW = COL.rep + NW + 24;
const VH = ROW0 + ROWH * (PHASES.length - 1) + NH + 34;

const STATUS_COLOR = {
  idle:    { stroke: "var(--line-hard)", text: "var(--ink-faint)", fill: "var(--surface)" },
  running: { stroke: "var(--acid)",      text: "var(--ink)",       fill: "var(--surface-2)" },
  done:    { stroke: "var(--ok)",        text: "var(--ink)",       fill: "var(--surface)" },
  skipped: { stroke: "var(--line-hard)", text: "var(--ink-faint)", fill: "var(--surface)" },
  alert:   { stroke: "var(--alert)",     text: "var(--ink)",       fill: "var(--surface-2)" },
  failed:  { stroke: "var(--alert)",     text: "var(--alert)",     fill: "var(--surface)" },
};

// Horizontal bezier between two node edges.
function edge(x1, y1, x2, y2) {
  const dx = Math.max(36, (x2 - x1) * 0.45);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function Node({ x, y, w = NW, h = NH, status, title, sub, badge, badgeColor, accent }) {
  const c = STATUS_COLOR[status] || STATUS_COLOR.idle;
  const live = status === "running";
  return (
    <g>
      {/* hard offset shadow — matches the brutalist system */}
      <rect x={x + 4} y={y + 4} width={w} height={h} fill="#000" />
      <rect
        x={x} y={y} width={w} height={h}
        fill={c.fill} stroke={c.stroke} strokeWidth={accent ? 2.5 : 1.5}
        strokeDasharray={status === "skipped" ? "5 4" : undefined}
      >
        {live && <animate attributeName="stroke-opacity" values="1;0.35;1" dur="1.3s" repeatCount="indefinite" />}
      </rect>

      {/* status tick in the corner */}
      <rect x={x} y={y} width={5} height={h} fill={c.stroke} opacity={status === "idle" ? 0.35 : 1} />

      <text x={x + 15} y={y + 23} fill={c.text} style={{ font: "700 11.5px var(--mono)", letterSpacing: ".02em" }}>
        {title}
      </text>
      <text x={x + 15} y={y + 40} fill="var(--ink-faint)" style={{ font: "9.5px var(--mono)", letterSpacing: ".08em" }}>
        {sub}
      </text>

      {badge != null && (
        <>
          <rect x={x + w - 42} y={y + 11} width={32} height={17} fill={badgeColor || c.stroke} />
          <text
            x={x + w - 26} y={y + 23.5} textAnchor="middle"
            fill="#000" style={{ font: "700 10.5px var(--mono)" }}
          >
            {badge}
          </text>
        </>
      )}
    </g>
  );
}

// Dots travelling along a live edge — the Railway-style motion cue.
function Flow({ d, active, delay = 0, color = "var(--acid)" }) {
  if (!active) return null;
  return (
    <>
      {[0, 0.55, 1.1].map((off) => (
        <circle key={off} r={2.6} fill={color}>
          <animateMotion dur="1.65s" repeatCount="indefinite" path={d} begin={`${delay + off}s`} />
          <animate attributeName="opacity" values="0;1;1;0" dur="1.65s" repeatCount="indefinite" begin={`${delay + off}s`} />
        </circle>
      ))}
    </>
  );
}

export default function PipelineFlow({ logs = [], status, findings = [], pathStats, risk }) {
  const s = useMemo(
    () => derive(logs, { status, findings, pathStats, risk }),
    [logs, status, findings, pathStats, risk]
  );

  const doneOrLive = (v) => v === "running" || v === "done" || v === "alert";

  const seedY = MIDY + NH / 2;
  const clfY = MIDY + NH / 2;

  const totalFindings = findings.length;
  const chains = pathStats?.chainsEmitted ?? 0;

  return (
    <div className="flowcanvas">
      <svg viewBox={`0 0 ${VW} ${VH}`} width="100%" style={{ display: "block" }}>
        <defs>
          <pattern id="fgrid" width="22" height="22" patternUnits="userSpaceOnUse">
            <path d="M22 0 L0 0 0 22" fill="none" stroke="rgba(255,255,255,.028)" strokeWidth="1" />
          </pattern>
        </defs>
        <rect x="0" y="0" width={VW} height={VH} fill="url(#fgrid)" />

        {/* ── edges: seed → phases, phases → classifier ── */}
        {PHASES.map((p, i) => {
          const py = ROW0 + i * ROWH + NH / 2;
          const dIn = edge(COL.seed + NW, seedY, COL.phase, py);
          const dOut = edge(COL.phase + NW, py, COL.clf, clfY);
          const inLive = s[p.id] === "running";
          const outLive = s[p.id] === "running" && s.classifier === "running";
          const inOn = doneOrLive(s[p.id]);
          return (
            <g key={p.id}>
              <path d={dIn} fill="none" stroke={inOn ? "var(--line-hard)" : "var(--line)"} strokeWidth="1.5" />
              <path d={dOut} fill="none" stroke={inOn ? "var(--line-hard)" : "var(--line)"} strokeWidth="1.5"
                strokeDasharray={s[p.id] === "skipped" ? "4 4" : undefined} />
              <Flow d={dIn} active={inLive} delay={i * 0.12} />
              <Flow d={dOut} active={outLive} delay={i * 0.12 + 0.3} />
            </g>
          );
        })}

        {/* ── edges: classifier → correlate → report ── */}
        {(() => {
          const d1 = edge(COL.clf + NW, clfY, COL.corr, clfY);
          const d2 = edge(COL.corr + NW, clfY, COL.rep, clfY);
          return (
            <>
              <path d={d1} fill="none" stroke={doneOrLive(s.correlate) ? "var(--line-hard)" : "var(--line)"} strokeWidth="1.5" />
              <path d={d2} fill="none" stroke={doneOrLive(s.report) ? "var(--line-hard)" : "var(--line)"} strokeWidth="1.5" />
              <Flow d={d1} active={s.correlate === "running"} color="var(--violet)" />
              <Flow d={d2} active={s.report === "running"} color="var(--violet)" />
            </>
          );
        })()}

        {/* ── nodes ── */}
        <Node
          x={COL.seed} y={MIDY} w={NW} status={s.seed}
          title="TARGET" sub="domain · email · brand"
        />

        {PHASES.map((p, i) => (
          <Node
            key={p.id}
            x={COL.phase} y={ROW0 + i * ROWH}
            status={s[p.id]}
            title={`${p.n}. ${p.label.toUpperCase()}`}
            sub={s.skips[p.id] ? `${p.sub} · ${s.skips[p.id]} skipped` : p.sub}
            badge={s.counts[p.id] ?? (s[p.id] === "done" || s[p.id] === "skipped" ? 0 : null)}
          />
        ))}

        <Node
          x={COL.clf} y={MIDY} status={s.classifier} accent
          title="EXPOSURE CLASSIFIER"
          sub={`MiniLM-L6-v2 · ${s.abstainedCount || 0} abstained`}
          badge={s.classifiedCount ?? null}
          badgeColor="var(--info)"
        />

        <Node
          x={COL.corr} y={MIDY} status={s.correlate} accent
          title="ATTACK PATH CORRELATION"
          sub={pathStats ? `${pathStats.rulesSuppressedForLackOfEvidence}/${pathStats.rulesEvaluated} silent` : "8 chain rules"}
          badge={pathStats ? chains : null}
          badgeColor={chains ? "var(--alert)" : "var(--ok)"}
        />

        <Node
          x={COL.rep} y={MIDY} status={s.report}
          title="RISK & REPORT"
          sub={risk ? `${risk.level} · PDF / JSON` : "score · ATT&CK · remediation"}
          badge={typeof risk?.score === "number" ? risk.score : null}
          badgeColor={risk?.score >= 70 ? "var(--alert)" : risk?.score >= 40 ? "var(--warn)" : "var(--ok)"}
        />
      </svg>

      {/* ── legend / live readout ── */}
      <div className="flowlegend">
        <span><i className="dot" style={{ background: "var(--acid)" }} /> running</span>
        <span><i className="dot" style={{ background: "var(--ok)" }} /> complete</span>
        <span><i className="dot" style={{ background: "var(--line-hard)" }} /> idle / skipped</span>
        <span><i className="dot" style={{ background: "var(--alert)" }} /> needs attention</span>
        <span className="grow" />
        <span className="mono-label">
          {totalFindings} finding{totalFindings === 1 ? "" : "s"}
          {s.classifiedCount ? ` · ${s.classifiedCount} model-classified` : ""}
          {pathStats ? ` · ${chains} chain${chains === 1 ? "" : "s"}` : ""}
        </span>
      </div>
    </div>
  );
}
