// ── Attack graph canvas (Feature A) ─────────────────────────────────────────
//
// Renders an incident's event lineage as an animated SVG kill-chain. Edges carry
// the B2 causality label and are styled by it — we never assert causation beyond
// "execution linkage":
//   direct_execution_linkage  solid acid   (evidence relationship)
//   strong_correlation        solid cyan   (independent corroboration)
//   possible_correlation      dashed grey  (temporal/session only)
//
// Nodes on the resolved path-to-sink are emphasised; the blocked node is ringed.

const NW = 170, NH = 64, SLOT = 212, Y = 126, VH = 248, PAD = 16;

const OUT = {
  blocked: { stroke: "var(--alert)", fill: "rgba(255,69,58,.10)" },
  leak: { stroke: "var(--warn)", fill: "rgba(255,176,32,.10)" },
  ingress: { stroke: "var(--violet)", fill: "rgba(181,108,255,.10)" },
  observed: { stroke: "var(--line-hard)", fill: "var(--surface)" },
};
const EDGE = {
  direct_execution_linkage: { color: "var(--acid)", dash: "", short: "direct" },
  strong_correlation: { color: "var(--info)", dash: "", short: "strong" },
  possible_correlation: { color: "var(--ink-faint)", dash: "5 4", short: "possible" },
};

function trunc(s, n) { s = s || ""; return s.length > n ? s.slice(0, n - 1) + "…" : s; }

export default function AttackGraphCanvas({ data }) {
  if (!data || !data.nodes?.length) return <div className="empty">No graph.</div>;
  const nodes = data.nodes;
  const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  const pathIds = new Set((data.cause_path?.steps || []).map((s) => s.event_id));
  const pathEdge = new Set();
  const steps = data.cause_path?.steps || [];
  for (let i = 1; i < steps.length; i++) pathEdge.add(steps[i - 1].event_id + "->" + steps[i].event_id);

  const VW = Math.max(760, PAD * 2 + nodes.length * SLOT);
  const xOf = (i) => PAD + i * SLOT + 4;
  const cx = (i) => xOf(i) + NW / 2;

  const edgePath = (a, b, lift) => {
    const x1 = xOf(a) + NW, y1 = Y + NH / 2;
    const x2 = xOf(b), y2 = Y + NH / 2;
    if (Math.abs(b - a) === 1) {
      const dx = (x2 - x1) * 0.5;
      return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
    }
    // arc above for non-adjacent (e.g. strong-correlation read->leak)
    const mx = (x1 + x2) / 2, my = Y - 44 - lift * 26;
    return `M ${x1} ${y1} C ${mx} ${my}, ${mx} ${my}, ${x2} ${y2}`;
  };

  return (
    <div className="flowcanvas">
      <svg viewBox={`0 0 ${VW} ${VH}`} width="100%" style={{ display: "block", minWidth: Math.min(VW, 900) }}>
        <defs>
          <pattern id="agrid" width="22" height="22" patternUnits="userSpaceOnUse">
            <path d="M22 0 L0 0 0 22" fill="none" stroke="rgba(255,255,255,.028)" strokeWidth="1" />
          </pattern>
          <marker id="agarrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0,0 L7,3.5 L0,7 Z" fill="var(--ink-faint)" />
          </marker>
        </defs>
        <rect x="0" y="0" width={VW} height={VH} fill="url(#agrid)" />

        {/* edges */}
        {(data.edges || []).map((e, k) => {
          const a = idx[e.source], b = idx[e.target];
          if (a == null || b == null) return null;
          const st = EDGE[e.label] || EDGE.possible_correlation;
          const onPath = pathEdge.has(e.source + "->" + e.target);
          const d = edgePath(a, b, k % 2);
          return (
            <g key={k}>
              <path d={d} fill="none" stroke={st.color} strokeWidth={onPath ? 2.4 : 1.5}
                strokeDasharray={st.dash} opacity={onPath ? 1 : 0.6} markerEnd="url(#agarrow)" />
              {/* B2 label chip at the midpoint */}
              {Math.abs(b - a) === 1 && (
                <text x={(xOf(a) + NW + xOf(b)) / 2} y={Y + NH / 2 - 8} textAnchor="middle"
                  fill={st.color} style={{ font: "8px var(--mono)", letterSpacing: ".06em" }}>{st.short}</text>
              )}
              {/* particles along the cause path */}
              {onPath && [0, 0.6].map((off) => (
                <circle key={off} r="2.6" fill={st.color}>
                  <animateMotion dur="1.6s" repeatCount="indefinite" path={d} begin={`${off}s`} />
                  <animate attributeName="opacity" values="0;1;1;0" dur="1.6s" repeatCount="indefinite" begin={`${off}s`} />
                </circle>
              ))}
            </g>
          );
        })}

        {/* nodes */}
        {nodes.map((n, i) => {
          const o = OUT[n.outcome] || OUT.observed;
          const onPath = pathIds.has(n.id);
          return (
            <g key={n.id}>
              <rect x={xOf(i) + 4} y={Y + 4} width={NW} height={NH} fill="#000" />
              <rect x={xOf(i)} y={Y} width={NW} height={NH} fill={o.fill} stroke={o.stroke}
                strokeWidth={n.blocked ? 2.6 : onPath ? 2 : 1.4}>
                {n.blocked && <animate attributeName="stroke-opacity" values="1;.4;1" dur="1.3s" repeatCount="indefinite" />}
              </rect>
              <rect x={xOf(i)} y={Y} width={5} height={NH} fill={o.stroke} />
              <text x={xOf(i) + 15} y={Y + 16} fill="var(--ink-faint)" style={{ font: "8px var(--mono)", letterSpacing: ".1em" }}>
                {String(i + 1).padStart(2, "0")} · {trunc(n.type, 20)}
              </text>
              <text x={xOf(i) + 15} y={Y + 34} fill="var(--ink)" style={{ font: "700 11px var(--mono)" }}>
                {trunc(n.label, 22)}
              </text>
              <text x={xOf(i) + 15} y={Y + 50} fill="var(--ink-dim)" style={{ font: "9px var(--mono)" }}>
                {trunc(n.process, 16)}
              </text>
              {n.blocked && (
                <>
                  <rect x={xOf(i) + NW - 52} y={Y + 10} width={46} height={15} fill="var(--alert)" />
                  <text x={xOf(i) + NW - 29} y={Y + 21} textAnchor="middle" fill="#000" style={{ font: "700 9px var(--mono)" }}>BLOCKED</text>
                </>
              )}
              {!n.blocked && n.outcome === "leak" && (
                <>
                  <rect x={xOf(i) + NW - 40} y={Y + 10} width={34} height={15} fill="var(--warn)" />
                  <text x={xOf(i) + NW - 23} y={Y + 21} textAnchor="middle" fill="#000" style={{ font: "700 9px var(--mono)" }}>LEAK</text>
                </>
              )}
            </g>
          );
        })}
      </svg>

      <div className="flowlegend">
        <span><i className="dot" style={{ background: "var(--acid)" }} /> direct execution linkage</span>
        <span><i className="dot" style={{ background: "var(--info)" }} /> strong correlation</span>
        <span><i className="dot" style={{ background: "var(--ink-faint)" }} /> possible correlation</span>
        <span className="grow" />
        <span className="mono-label">
          {data.stats?.events} events · {data.stats?.blocked} blocked · path {steps.length} deep
        </span>
      </div>
      <div className="snip" style={{ padding: "6px 4px 0", color: "var(--ink-faint)" }}>{data.causality_caveat}</div>
    </div>
  );
}
