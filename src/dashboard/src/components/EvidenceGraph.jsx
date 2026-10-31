// Renders an incident's evidence graph (nodes + edges) as a neo-brutalist SVG.
// Columns by node kind so the "who -> what -> where" story reads left to right.
const COL = { process: 0, file: 1, behavior: 1, secret: 2, pii: 2, anomaly: 2, provider: 3 };
const FILL = {
  process: "#4DE1FF", provider: "#FF5FA2", file: "#FFC531",
  secret: "#FF4D4D", pii: "#C7FB4F", behavior: "#9B6BFF", anomaly: "#FF8A3D",
};

export default function EvidenceGraph({ graph }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length) return <div className="font-mono text-xs text-ink/60">No evidence graph yet.</div>;

  const cols = [[], [], [], []];
  nodes.forEach((n) => cols[COL[n.kind] ?? 2].push(n));

  const W = 680, colX = [70, 250, 440, 620], rowH = 64;
  const pos = {};
  cols.forEach((list, ci) =>
    list.forEach((n, ri) => {
      pos[n.id] = { x: colX[ci], y: 50 + ri * rowH };
    })
  );
  const H = Math.max(180, 50 + Math.max(...cols.map((c) => c.length)) * rowH);

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="min-w-[640px]" style={{ width: "100%" }}>
        {edges.map((e, i) => {
          const a = pos[e.src], b = pos[e.dst];
          if (!a || !b) return null;
          const mx = (a.x + b.x) / 2;
          return (
            <g key={i}>
              <path d={`M ${a.x + 55} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - 55} ${b.y}`}
                fill="none" stroke="#0A0A0A" strokeWidth="2.5" strokeDasharray="6 4"
                className="animate-flow" />
              <text x={mx} y={(a.y + b.y) / 2 - 6} textAnchor="middle"
                className="font-mono" fontSize="9" fill="#0A0A0A">{e.rel}</text>
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos[n.id];
          if (!p) return null;
          const label = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
          return (
            <g key={n.id} transform={`translate(${p.x - 55} ${p.y - 18})`}>
              <rect x="3" y="3" width="110" height="36" fill="#0A0A0A" />
              <rect width="110" height="36" fill={FILL[n.kind] || "#fff"} stroke="#0A0A0A" strokeWidth="2.5" />
              <text x="55" y="15" textAnchor="middle" className="font-mono" fontSize="8"
                fill="#0A0A0A" opacity="0.6">{n.kind.toUpperCase()}</text>
              <text x="55" y="28" textAnchor="middle" className="font-display" fontSize="9"
                fontWeight="700" fill="#0A0A0A">{label}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
