// Incident evidence graph (nodes + edges) as a dark, DarkGuard-styled SVG.
const COL = { process: 0, file: 1, behavior: 1, injection: 1, secret: 2, pii: 2, anomaly: 2, provider: 3 };
const FILL = {
  process: "#4cc9f0", provider: "#ff453a", file: "#ffb020",
  secret: "#ff453a", pii: "#c6ff3a", behavior: "#b56cff", injection: "#b56cff", anomaly: "#ffb020",
};

export default function EvidenceGraph({ graph }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length) return <div className="snip">No evidence graph yet.</div>;

  const cols = [[], [], [], []];
  nodes.forEach((n) => cols[COL[n.kind] ?? 2].push(n));
  const W = 680, colX = [70, 250, 440, 615], rowH = 60;
  const pos = {};
  cols.forEach((list, ci) => list.forEach((n, ri) => { pos[n.id] = { x: colX[ci], y: 46 + ri * rowH }; }));
  const H = Math.max(170, 46 + Math.max(1, ...cols.map((c) => c.length)) * rowH);

  return (
    <div style={{ overflowX: "auto" }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", minWidth: 600 }}>
        {edges.map((e, i) => {
          const a = pos[e.src], b = pos[e.dst];
          if (!a || !b) return null;
          const mx = (a.x + b.x) / 2;
          const exfil = e.rel === "exfiltrated";
          return (
            <g key={i}>
              <path d={`M ${a.x + 52} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x - 52} ${b.y}`}
                fill="none" stroke={exfil ? "#ff453a" : "#3a3a40"} strokeWidth={exfil ? 2.2 : 1.4}
                strokeDasharray="5 4" />
              <text x={mx} y={(a.y + b.y) / 2 - 5} textAnchor="middle" fontSize="8"
                fill={exfil ? "#ff453a" : "#8d8d85"} fontFamily="'JetBrains Mono', monospace">{e.rel}</text>
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos[n.id]; if (!p) return null;
          const label = n.label.length > 20 ? n.label.slice(0, 19) + "…" : n.label;
          const c = FILL[n.kind] || "#8d8d85";
          return (
            <g key={n.id} transform={`translate(${p.x - 52} ${p.y - 17})`}>
              <rect width="104" height="34" fill="#0f0f11" stroke={c} strokeWidth="1.5" />
              <rect width="104" height="3" fill={c} />
              <text x="52" y="17" textAnchor="middle" fontSize="7.5" fill="#8d8d85"
                fontFamily="'JetBrains Mono', monospace">{n.kind.toUpperCase()}</text>
              <text x="52" y="28" textAnchor="middle" fontSize="8.5" fill="#ededea"
                fontFamily="'Space Grotesk', sans-serif" fontWeight="700">{label}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
