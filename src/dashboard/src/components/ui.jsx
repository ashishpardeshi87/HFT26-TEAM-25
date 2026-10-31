// Reusable neo-brutalist UI atoms.
import { SEV } from "../api.js";

export function SeverityPill({ level }) {
  return (
    <span className={`chip ${SEV[level] || "bg-paper"} ${level === "critical" ? "text-white" : ""}`}>
      {level}
    </span>
  );
}

export function Stat({ label, value, accent = "bg-volt", sub }) {
  return (
    <div className="card p-4">
      <div className="label">{label}</div>
      <div className="mt-1 flex items-end gap-2">
        <div className="font-display text-4xl font-bold leading-none">{value}</div>
        {sub && <div className="mb-1 font-mono text-xs text-ink/60">{sub}</div>}
      </div>
      <div className={`mt-3 h-2 border-2 border-ink ${accent}`} />
    </div>
  );
}

export function RiskGauge({ score = 0 }) {
  const level = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  const color = { critical: "#FF4D4D", high: "#FF8A3D", medium: "#FFC531", low: "#7BE38B" }[level];
  const r = 70, c = 2 * Math.PI * r, off = c * (1 - score / 100);
  return (
    <div className="card flex flex-col items-center p-5">
      <div className="label self-start">Org Risk Posture</div>
      <div className="relative my-2">
        <svg width="180" height="180" viewBox="0 0 180 180">
          <circle cx="90" cy="90" r={r} fill="none" stroke="#0A0A0A" strokeWidth="18" />
          <circle cx="90" cy="90" r={r} fill="none" stroke={color} strokeWidth="14"
            strokeDasharray={c} strokeDashoffset={off} strokeLinecap="butt"
            transform="rotate(-90 90 90)" style={{ transition: "stroke-dashoffset .6s ease" }} />
          <text x="90" y="86" textAnchor="middle" className="font-display" fontSize="44" fontWeight="700" fill="#0A0A0A">{score}</text>
          <text x="90" y="110" textAnchor="middle" className="font-mono" fontSize="12" fill="#0A0A0A">/ 100</text>
        </svg>
      </div>
      <SeverityPill level={level} />
    </div>
  );
}

export function Card({ title, right, children, className = "" }) {
  return (
    <div className={`card ${className}`}>
      {(title || right) && (
        <div className="flex items-center justify-between border-b-[3px] border-ink bg-paper px-4 py-2">
          <h3 className="font-display text-sm font-bold uppercase tracking-wide">{title}</h3>
          {right}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function Marquee({ items }) {
  const row = [...items, ...items];
  return (
    <div className="overflow-hidden border-y-[3px] border-ink bg-ink text-volt">
      <div className="flex whitespace-nowrap py-2" style={{ animation: "flow 1s linear" }}>
        <div className="flex animate-[marquee_26s_linear_infinite] gap-8 pr-8"
             style={{ animationName: "none" }}>
          {row.map((t, i) => (
            <span key={i} className="font-mono text-xs uppercase tracking-widest">◆ {t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
