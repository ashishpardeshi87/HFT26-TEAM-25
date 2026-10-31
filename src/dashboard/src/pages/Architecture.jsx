// Animated neo-brutalist architecture canvas for SENTINEL APEX.
const VB_W = 1200, VB_H = 780;

const C = {
  src: "#4DE1FF", tel: "#FFE500", fp: "#C7FB4F", det: "#FF8A3D",
  cor: "#9B6BFF", score: "#FFC531", ai: "#FF5FA2", dg: "#4DE1FF", out: "#FF4D4D",
};

// id: [x, y, w, h, title, sub, color]
const N = {
  endpoint: [40, 70, 150, 54, "Endpoint / Network", "psutil · scapy", C.src],
  browser: [40, 150, 150, 54, "Browser Extension", "pre-encryption", C.src],
  upload: [40, 230, 150, 54, "PCAP / HAR Upload", "offline replay", C.src],

  telemetry: [240, 120, 160, 150, "Telemetry Collection", "normalize → event", C.tel],

  fp: [450, 70, 150, 54, "AI Provider FP", "host + port", C.fp],
  proc: [450, 150, 150, 54, "Process & Agent", "attribution", C.fp],
  payload: [450, 230, 150, 54, "Payload Inspection", "regex + entropy", C.fp],

  shadow: [660, 70, 150, 54, "Shadow AI Detect", "approved?", C.det],
  behav: [660, 150, 150, 54, "Agent Behaviour", ".env · shell", C.det],
  secret: [660, 230, 150, 54, "Secret / PII", "Aadhaar · Luhn", C.det],

  correlate: [880, 110, 170, 170, "Risk Correlation", "graph · one incident", C.cor],

  score: [880, 420, 170, 70, "Threat Scoring", "explainable 0–100", C.score],
  copilot: [630, 420, 180, 70, "Featherless Copilot", "explain · remediate", C.ai],
  darkguard: [630, 540, 180, 70, "DarkGuard", "external exposure", C.dg],
  command: [300, 470, 220, 90, "SENTINEL Command Center", "incidents · graph · score", C.out],
};

const E = [
  ["endpoint", "telemetry"], ["browser", "telemetry"], ["upload", "telemetry"],
  ["telemetry", "fp"], ["telemetry", "proc"], ["telemetry", "payload"],
  ["fp", "shadow"], ["proc", "behav"], ["payload", "secret"],
  ["shadow", "correlate"], ["behav", "correlate"], ["secret", "correlate"],
  ["correlate", "score"], ["score", "copilot"], ["score", "darkguard"],
  ["darkguard", "correlate"], ["copilot", "command"], ["score", "command"],
];

function port(id, side) {
  const [x, y, w, h] = N[id];
  if (side === "r") return [x + w, y + h / 2];
  if (side === "l") return [x, y + h / 2];
  if (side === "b") return [x + w / 2, y + h];
  if (side === "t") return [x + w / 2, y];
  return [x + w / 2, y + h / 2];
}

function edgePath(a, b) {
  const [ax, ay, aw] = N[a];
  const [bx, by] = N[b];
  // pick sensible ports: horizontal if b is to the right, else route down/left
  if (bx > ax + aw - 1) {
    const [x1, y1] = port(a, "r"), [x2, y2] = port(b, "l");
    const mx = (x1 + x2) / 2;
    return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
  }
  // going back/down (e.g. score->copilot, darkguard->correlate, ->command)
  const [x1, y1] = port(a, "b"), [x2, y2] = port(b, bx < ax ? "r" : "t");
  const my = (y1 + y2) / 2;
  return `M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`;
}

export default function Architecture() {
  return (
    <main className="mx-auto max-w-7xl px-4 py-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-bold uppercase">Live Architecture</h1>
          <p className="font-mono text-xs text-ink/60">
            Telemetry → detection → graph correlation → scoring → copilot &amp; DarkGuard → Command Center
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Legend c={C.src} t="Sources" /><Legend c={C.tel} t="Telemetry" />
          <Legend c={C.fp} t="Fingerprint" /><Legend c={C.det} t="Detect" />
          <Legend c={C.cor} t="Correlate" /><Legend c={C.ai} t="AI / Intel" />
        </div>
      </div>

      <div className="mt-5 card overflow-x-auto p-3">
        <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="min-w-[900px]" style={{ width: "100%" }}>
          <defs>
            <marker id="arrow" markerWidth="10" markerHeight="10" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#0A0A0A" />
            </marker>
          </defs>

          {E.map(([a, b], i) => (
            <path key={i} d={edgePath(a, b)} fill="none" stroke="#0A0A0A" strokeWidth="2.5"
              strokeDasharray="7 5" className="animate-flow" markerEnd="url(#arrow)" />
          ))}

          {Object.entries(N).map(([id, [x, y, w, h, title, sub, color]]) => (
            <g key={id}>
              <rect x={x + 5} y={y + 5} width={w} height={h} fill="#0A0A0A" />
              <rect x={x} y={y} width={w} height={h} fill={color} stroke="#0A0A0A" strokeWidth="3" />
              <text x={x + w / 2} y={y + h / 2 - 4} textAnchor="middle" className="font-display"
                fontSize="15" fontWeight="700" fill="#0A0A0A">{title}</text>
              <text x={x + w / 2} y={y + h / 2 + 14} textAnchor="middle" className="font-mono"
                fontSize="10" fill="#0A0A0A" opacity="0.7">{sub}</text>
            </g>
          ))}
        </svg>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-3">
        <Note title="Non-invasive" body="No SSL decryption. Reads process↔connection telemetry, local-LLM plaintext, and browser prompts before encryption." />
        <Note title="Graph correlation" body="Research-inspired cross-signal correlation turns discovery + access + exfiltration events into one evidence graph and score." />
        <Note title="Deterministic core" body="Detection and scoring are deterministic and reproducible; the Featherless LLM only explains and recommends." />
      </div>
    </main>
  );
}

function Legend({ c, t }) {
  return (
    <span className="chip bg-panel">
      <span className="h-3 w-3 border-2 border-ink" style={{ background: c }} />{t}
    </span>
  );
}
function Note({ title, body }) {
  return (
    <div className="card p-4">
      <div className="font-display font-bold">{title}</div>
      <p className="mt-1 font-mono text-xs leading-relaxed text-ink/75">{body}</p>
    </div>
  );
}
