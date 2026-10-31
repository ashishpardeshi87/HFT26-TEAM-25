import { useMemo } from "react";

const PROBES = [
  ["root", "ROOT PAGE"], ["favicon", "FAVICON"], ["error", "ERROR PAGE"],
  ["status", "STATUS PATHS"], ["tls", "TLS CERT"],
];
const NW = 138, NH = 42, VW = 1060, VH = 390;
const C = { pending: "var(--line-hard)", active: "var(--acid)", done: "var(--ok)", failed: "var(--alert)" };

function derive(events, status) {
  const side = () => ({ state: "pending", probes: Object.fromEntries(PROBES.map(([k]) => [k, "pending"])), notes: {} });
  const out = { a: side(), b: side(), compare: "pending", fusion: "pending" };
  for (const e of events || []) {
    const s = e.side && out[e.side];
    if (e.step === "service_start" && s) s.state = "active";
    if (e.step === "connecting" && s) s.probes.root = "active";
    if (e.step === "fetched" && s) { s.probes.root = "done"; s.notes.root = `HTTP ${e.status}`; }
    if (e.step === "probing" && s) {
      const d = String(e.detail || "").toLowerCase();
      const k = d.includes("favicon") ? "favicon" : d.includes("error") ? "error" : d.includes("status") ? "status" : d.includes("tls") ? "tls" : null;
      if (k) s.probes[k] = "active";
    }
    if (e.step === "tls_found" && s) { s.probes.tls = "done"; s.notes.tls = "captured"; }
    if (e.step === "leak_found" && s) { s.probes.status = "done"; s.notes.status = e.path; }
    if (["offline", "blocked"].includes(e.step) && s) { s.state = "failed"; Object.keys(s.probes).forEach((k) => { if (s.probes[k] === "pending" || s.probes[k] === "active") s.probes[k] = "failed"; }); }
    if (["fingerprinted", "service_done"].includes(e.step) && s) { s.state = "done"; Object.keys(s.probes).forEach((k) => { if (s.probes[k] !== "failed") s.probes[k] = "done"; }); }
    if (e.step === "comparing") out.compare = "active";
    if (e.step === "compared") { out.compare = "done"; out.fusion = "active"; }
  }
  if (status === "completed") out.fusion = "done";
  if (status === "failed") out.fusion = "failed";
  return out;
}

function path(x1, y1, x2, y2) { const dx = (x2 - x1) * .48; return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`; }
function Particles({ d, active, color = "var(--acid)" }) { if (!active) return null; return <>{[0, .55, 1.1].map((n) => <circle key={n} r="2.5" fill={color}><animateMotion path={d} dur="1.65s" begin={`${n}s`} repeatCount="indefinite" /><animate attributeName="opacity" values="0;1;1;0" dur="1.65s" begin={`${n}s`} repeatCount="indefinite" /></circle>)}</>; }
function Node({ x, y, label, sub, state = "pending", w = NW, accent = false }) { const c = C[state]; return <g><rect x={x + 4} y={y + 4} width={w} height={NH} fill="#000" /><rect x={x} y={y} width={w} height={NH} fill="var(--surface)" stroke={c} strokeWidth={accent ? 2.4 : 1.4}>{state === "active" && <animate attributeName="stroke-opacity" values="1;.3;1" dur="1.2s" repeatCount="indefinite" />}</rect><rect x={x} y={y} width="5" height={NH} fill={c} /><text x={x + 13} y={y + 18} fill={state === "pending" ? "var(--ink-faint)" : "var(--ink)"} style={{ font: "700 10px var(--mono)" }}>{label}</text><text x={x + 13} y={y + 32} fill="var(--ink-faint)" style={{ font: "8px var(--mono)" }}>{String(sub || state).slice(0, 22)}</text></g>; }

export default function LiveAttributionCanvas({ events = [], hosts = {}, status = "idle", result = null }) {
  const st = useMemo(() => derive(events, status), [events, status]);
  const ax = 30, bx = 30, probeX = 265, mergeX = 570, verdictX = 840;
  return <div className="flowcanvas"><svg viewBox={`0 0 ${VW} ${VH}`} width="100%" style={{ display: "block", minWidth: 900 }}><defs><pattern id="latgrid" width="22" height="22" patternUnits="userSpaceOnUse"><path d="M22 0L0 0 0 22" fill="none" stroke="rgba(255,255,255,.028)" /></pattern></defs><rect width={VW} height={VH} fill="url(#latgrid)" />
    <Node x={ax} y={72} label="SERVICE A" sub={hosts?.a || "select service"} state={st.a.state} accent />
    <Node x={bx} y={276} label="SERVICE B" sub={hosts?.b || "select service"} state={st.b.state} accent />
    {PROBES.map(([k, label], i) => { const y1 = 18 + i * 59, y2 = 222 + i * 31; const da = path(ax + NW, 93, probeX, y1 + NH / 2); const db = path(bx + NW, 297, probeX, y2 + NH / 2); return <g key={k}><path d={da} fill="none" stroke="var(--line-hard)" /><path d={db} fill="none" stroke="var(--line-hard)" /><Particles d={da} active={st.a.probes[k] === "active"} /><Particles d={db} active={st.b.probes[k] === "active"} color="var(--info)" /><Node x={probeX} y={y1} label={`A · ${label}`} sub={st.a.notes[k]} state={st.a.probes[k]} /><Node x={probeX} y={y2} label={`B · ${label}`} sub={st.b.notes[k]} state={st.b.probes[k]} /></g>; })}
    {(() => { const d1 = path(probeX + NW, 175, mergeX, 175); const d2 = path(probeX + NW, 286, mergeX, 205); const d3 = path(mergeX + 180, 190, verdictX, 190); return <><path d={d1} fill="none" stroke="var(--line-hard)" /><path d={d2} fill="none" stroke="var(--line-hard)" /><path d={d3} fill="none" stroke="var(--line-hard)" /><Particles d={d1} active={st.compare === "active"} /><Particles d={d2} active={st.compare === "active"} color="var(--info)" /><Particles d={d3} active={st.fusion === "active"} color="var(--violet)" /></>; })()}
    <Node x={mergeX} y={166} w={180} label="SIGNAL COMPARISON" sub={`${events.length} collection steps`} state={st.compare} accent />
    <Node x={verdictX} y={166} w={180} label="FUSION + VERDICT" sub={result ? `${result.tier || "result"} · ${result.icd203?.band || ""}` : "LLR · dependence · grade"} state={st.fusion} accent />
  </svg><div className="flowlegend"><span><i className="dot" style={{ background: "var(--acid)" }} /> service A</span><span><i className="dot" style={{ background: "var(--info)" }} /> service B</span><span><i className="dot" style={{ background: "var(--violet)" }} /> fusion</span><span className="grow" /><span className="mono-label">{status} · LIVE DARKGUARD</span></div></div>;
}
