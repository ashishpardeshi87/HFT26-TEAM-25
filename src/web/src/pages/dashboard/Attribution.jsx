import { useEffect, useRef, useState } from "react";
import LiveInfraCanvas from "../../components/LiveInfraCanvas.jsx";
import { api } from "../../lib/api.js";
import { useToast } from "../../lib/ui.jsx";

export default function Attribution() {
  const toast = useToast();
  const [statusInfo, setStatusInfo] = useState(null);
  const [services, setServices] = useState([]);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [state, setState] = useState("idle");
  const [events, setEvents] = useState([]);
  const [hosts, setHosts] = useState({});
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [text, setText] = useState("");
  const [category, setCategory] = useState(null);
  const timer = useRef(null);
  const cursor = useRef(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const info = await api("/attribution/status");
        if (!alive) return;
        setStatusInfo(info);
        if (info.status === "unconfigured" || info.status === "unavailable") {
          setError(info.note || info.error || "DarkGuard live integration is unavailable.");
          return;
        }
        const live = await api("/attribution/live/services");
        if (!alive) return;
        const list = live.services || []; setServices(list);
        if (list.length > 1) { setA(list[0].host); setB(list[1].host); }
        if (!list.length) setError(live.note || "No reachable services are listed by DarkGuard/Tor.");
      } catch (e) { if (alive) setError(e.message || "DarkGuard live service discovery unavailable."); }
    })();
    return () => { alive = false; clearInterval(timer.current); };
  }, []);

  async function run() {
    if (!a || !b || a === b) { toast("Select two different onion services", "warn"); return; }
    clearInterval(timer.current); setState("running"); setEvents([]); setResult(null); setError(""); cursor.current = 0;
    try {
      const started = await api("/attribution/live/start", { method: "POST", body: { a, b } });
      const tick = async () => {
        try {
          const d = await api(`/attribution/live/job/${started.jobId}?after=${cursor.current}`);
          cursor.current = d.lastSeq ?? cursor.current;
          if (d.events?.length) setEvents((x) => [...x, ...d.events].slice(-500));
          setHosts(d.hosts || { a, b }); setState(d.status || "running");
          if (d.status !== "running") {
            clearInterval(timer.current);
            if (d.result) setResult(d.result);
            if (d.error) setError(d.error);
          }
        } catch (e) { clearInterval(timer.current); setState("failed"); setError(e.message); }
      };
      await tick(); timer.current = setInterval(tick, 1500);
    } catch (e) { setState("failed"); setError(e.message); }
  }

  async function categorise() {
    if (text.trim().length < 3) return;
    try { setCategory(await api("/attribution/categorise", { method: "POST", body: { text } })); }
    catch (e) { setError(e.message); }
  }

  return <div>
    <div className="page-title"><div><div className="eyebrow">// DarkGuard APEX · threat-actor attribution</div><h1 className="display" style={{ fontSize: "1.9rem", marginTop: 6 }}>Attribution</h1><p>Compare two currently reachable onion services using DarkGuard's original live infrastructure collection flow and evidence engine.</p></div><span className="pill" style={{ color: statusInfo?.status === "ready" ? "var(--ok)" : "var(--warn)", borderColor: statusInfo?.status === "ready" ? "var(--ok)" : "var(--warn)" }}>{statusInfo?.status || "checking"}</span></div>

    {statusInfo?.status === "unconfigured" && <div className="banner" style={{ borderColor: "var(--warn)", color: "var(--warn)" }}>DarkGuard is not configured. Set DARKGUARD_API_BASE plus DARKGUARD_TOKEN, or DARKGUARD_EMAIL + DARKGUARD_PASSWORD, on the SENTINEL backend. No synthetic fallback is shown.</div>}
    {statusInfo?.status === "degraded" && <div className="banner" style={{ borderColor: "var(--warn)", color: "var(--warn)" }}>{statusInfo.darkguard?.note || "DarkGuard is reachable, but scraper/Tor readiness is degraded. Candidate services may be listed; fingerprinting will remain unavailable until Tor is ready."}</div>}

    <div className="panel ticked" style={{ marginTop: 16 }}><div className="panel-head"><span>Live service pair</span><span className="tag">{services.length} listed by DarkGuard</span></div><div className="panel-pad"><div className="grid g2"><label className="fld"><span>Service A</span><select className="input" value={a} onChange={(e) => setA(e.target.value)}><option value="">Select service</option>{services.map((s) => <option key={s.host} value={s.host}>{s.name || s.host} · {s.host}</option>)}</select></label><label className="fld"><span>Service B</span><select className="input" value={b} onChange={(e) => setB(e.target.value)}><option value="">Select service</option>{services.map((s) => <option key={s.host} value={s.host}>{s.name || s.host} · {s.host}</option>)}</select></label></div><button className="btn btn-primary" style={{ marginTop: 12 }} disabled={state === "running" || services.length < 2} onClick={run}>{state === "running" ? "Fingerprinting over Tor…" : "Start live comparison →"}</button>{error && <div className="snip" style={{ color: "var(--alert)", marginTop: 9 }}>✕ {error}</div>}</div></div>

    <div className="panel ticked" style={{ marginTop: 16 }}><div className="panel-head"><span>// Live collection — what is happening right now</span><span className="tag">original DarkGuard APEX flow</span></div><LiveInfraCanvas events={events} hosts={hosts?.a ? hosts : { a, b }} status={state} verdict={result} /></div>

    {result && <div className="grid g4" style={{ marginTop: 16 }}><Metric label="Verdict" value={result.tier || "—"} color="var(--acid)" /><Metric label="Posterior" value={result.posterior == null ? "—" : `${(result.posterior * 100).toFixed(1)}%`} /><Metric label="ICD 203" value={result.icd203?.band || "—"} /><Metric label="Signals" value={(result.modalitiesSupporting || []).length} /></div>}
    {result && <div className="grid g2" style={{ marginTop: 16 }}><ResultPanel title="Supporting evidence" rows={result.evidence || result.assertions || []} empty="No supporting evidence returned." /><ResultPanel title="Contradictions & unknowns" rows={[...(result.contradictions || []), ...(result.unknownSignals || [])]} empty="No contradictions returned." /></div>}

    <div className="panel ticked" style={{ marginTop: 16 }}><div className="panel-head"><span>Mandate category classifier</span><span className="tag">DarkGuard model</span></div><div className="panel-pad"><div className="row"><textarea className="input grow" rows="3" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste captured listing text to categorise…" /><button className="btn" onClick={categorise}>Categorise</button></div>{category && <pre className="terminal" style={{ marginTop: 10 }}>{JSON.stringify(category, null, 2)}</pre>}</div></div>

    <div className="snip" style={{ marginTop: 14, color: "var(--ink-faint)" }}>Live mode has no known ground truth or measured error rate. The output is an investigative lead for human adjudication, never an identity verdict.</div>
  </div>;
}

function Metric({ label, value, color = "var(--ink)" }) { return <div className="panel panel-pad"><div className="mono-label">{label}</div><div className="display brk" style={{ fontSize: "1.45rem", color, marginTop: 8 }}>{value}</div></div>; }
function ResultPanel({ title, rows, empty }) { return <div className="panel"><div className="panel-head"><span>{title}</span><span className="tag">{rows.length}</span></div><div className="panel-pad">{rows.length ? rows.map((x, i) => <div className="snip" style={{ padding: "7px 0", borderBottom: "1px solid var(--line)" }} key={i}>▸ {x.detail || x.label || x.reason || JSON.stringify(x)}</div>) : <div className="empty">{empty}</div>}</div></div>; }
