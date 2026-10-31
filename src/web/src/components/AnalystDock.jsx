import { useEffect, useRef, useState } from "react";
import { postJSON } from "../lib/api.js";

export default function AnalystDock({ feed }) {
  const [open, setOpen] = useState(false);
  const [incidentId, setIncidentId] = useState("");
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [wordlist, setWordlist] = useState([]);
  const [messages, setMessages] = useState([{ who: "apex", text: "SENTINEL agent ready. Bind an incident or type help." }]);
  const end = useRef(null);
  const incidents = feed?.incidents || [];
  const bound = incidentId || incidents[0]?.incident_id || "";
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, open]);

  async function send(raw = input) {
    const text = raw.trim(); if (!text || busy || !feed?.session) return;
    setMessages((x) => [...x, { who: "you", text }]); setInput(""); setBusy(true);
    try {
      const r = await postJSON("/api/console", { message: text, incident_id: bound || null });
      if (r.wordlist) setWordlist(r.wordlist);
      let answer = r.answer || "Completed.";
      if (r.job) answer += `\nJob ${r.job.id}: ${r.job.status}`;
      if (r.osint) answer += `\nPassive evidence: ${(r.osint.results || []).reduce((n, x) => n + (x.findings || []).length, 0)} finding(s).`;
      if (r.darkweb) answer += `\nDarkGuard: ${r.darkweb.status}.`;
      setMessages((x) => [...x, { who: "apex", text: answer, evidence: r.evidence_only }]);
    } catch (e) { setMessages((x) => [...x, { who: "apex", text: `Error: ${e.message}`, error: true }]); }
    finally { setBusy(false); }
  }

  return <>
    <button className="analyst-dock-toggle" onClick={() => setOpen((x) => !x)} aria-expanded={open}>
      <span className="livedot" style={{ background: feed?.connected ? "var(--ok)" : "var(--warn)" }} /> APEX AGENT {open ? "×" : "↑"}
    </button>
    {open && <section className="analyst-dock" aria-label="SENTINEL analyst console">
      <div className="panel-head"><span>// analyst console</span><span className="tag">{bound ? "incident bound" : "unbound"}</span></div>
      <div className="analyst-dock-body">
        <select className="input" value={bound} onChange={(e) => setIncidentId(e.target.value)}>
          <option value="">No incident</option>{incidents.map((i) => <option value={i.incident_id} key={i.incident_id}>{i.title?.slice(0, 46)}</option>)}
        </select>
        {!!wordlist.length && <div className="chips">{wordlist.map((w) => <button key={w} className="chip" onClick={() => send(`remove keyword ${w}`)}>{w} ×</button>)}</div>}
        <div className="analyst-dock-log">{messages.map((m, i) => <div className="row" style={{ gap: 8, alignItems: "flex-start" }} key={i}><span className="mono-label" style={{ minWidth: 36, color: m.who === "you" ? "var(--info)" : m.error ? "var(--alert)" : "var(--acid)" }}>{m.who}</span><div className="snip" style={{ whiteSpace: "pre-wrap", color: m.error ? "var(--alert)" : "var(--ink)" }}>{m.text}{m.evidence && <span className="tag" style={{ marginLeft: 5, color: "var(--ok)" }}>cited</span>}</div></div>)}<div ref={end} /></div>
        <div className="row" style={{ gap: 6 }}><input className="input" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()} placeholder={feed?.session ? "help · show wordlist · search…" : "Complete Setup first"} disabled={!feed?.session} /><button className="btn btn-primary btn-sm" onClick={() => send()} disabled={busy || !feed?.session}>{busy ? "…" : "Send"}</button></div>
        <div className="row wrap" style={{ gap: 5 }}>{["help", "show wordlist", "run full investigation", "why did this flag fire?"].map((x) => <button className="tag" style={{ cursor: "pointer", background: "none" }} key={x} onClick={() => send(x)} disabled={!feed?.session}>{x}</button>)}</div>
      </div>
    </section>}
  </>;
}
