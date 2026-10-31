import { useEffect, useRef, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { postJSON } from "../../lib/api.js";

const COMMANDS = [
  "show wordlist", "add keyword <term>", "remove keyword <term>",
  "search <email/domain/ip/@handle>", "darkweb search <term>",
  "run full investigation", "isolate agent <registered-agent-id>", "why did this flag fire?",
];

export default function Console() {
  const feed = useOutletContext();
  const incidents = feed.incidents || [];
  const [sel, setSel] = useState("");
  const [msg, setMsg] = useState("");
  const [wordlist, setWordlist] = useState([]);
  const [log, setLog] = useState([{ who: "apex", text: "Evidence-only analyst console online. Bind an incident or type 'help'." }]);
  const [busy, setBusy] = useState(false);
  const endRef = useRef(null);
  const incidentId = sel || incidents[0]?.incident_id || "";
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [log]);
  useEffect(() => { setWordlist([]); }, [incidentId]);

  async function send(value = msg) {
    const m = value.trim(); if (!m) return;
    setLog((l) => [...l, { who: "you", text: m }]); setMsg(""); setBusy(true);
    try {
      const r = await postJSON("/api/console", { message: m, incident_id: incidentId || null });
      if (r.wordlist) setWordlist(r.wordlist);
      let text = r.answer || "(no response)";
      if (r.osint) {
        const count = (r.osint.results || []).reduce((n, x) => n + (x.findings || []).length, 0);
        text += `\nOverweb evidence: ${count} live finding(s).`;
      }
      if (r.darkweb) text += `\nDarkGuard: ${r.darkweb.status}; ${(r.darkweb.results || []).length} finding(s).`;
      if (r.job) text += `\nInvestigation job: ${r.job.id} · ${r.job.status}`;
      if (r.report?.cited_event_ids) text += `\nCitations: ${r.report.cited_event_ids.map((x) => "#" + x.slice(-6)).join(" ")}`;
      setLog((l) => [...l, { who: "apex", text, action: r.action, evidence_only: r.evidence_only }]);
    } catch (e) {
      setLog((l) => [...l, { who: "apex", text: `Error: ${e.message}`, error: true }]);
    } finally { setBusy(false); }
  }

  return <div>
    <div className="page-title"><div><div className="eyebrow">// Analyst steering · auditable commands</div><h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>SENTINEL side console</h1><p>Redirect searches, edit the evidence-derived wordlist, start investigation, isolate an agent, or ask for a cited explanation.</p></div><select className="input" style={{ maxWidth: 360 }} value={incidentId} onChange={(e) => setSel(e.target.value)}><option value="">no incident bound</option>{incidents.map((i) => <option key={i.incident_id} value={i.incident_id}>{i.title?.slice(0, 58)}</option>)}</select></div>

    <div className="grid" style={{ gridTemplateColumns: "1fr 310px", gap: 16, alignItems: "start" }}>
      <div className="panel ticked"><div className="panel-head"><span>sentinel@apex ~ % console</span><span className="tag">{incidentId ? "incident bound" : "bind incident for actions"}</span></div><div className="panel-pad"><div style={{ minHeight: 330, maxHeight: "56vh", overflow: "auto", display: "grid", alignContent: "start", gap: 10 }}>{log.map((l, i) => <div key={i} className="row" style={{ gap: 10, alignItems: "flex-start" }}><span className="mono-label" style={{ minWidth: 48, color: l.who === "you" ? "var(--info)" : l.error ? "var(--alert)" : "var(--acid)" }}>{l.who === "you" ? "you" : "apex"}</span><div className="snip" style={{ color: l.error ? "var(--alert)" : "var(--ink)", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{l.text}{l.evidence_only && <span className="pill" style={{ marginLeft: 8, color: "var(--ok)", borderColor: "var(--ok)" }}>evidence-only</span>}</div></div>)}<div ref={endRef} /></div><div className="row" style={{ gap: 8, marginTop: 14 }}><input className="input" value={msg} onChange={(e) => setMsg(e.target.value)} placeholder='"search attacker@example.com" or "why did this flag fire?"' onKeyDown={(e) => { if (e.key === "Enter") send(); }} /><button className="btn btn-primary" onClick={() => send()} disabled={busy}>{busy ? "Working…" : "Send"}</button></div></div></div>

      <div style={{ display: "grid", gap: 14 }}><div className="panel"><div className="panel-head"><span>Editable wordlist</span><span className="tag">{wordlist.length}</span></div><div className="panel-pad"><div className="chips">{wordlist.map((w) => <button key={w} className="chip" style={{ cursor: "pointer" }} title="Click to remove" onClick={() => send(`remove keyword ${w}`)}>{w} ×</button>)}{!wordlist.length && <span className="snip">Type “show wordlist” after footprint extraction.</span>}</div></div></div><div className="panel"><div className="panel-head"><span>Commands</span></div><div className="panel-pad" style={{ display: "grid", gap: 6 }}>{COMMANDS.map((c) => <button key={c} className="snip" style={{ textAlign: "left", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--ink-dim)", padding: 7, cursor: "pointer" }} onClick={() => setMsg(c.includes("<") ? c : c)}>{c}</button>)}</div></div><div className="panel panel-pad"><div className="mono-label">Safety boundary</div><p className="snip" style={{ marginTop: 7 }}>The console calls a fixed command router. It cannot invent evidence or execute arbitrary shell commands. Active scanning is never launched without separate target authorization.</p></div></div>
    </div>
  </div>;
}
