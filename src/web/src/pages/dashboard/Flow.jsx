import { useEffect, useMemo, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import AutonomousFlowCanvas from "../../components/AutonomousFlowCanvas.jsx";
import { getJSON } from "../../lib/api.js";

const COPY = [
  ["1", "Setup", "Real HTTP/SSH/DB ownership proof → agent registry → scenario → compiled 45-rule policy.", "Session Registry · Policy Compiler"],
  ["2", "Monitor", "URL health starts automatically. Enrolled sensors observe metadata; managed agents call the Guardian gateway.", "Target Monitor · Sensors · Gateway"],
  ["3", "Detect", "Injection, secret/PII, poisoned memory, unknown tools, agent messages and behaviour drift.", "Injection · Memory · Tool · Agent Trust"],
  ["4", "Enforce", "Gateway blocks before execution, sends a trusted re-ground message, and quarantines under explicit criteria.", "Guardian · Zero Trust"],
  ["5", "Flag", "What, where, agent/process, destination, violated rules, policy version and internal/external evidence label.", "Correlation Engine"],
  ["6", "Forensics", "Extract delivery vector, payload hash, indicators, connection path and attack behaviour from stored evidence.", "APEX TRACE"],
  ["7", "Wordlist", "Evidence-derived domains, emails, IPs, handles and wallets; editable through the analyst console.", "Wordlist Builder"],
  ["8", "Investigate", "Passive RDAP/WHOIS, crt.sh, DNS, breach and exact-handle lookup + real DarkGuard handoff.", "OSINT · DarkGuard"],
  ["9", "Report", "One cited timeline and execution-linkage graph. Correlation is never mislabeled as proven semantic causation.", "Evidence Store · Assistant"],
];

export default function Flow() {
  const feed = useOutletContext();
  const incident = feed.incidents?.[0];
  const [job, setJob] = useState(null);
  useEffect(() => {
    if (!incident?.incident_id) { setJob(null); return; }
    let alive = true; let timer;
    const poll = async () => { try { const r = await getJSON(`/api/investigations/${incident.incident_id}`); if (!alive) return; setJob(r.job || null); if (["queued", "running"].includes(r.job?.status)) timer = setTimeout(poll, 1600); } catch { /* no job */ } };
    poll(); return () => { alive = false; clearTimeout(timer); };
  }, [incident?.incident_id]);

  const stages = useMemo(() => {
    const session = !!feed.session;
    const events = feed.events?.length || 0;
    const incidents = feed.incidents?.length || 0;
    const guardian = (feed.events || []).some((e) => e.meta?.guardian);
    const words = job?.wordlist?.length || 0;
    return COPY.map(([n, title]) => {
      let state = "idle", detail = "waiting";
      if (n === "1") { state = session ? "done" : "active"; detail = session ? "verified" : "required"; }
      if (n === "2" && session) { state = feed.connected ? "active" : "unavailable"; detail = feed.connected ? "authenticated" : "sensor offline"; }
      if (n === "3" && events) { state = "active"; detail = `${events} event(s)`; }
      if (n === "4" && guardian) { state = "alert"; detail = "policy action"; }
      if (n === "5" && incidents) { state = "done"; detail = `${incidents} incident(s)`; }
      if (n === "6" && job) { state = job.footprint ? "done" : "active"; detail = job.status; }
      if (n === "7" && words) { state = "done"; detail = `${words} keywords`; }
      if (n === "8" && job) { state = job.status === "failed" ? "unavailable" : job.status === "completed" ? "done" : "active"; detail = job.darkweb?.status || job.status; }
      if (n === "9" && incident) { state = "done"; detail = `risk ${incident.score}`; }
      return { n, title, state, detail };
    });
  }, [feed.session, feed.connected, feed.events, feed.incidents, job]);

  return <div>
    <div className="page-title"><div><div className="eyebrow">// Setup-first · automated after verification</div><h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Live end-to-end flow</h1><p>This view is driven by the active session, event stream and investigation job, not a scripted demo.</p></div>{!feed.session && <Link to="/app" className="btn btn-primary">Complete Setup →</Link>}</div>
    <div className="panel ticked" style={{ marginTop: 16 }}><div className="panel-head"><span>// Runtime pipeline canvas</span><span className="tag">{feed.session ? feed.session.session_id : "no active session"}</span></div><AutonomousFlowCanvas stages={stages} /></div>
    <div style={{ marginTop: 16, display: "grid", gap: 10 }}>{COPY.map(([n, title, desc, modules]) => { const s = stages[Number(n) - 1]; const color = s.state === "done" ? "var(--ok)" : s.state === "active" ? "var(--acid)" : s.state === "alert" ? "var(--alert)" : s.state === "unavailable" ? "var(--warn)" : "var(--line-hard)"; return <div className="panel ticked" key={n} style={{ borderLeft: `3px solid ${color}` }}><div className="panel-pad" style={{ display: "grid", gridTemplateColumns: "44px 1fr", gap: 12 }}><div className="display" style={{ fontSize: "1.5rem", color }}>{n}</div><div><div className="row between center"><h3 className="display" style={{ fontSize: ".98rem" }}>{title}</h3><span className="mono-label" style={{ color }}>{s.state} · {modules}</span></div><p className="snip" style={{ marginTop: 5 }}>{desc}</p></div></div></div>; })}</div>
    <div className="banner" style={{ marginTop: 14, borderColor: "var(--info)", color: "var(--ink-dim)" }}>Enforcement is real only for gateway-mediated actions. Unsupported/bypassed paths remain observe-only and are labeled as such. Active ZAP scanning is not launched against third-party infrastructure without separate authorization.</div>
  </div>;
}
