import { useEffect, useMemo, useState } from "react";
import { Card, RiskGauge, SeverityPill, Stat } from "../components/ui.jsx";
import EvidenceGraph from "../components/EvidenceGraph.jsx";
import { getJSON, postJSON, uploadFile } from "../api.js";

const TABS = ["Incidents", "Agent Security", "AI Discovery", "Data Leakage", "Agent Behaviour", "Live Events"];

const PROBLEM_NAMES = {
  1: "Unauthorized tool usage", 2: "Memory poisoning", 3: "Malicious plugins/tools",
  4: "Goal manipulation", 5: "Harmful autonomous actions", 6: "Indirect prompt injection",
  7: "Multi-agent comms attacks", 8: "Identity & permission misuse",
};

export default function Dashboard({ feed }) {
  const { stats, incidents, events, flash } = feed;
  const [tab, setTab] = useState("Incidents");
  const [sel, setSel] = useState(null);
  const [scan, setScan] = useState("");
  const [scanRes, setScanRes] = useState(null);
  const [busy, setBusy] = useState(false);

  const leakEvents = useMemo(() => events.filter((e) => e.findings?.length), [events]);
  const agentEvents = useMemo(() => events.filter((e) => e.behavior?.length), [events]);
  const providers = stats?.providers || {};
  const [cov, setCov] = useState(null);
  useEffect(() => { getJSON("/api/coverage").then(setCov).catch(() => {}); }, [stats?.incidents]);

  async function runScan() {
    setBusy(true);
    const r = await postJSON("/api/scan", { text: scan });
    setScanRes(r.findings || []);
    setBusy(false);
  }
  async function onUpload(e) {
    const f = e.target.files?.[0];
    if (f) await uploadFile(f);
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      {/* top bar */}
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-display text-3xl font-bold uppercase">Command Center</h1>
          <p className="font-mono text-xs text-ink/60">Live AI Shadow IT &amp; exfiltration monitoring</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <label className="btn-ghost cursor-pointer text-xs">
            Upload HAR / JSONL
            <input type="file" accept=".har,.json,.jsonl" className="hidden" onChange={onUpload} />
          </label>
        </div>
      </div>

      {/* stat row */}
      <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
        <RiskGauge score={stats?.risk_score ?? 0} />
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
          <Stat label="Incidents" value={stats?.incidents ?? 0} accent="bg-crit" sub={`${stats?.by_level?.critical ?? 0} crit`} />
          <Stat label="Events seen" value={stats?.events ?? 0} accent="bg-cyan" />
          <Stat label="Unapproved AI" value={stats?.unapproved ?? 0} accent="bg-hot" sub="shadow" />
          <Stat label="Data leaks" value={stats?.data_leaks ?? 0} accent="bg-volt" />
          <Stat label="Risky agents" value={stats?.risky_agents ?? 0} accent="bg-grape" />
        </div>
      </div>

      {/* scan box */}
      <div className="mt-4 card p-4">
        <div className="label">Inspect a payload (entropy + regex + PII)</div>
        <div className="mt-2 flex flex-col gap-2 sm:flex-row">
          <input value={scan} onChange={(e) => setScan(e.target.value)}
            placeholder="Paste an authorized prompt or request body for local inspection"
            className="flex-1 border-[3px] border-ink bg-paper px-3 py-2 font-mono text-sm outline-none focus:bg-volt/30" />
          <button className="btn-acid" onClick={runScan} disabled={busy}>{busy ? "…" : "Scan"}</button>
        </div>
        {scanRes && (
          <div className="mt-3 flex flex-wrap gap-2">
            {scanRes.length === 0 && <span className="font-mono text-xs text-ink/60">No sensitive data found.</span>}
            {scanRes.map((f, i) => (
              <span key={i} className="chip bg-paper">
                <b>{f.label}</b>&nbsp;<span className="font-mono">{f.match_masked}</span>
                <SeverityPill level={f.severity} />
              </span>
            ))}
          </div>
        )}
      </div>

      {/* tabs */}
      <div className="mt-6 flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`border-[3px] border-ink px-3 py-1.5 font-bold uppercase text-xs tracking-wide shadow-brutal-sm transition-all ${
              tab === t ? "bg-ink text-volt" : "bg-panel hover:bg-volt"}`}>
            {t}
          </button>
        ))}
      </div>

      <div className="mt-4">
        {tab === "Incidents" && (
          <div className="grid gap-3">
            {incidents.length === 0 && <Empty text="Waiting for authenticated live telemetry from an enrolled sensor or Guardian gateway." />}
            {incidents.map((inc) => (
              <button key={inc.incident_id} onClick={() => setSel(inc)}
                className={`card group flex items-center gap-4 p-4 text-left transition-transform hover:-translate-y-0.5 ${
                  flash?.incident_id === inc.incident_id ? "animate-pop ring-4 ring-volt" : ""}`}>
                <ScoreBadge score={inc.score} level={inc.level} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityPill level={inc.level} />
                    <StatusBadge status={inc.status} />
                    <ModeChip mode={inc.mode} />
                    <span className="tag">{inc.host}</span>
                    <span className="font-mono text-[10px] text-ink/50">{inc.cause?.replace(/_/g, " ")}</span>
                  </div>
                  <div className="mt-1 truncate font-display font-bold">{inc.title}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {(inc.signals?.data_leak || []).slice(0, 3).map((d) => <span key={d} className="tag bg-crit/10">{d}</span>)}
                    {(inc.problems || []).map((p) => <span key={p} className="tag bg-grape/20" title={PROBLEM_NAMES[p]}>P{p}</span>)}
                  </div>
                </div>
                <span className="hidden shrink-0 font-mono text-xs text-ink/50 group-hover:text-ink sm:block">inspect →</span>
              </button>
            ))}
          </div>
        )}

        {tab === "Agent Security" && (
          <div className="grid gap-4">
            <Card title="AI-agent security coverage — the 8 problems behind one Guardian gate">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {Object.entries(PROBLEM_NAMES).map(([num, name]) => {
                  const hits = cov?.fired?.[num] || 0;
                  const lit = hits > 0;
                  return (
                    <div key={num} className={`border-[3px] border-ink p-3 shadow-brutal-sm ${lit ? "bg-acid" : "bg-paper"}`}>
                      <div className="flex items-center justify-between">
                        <span className="font-display text-lg font-bold">P{num}</span>
                        <span className={`chip ${lit ? "bg-ink text-volt" : "bg-paper"}`}>{lit ? `${hits} fired` : "ready"}</span>
                      </div>
                      <div className="mt-1 font-mono text-[11px] leading-snug">{name}</div>
                      <div className="mt-1 font-mono text-[9px] text-ink/50">{cov?.problems?.[num]?.module}</div>
                    </div>
                  );
                })}
              </div>
            </Card>
            <Card title="APEX Tool Trust — tool / plugin / MCP inventory">
              <div className="grid gap-2">
                {(cov?.tools || []).map((t) => (
                  <div key={t.tool_id} className="flex items-center justify-between border-[3px] border-ink bg-paper p-2 shadow-brutal-sm">
                    <div>
                      <span className="font-display font-bold">{t.tool_id}</span>
                      <span className="ml-2 font-mono text-[11px] text-ink/60">{t.publisher || "—"}{t.endpoint ? ` · ${t.endpoint}` : ""}</span>
                    </div>
                    <span className={`chip ${t.trust === "approved" ? "bg-low" : t.trust === "unknown" ? "bg-med" : "bg-crit text-white"}`}>{t.trust}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}

        {tab === "AI Discovery" && (
          <Card title="AI providers seen (approved vs shadow)">
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(providers).length === 0 && <Empty text="No AI destinations observed yet." />}
              {Object.entries(providers).map(([p, n]) => (
                <div key={p} className="flex items-center justify-between border-[3px] border-ink bg-paper p-3 shadow-brutal-sm">
                  <div>
                    <div className="font-display font-bold">{p}</div>
                    <div className="font-mono text-[11px] text-ink/60">{p.includes("local") ? "local LLM" : "cloud API"}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="chip bg-hot text-white">unapproved</span>
                    <span className="font-display text-2xl font-bold">{n}</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {tab === "Data Leakage" && (
          <Card title="Sensitive data in outgoing payloads (masked)">
            <div className="grid gap-2">
              {leakEvents.length === 0 && <Empty text="No data-leak events yet." />}
              {leakEvents.map((e) => (
                <div key={e.id} className="border-[3px] border-ink bg-paper p-3 shadow-brutal-sm">
                  <div className="flex items-center gap-2">
                    <span className="tag">{e.process?.name}</span>
                    <span className="font-mono text-[11px] text-ink/60">→ {e.destination?.provider || e.destination?.host}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {e.findings.map((f, i) => (
                      <span key={i} className="chip bg-panel">
                        <b>{f.label}</b>&nbsp;<span className="font-mono">{f.match_masked}</span>
                        <SeverityPill level={f.severity} />
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {tab === "Agent Behaviour" && (
          <Card title="Autonomous-agent behaviour alerts">
            <div className="grid gap-2">
              {agentEvents.length === 0 && <Empty text="No risky agent behaviour yet." />}
              {agentEvents.map((e) => (
                <div key={e.id} className="border-[3px] border-ink bg-paper p-3 shadow-brutal-sm">
                  <div className="flex items-center gap-2">
                    <span className="tag">{e.process?.name}</span>
                    {e.process?.parent && <span className="font-mono text-[11px] text-ink/60">⤵ {e.process.parent}</span>}
                  </div>
                  {e.behavior.map((b, i) => (
                    <div key={i} className="mt-2 flex items-center gap-2">
                      <SeverityPill level={b.severity} />
                      <span className="font-mono text-xs">{b.detail}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </Card>
        )}

        {tab === "Live Events" && (
          <Card title="Raw normalized event stream">
            <div className="max-h-[480px] overflow-auto font-mono text-[11px]">
              {events.map((e) => (
                <div key={e.id} className="flex items-center gap-3 border-b border-ink/10 py-1">
                  <span className="text-ink/40">{e.ts?.slice(11, 19)}</span>
                  <span className="chip bg-paper">{e.source}</span>
                  <span className="text-ink/70">{e.process?.name}</span>
                  <span className="text-hot">→ {e.destination?.provider || e.destination?.host || "—"}</span>
                  {e.findings?.length > 0 && <span className="text-crit">⚠ {e.findings.length} finding(s)</span>}
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>

      {sel && <IncidentDrawer inc={sel} onClose={() => setSel(null)} />}
    </main>
  );
}

function StatusBadge({ status }) {
  const map = {
    exposed: "bg-crit text-white",
    contained: "bg-low",
    open: "bg-paper",
  };
  const icon = { exposed: "⚠ EXPOSED", contained: "✓ CONTAINED", open: "○ OPEN" }[status] || status;
  return <span className={`chip ${map[status] || "bg-paper"}`}>{icon}</span>;
}

function ModeChip({ mode }) {
  return (
    <span className={`chip ${mode === "gateway" ? "bg-cyan" : "bg-paper"}`} title={mode === "gateway" ? "pre-execution enforcement" : "detection after the fact"}>
      {mode === "gateway" ? "⛬ gateway" : "👁 observe"}
    </span>
  );
}

function ScoreBadge({ score, level }) {
  const c = { critical: "bg-crit text-white", high: "bg-high", medium: "bg-med", low: "bg-low" }[level];
  return (
    <div className={`grid h-16 w-16 shrink-0 place-items-center border-[3px] border-ink shadow-brutal-sm ${c}`}>
      <div className="text-center leading-none">
        <div className="font-display text-2xl font-bold">{score}</div>
        <div className="font-mono text-[8px] uppercase">risk</div>
      </div>
    </div>
  );
}

function Empty({ text }) {
  return <div className="border-[3px] border-dashed border-ink/40 p-8 text-center font-mono text-sm text-ink/50">{text}</div>;
}

function IncidentDrawer({ inc, onClose }) {
  const [q, setQ] = useState("");
  const [ans, setAns] = useState(null);
  const [loading, setLoading] = useState(false);

  async function ask() {
    setLoading(true);
    const r = await postJSON("/api/copilot", { question: q || "Explain this incident and how to fix it.", incident_id: inc.incident_id });
    setAns(r);
    setLoading(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-ink/40" onClick={onClose}>
      <div className="h-full w-full max-w-2xl overflow-auto border-l-[3px] border-ink bg-paper p-5 shadow-brutal-lg"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityPill level={inc.level} />
              <StatusBadge status={inc.status} />
              <ModeChip mode={inc.mode} />
              {inc.taint > 0 && <span className="chip bg-grape text-white">taint {inc.taint}</span>}
              <span className="tag">{inc.host}</span>
            </div>
            <h2 className="mt-2 font-display text-2xl font-bold">{inc.title}</h2>
          </div>
          <button className="btn-ghost px-3 py-1" onClick={onClose}>✕</button>
        </div>

        <div className="mt-4 grid grid-cols-[auto_1fr] items-center gap-4 border-[3px] border-ink bg-ink p-4 text-paper">
          <div className="font-display text-5xl font-bold text-volt">{inc.score}</div>
          <div>
            <div className="label text-paper/70">Explainable risk score</div>
            <div className="mt-1 font-mono text-xs text-paper/90">{inc.ai_explanation}</div>
          </div>
        </div>

        {inc.problems?.length > 0 && (
          <Section title="AI-agent security problems implicated">
            <div className="flex flex-wrap gap-2">
              {inc.problems.map((p) => (
                <span key={p} className="chip bg-grape text-white">P{p} · {PROBLEM_NAMES[p]}</span>
              ))}
            </div>
          </Section>
        )}

        {inc.guardian?.length > 0 && (
          <Section title="APEX Guardian — pre-execution decisions">
            {inc.guardian.map((g, i) => (
              <div key={i} className={`mb-2 border-[3px] border-ink p-3 ${g.decision === "deny" || g.decision === "pause" ? "bg-crit text-white" : "bg-low"}`}>
                <span className="font-display font-bold uppercase">{g.decision}</span>
                <span className="ml-2 font-mono text-xs">{g.reason}</span>
              </div>
            ))}
          </Section>
        )}

        <Section title="Evidence graph (correlation)">
          <div className="border-[3px] border-ink bg-panel p-2"><EvidenceGraph graph={inc.graph} /></div>
        </Section>

        <Section title="Why this score (every rule cites the events that fired it)">
          <ul className="grid gap-1">
            {(inc.fired_rules?.length ? inc.fired_rules : null)
              ? inc.fired_rules.map((r, i) => (
                  <li key={i} className="flex items-center justify-between gap-2 border-l-4 border-ink bg-panel px-3 py-1 font-mono text-xs">
                    <span><b className="text-crit">+{r.points}</b> {r.detail}</span>
                    {r.event_ids?.length > 0 && <span className="shrink-0 text-ink/40">{r.event_ids.length} evt</span>}
                  </li>
                ))
              : inc.score_reasons?.map((r, i) => (
                  <li key={i} className="border-l-4 border-ink bg-panel px-3 py-1 font-mono text-xs">{r}</li>
                ))}
          </ul>
        </Section>

        {inc.darkguard && (
          <Section title="DarkGuard — external exposure">
            <div className="flex items-center gap-3 border-[3px] border-ink bg-cyan p-3">
              <div className="font-display text-3xl font-bold">{inc.darkguard.exposure_score}</div>
              <div className="font-mono text-xs">
                Asset already exposed on: {inc.darkguard.sources?.join(", ")}
                {inc.darkguard.demo && <span className="ml-1 opacity-60">(demo intel)</span>}
              </div>
            </div>
          </Section>
        )}

        <Section title="Remediation">
          <ul className="grid gap-1">
            {inc.remediation?.map((r, i) => (
              <li key={i} className="flex items-start gap-2 font-mono text-xs"><span className="text-crit">▸</span>{r}</li>
            ))}
          </ul>
        </Section>

        <Section title="Ask the Featherless copilot">
          <div className="flex flex-col gap-2 sm:flex-row">
            <input value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="Why is this critical? What do we fix first?"
              className="flex-1 border-[3px] border-ink bg-panel px-3 py-2 font-mono text-sm outline-none focus:bg-volt/30" />
            <button className="btn-cyan" onClick={ask} disabled={loading}>{loading ? "…" : "Ask"}</button>
          </div>
          {ans && (
            <div className="mt-3 border-[3px] border-ink bg-panel p-3">
              <div className="label">Copilot {ans.used_llm ? "· Featherless" : "· offline fallback"}</div>
              <p className="mt-1 font-mono text-xs leading-relaxed">{ans.answer}</p>
            </div>
          )}
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="mt-5">
      <div className="label mb-2">{title}</div>
      {children}
    </div>
  );
}
