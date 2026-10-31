import { Link } from "react-router-dom";

const STATS = [
  ["43%", "of 2026 breaches involved Shadow AI", "bg-crit text-white"],
  ["~40%", "of AI prompts contain sensitive data", "bg-volt"],
  ["175K+", "Ollama servers exposed, zero auth", "bg-cyan"],
  ["₹250cr", "max DPDP penalty for a leak", "bg-hot text-white"],
];

const FEATURES = [
  ["01", "Passive Telemetry", "Watch local process ↔ network connections, or drop in a PCAP / HAR / request log. No SSL decryption, no enterprise agent.", "bg-acid"],
  ["02", "Shadow AI Discovery", "Fingerprint every AI destination — OpenAI, Anthropic, Cursor, Copilot, and local LLMs by port (Ollama :11434). Approved vs unapproved.", "bg-cyan"],
  ["03", "Secret & PII Detection", "Regex + Shannon entropy for API keys, JWTs and private keys. Presidio-style PII with Aadhaar (Verhoeff) & card (Luhn) validation.", "bg-volt"],
  ["04", "Agent Behaviour", "Flag the s1ngularity pattern — agents reading .env / SSH keys, spawning shells, or launched with --dangerously-skip-permissions.", "bg-hot text-white"],
  ["05", "Graph Correlation", "Fuse where + who + what + how + so-what into ONE scored incident with an evidence graph, not five disconnected alerts.", "bg-grape text-white"],
  ["AI", "Featherless Copilot", "A local-first LLM copilot explains each masked incident in plain English and writes remediation for the security admin.", "bg-panel"],
];

export default function Home({ stats }) {
  return (
    <main>
      {/* HERO */}
      <section className="border-b-[3px] border-ink">
        <div className="mx-auto grid max-w-7xl gap-8 px-4 py-14 lg:grid-cols-[1.3fr_1fr] lg:py-20">
          <div>
            <span className="chip bg-volt">AI Security &amp; Data Privacy · Problem Statement Locked</span>
            <h1 className="mt-5 font-display text-5xl font-bold leading-[0.95] tracking-tight sm:text-6xl lg:text-7xl">
              See every AI<br />your org uses.<br />
              <span className="bg-crit px-2 text-white">Catch every leak.</span>
            </h1>
            <p className="mt-6 max-w-xl font-mono text-sm leading-relaxed text-ink/80">
              SENTINEL APEX is a non-invasive endpoint &amp; network auditing engine for the AI Shadow IT crisis.
              It discovers unmonitored AI tools, inspects outgoing payloads for secrets &amp; PII, flags rogue
              autonomous agents, and fuses it all into one correlated, scored incident.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/dashboard" className="btn bg-acid text-base">Open Command Center →</Link>
              <Link to="/architecture" className="btn-ghost text-base">View Architecture</Link>
            </div>
          </div>

          <div className="card p-5">
            <div className="label">The problem, in numbers</div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              {STATS.map(([n, t, c]) => (
                <div key={t} className={`border-[3px] border-ink p-3 shadow-brutal-sm ${c}`}>
                  <div className="font-display text-3xl font-bold leading-none">{n}</div>
                  <div className="mt-2 font-mono text-[11px] leading-snug">{t}</div>
                </div>
              ))}
            </div>
            <div className="mt-4 border-t-[3px] border-dashed border-ink pt-3 font-mono text-[10px] text-ink/60">
              Sources: IBM Cost of a Data Breach 2026 · Cyberhaven Labs · SentinelOne+Censys · DPDP Rules 2025
            </div>
          </div>
        </div>
      </section>

      {/* TICKER */}
      <div className="overflow-hidden border-b-[3px] border-ink bg-ink py-2 text-volt">
        <div className="mx-auto max-w-7xl px-4 font-mono text-xs uppercase tracking-widest">
          ◆ Discover ◆ Monitor ◆ Detect ◆ Correlate ◆ Investigate ◆ Contain ◆ Verify ◆ Report ◆
        </div>
      </div>

      {/* FEATURES */}
      <section className="mx-auto max-w-7xl px-4 py-14">
        <h2 className="font-display text-3xl font-bold uppercase">What it does</h2>
        <p className="mt-1 font-mono text-sm text-ink/70">Five problem-statement requirements + a Featherless copilot, one platform.</p>
        <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(([tag, title, body, c]) => (
            <div key={title} className="card p-5 transition-transform hover:-translate-y-1">
              <div className={`mb-3 inline-grid h-10 w-10 place-items-center border-[3px] border-ink font-display font-bold shadow-brutal-sm ${c}`}>{tag}</div>
              <h3 className="font-display text-lg font-bold">{title}</h3>
              <p className="mt-2 font-mono text-xs leading-relaxed text-ink/75">{body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FLOW */}
      <section className="border-y-[3px] border-ink bg-grape/20">
        <div className="mx-auto max-w-7xl px-4 py-14">
          <h2 className="font-display text-3xl font-bold uppercase">Left of boom + right of boom</h2>
          <div className="mt-6 grid gap-5 lg:grid-cols-2">
            <div className="card bg-acid p-5">
              <div className="label">SENTINEL APEX · prevent</div>
              <p className="mt-2 font-display text-xl font-bold">Catch the leak as it happens</p>
              <p className="mt-2 font-mono text-xs text-ink/80">Endpoint telemetry + payload inspection + agent monitoring, correlated into a live incident the moment data heads to an unapproved AI tool.</p>
            </div>
            <div className="card bg-cyan p-5">
              <div className="label">DarkGuard · detect</div>
              <p className="mt-2 font-display text-xl font-bold">Know what already leaked</p>
              <p className="mt-2 font-mono text-xs text-ink/80">Every serious incident is cross-referenced against dark-web &amp; breach intelligence to see whether the asset is already exposed externally.</p>
            </div>
          </div>
          <div className="mt-8 flex justify-center">
            <Link to="/dashboard" className="btn bg-volt text-base">Launch the live demo →</Link>
          </div>
        </div>
      </section>
    </main>
  );
}
