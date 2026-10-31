import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import ShieldMark from "../components/ShieldMark.jsx";
import SiteFooter from "../components/SiteFooter.jsx";
import NetworkField from "../components/NetworkField.jsx";
import { getJSON } from "../lib/api.js";

function Console() {
  const [lines, setLines] = useState([["CONNECTING", "querying local SENTINEL backend…", ""]]);
  useEffect(() => {
    let alive = true;
    Promise.allSettled([
      getJSON("/api/health"), getJSON("/api/policy"),
      getJSON("/api/telemetry"), getJSON("/api/evidence/integrity"),
    ]).then(([h, p, t, e]) => {
      if (!alive) return;
      const health = h.status === "fulfilled" ? h.value : null;
      const pol = p.status === "fulfilled" ? p.value.summary : null;
      const tel = t.status === "fulfilled" ? t.value : null;
      const integrity = e.status === "fulfilled" ? e.value : null;
      setLines([
        ["BACKEND", health ? `${health.service} v${health.version} · real-only runtime` : "unreachable", health ? "" : "red"],
        ["SETUP", health?.setup_required ? "ownership proof required before monitoring" : "status unavailable", ""],
        ["POLICY", pol ? `${pol.total} rules · ${pol.floor} floor · v${pol.policy_version}` : "unavailable", pol ? "" : "red"],
        ["GUARDIAN", pol?.design_invariant || "independent policy gate", ""],
        ["TELEMETRY", tel ? `${tel.monitoring_state} · ${tel.note}` : "unavailable", tel?.monitoring_state === "active" ? "" : "red"],
        ["EVIDENCE", integrity ? `${integrity.ok ? "chain verified" : "integrity warning"} · ${integrity.records_total} records` : "unavailable", integrity?.ok ? "" : "red"],
        ["DARKGUARD", health?.darkguard?.configured ? "live bridge configured" : "unconfigured · no fallback intel", health?.darkguard?.configured ? "" : "red"],
      ]);
    });
    return () => { alive = false; };
  }, []);
  return (
    <div className="console">
      <div className="bar"><span className="dot" /> SYSTEM STATUS // sentinel@apex ~ %</div>
      <div className="body">
        {lines.map((l, k) => <div className="ln" key={k}><b>[{String(k).padStart(2, "0")}]</b> {l[0]} :: <span style={{ color: l[2] === "red" ? "var(--alert)" : "var(--acid)" }}>{l[1]}</span></div>)}
        <div className="ln"><b>$</b> real telemetry only<span className="blink">_</span></div>
      </div>
    </div>
  );
}

const PROBLEMS = [
  ["P1", "Unauthorized tool usage", "Verb-scoped manifest at the gateway: send_email with an external recipient is a transmit scope, gated separately from read_inbox."],
  ["P2", "Memory poisoning", "Agent memory is inspected on write and revalidated on retrieval — a poisoned instruction can't silently drive a future tool call."],
  ["P3", "Malicious plugins / tools", "Tool Trust inventories every plugin/MCP server; unknown or schema-changed tools are denied at runtime."],
  ["P4", "Goal manipulation", "Behaviour Intelligence flags drift chains — individually-allowed steps that end in sensitive-read → egress."],
  ["P5", "Harmful autonomous actions", "An action policy matrix: delete pauses for approval, permission changes deny, destructive shell blocked."],
  ["P6", "Indirect prompt injection", "Injection Guard scans untrusted content at ingress and raises session taint before the agent acts."],
  ["P7", "Multi-agent comms attacks", "Agent Trust authenticates A→B messages; B never inherits A's trust when the chain traces to tainted content."],
  ["P8", "Identity & permission misuse", "Session Registry scopes each task; inherited rights never grant use outside the declared objective."],
];

export default function Landing() {
  const tick = "SHADOW AI DISCOVERY · SECRET & PII DETECTION · AGENT BEHAVIOUR · GRAPH CORRELATION · GUARDIAN ENFORCEMENT · ";
  return (
    <div>
      <header className="topbar">
        <div className="container inner">
          <div className="logo"><ShieldMark size={20} /> SENTINEL APEX</div>
          <nav className="navlinks">
            <a href="#capabilities">Capabilities</a>
            <Link to="/how-it-works">How it works</Link>
            <a href="#coverage">Coverage</a>
            <a href="#about">About</a>
            <Link to="/app">Command Center</Link>
          </nav>
          <Link to="/app" className="btn btn-sm btn-primary">Open Command Center →</Link>
        </div>
      </header>

      <div className="ticker">
        <div className="track">
          {Array.from({ length: 6 }).map((_, i) => <span key={i}>{tick}</span>)}
        </div>
      </div>

      <section className="hero" style={{ position: "relative", overflow: "hidden" }}>
        <NetworkField opacity={0.55} max={80} linkDist={160} />
        <div className="container hero-grid" style={{ position: "relative", zIndex: 1 }}>
          <div>
            <div className="eyebrow">// AI Security &amp; Data Privacy</div>
            <h1 className="display" style={{ marginTop: 16 }}>
              AI Shadow IT,<br /><em>exfiltration</em>,<br /><span className="out">surfaced.</span>
            </h1>
            <p className="lead">
              SENTINEL APEX passively audits endpoint &amp; network activity for unmonitored AI tools,
              inspects outgoing payloads for secrets and PII, flags rogue autonomous agents — then
              fuses every signal into one correlated, scored incident. No SSL interception. No agent sprawl.
            </p>
            <div className="row wrap">
              <Link to="/app" className="btn btn-primary">Open Command Center</Link>
              <a href="#capabilities" className="btn">View Capabilities</a>
            </div>
            <div className="kvs">
              <div className="kv"><div className="n">45</div><div className="l">Versioned baseline security rules</div></div>
              <div className="kv"><div className="n">4</div><div className="l">Zero-trust checks per sensitive action</div></div>
              <div className="kv"><div className="n">0</div><div className="l">Raw secrets retained in evidence</div></div>
            </div>
          </div>
          <Console />
        </div>
      </section>

      <section className="section" id="capabilities">
        <div className="container">
          <div className="sec-head"><span className="ix">01 /</span><h2 className="display">Capabilities</h2></div>
          <div className="grid g3">
            {[
              ["A", "Shadow AI Discovery", "Fingerprint every AI destination — OpenAI, Anthropic, Cursor, Copilot, Hugging Face — and local LLMs by port (Ollama :11434). Approved vs unapproved by policy."],
              ["B", "Secret & PII Detection", "Regex + Shannon entropy for API keys, JWTs and private keys; Presidio-style PII with Aadhaar (Verhoeff) and card (Luhn) validation. All masked locally."],
              ["C", "Agent Behaviour & Injection", "Flag the s1ngularity pattern — .env reads, shell spawns, --dangerously-skip-permissions — and detect indirect prompt injection in untrusted content."],
              ["D", "Graph Correlation", "Fuse where + who + what + how + so-what into one scored incident with an evidence graph, not five disconnected alerts."],
              ["E", "Guardian Enforcement", "One gate for every action: allow / warn / deny / pause against a verb-scoped capability manifest. Taint tightens, never loosens."],
              ["F", "Featherless Copilot", "A local-first LLM explains each masked incident in plain English and writes remediation — detection stays deterministic."],
            ].map(([no, t, p]) => (
              <div className="cap ticked" key={no}>
                <div className="no">/{no}</div>
                <h3 className="display">{t}</h3>
                <p>{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="coverage">
        <div className="container">
          <div className="sec-head"><span className="ix">02 /</span><h2 className="display">Full agent-security coverage</h2></div>
          <p style={{ maxWidth: 760, marginBottom: 26, color: "var(--ink-dim)" }}>
            Eight known AI-agent security problems, each with an observation point, a signal producer, and a
            Guardian policy — behind <b style={{ color: "var(--ink)" }}>one enforcement gate</b>. The defensible
            contribution is the cross-layer correlation, not any single detector.
          </p>
          <div className="grid g4">
            {PROBLEMS.map(([no, t, p]) => (
              <div className="cap ticked" key={no}>
                <div className="no" style={{ color: "var(--acid)" }}>{no}</div>
                <h3 className="display" style={{ fontSize: "1rem", marginTop: 10 }}>{t}</h3>
                <p style={{ fontSize: ".82rem" }}>{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="process">
        <div className="container">
          <div className="sec-head"><span className="ix">03 /</span><h2 className="display">How it runs</h2></div>
          <div className="steps">
            {[
              ["01", "Observe", "Passive process↔network telemetry, browser prompts captured pre-encryption, local-LLM plaintext, or an uploaded PCAP / HAR / log."],
              ["02", "Detect", "Provider fingerprinting, secret & PII detection, agent-behaviour analysis, injection scanning — all deterministic and local."],
              ["03", "Correlate", "Related signals join into one incident with an evidence graph and an explainable 0–100 risk score."],
              ["04", "Contain", "Guardian allows / denies at the gateway; the Featherless copilot explains the incident and writes the fix."],
            ].map(([n, t, p]) => (
              <div className="step" key={n}>
                <div className="sn">{n}</div>
                <div><h3 className="display">{t}</h3><p>{p}</p></div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="about">
        <div className="container">
          <div className="sec-head"><span className="ix">04 /</span><h2 className="display">About</h2></div>
          <div className="about-grid">
            <div>
              <p className="lead" style={{ marginTop: 0 }}>
                SENTINEL APEX is an AI-security, runtime-protection and threat-intelligence platform for the
                AI Shadow IT crisis.
              </p>
              <p className="muted" style={{ maxWidth: "52ch" }}>
                Built by <b style={{ color: "var(--ink)" }}>The Nice Guys (TEAM-25)</b>, a student team from
                Sanjivani University, Kopargaon, for CBIT Hacktoberfest '26 — AI Security &amp; Data Privacy.
                It pairs with our DarkGuard dark-web intelligence platform for left-of-boom + right-of-boom coverage.
              </p>
              <div className="about-chips">
                <span className="a-chip">🛡️ AI Shadow IT</span>
                <span className="a-chip">🤖 Agent Security</span>
                <span className="a-chip">🔐 Data Exfiltration</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="cta">
        <div className="container">
          <div className="eyebrow">// Ready when you are</div>
          <h2 className="display" style={{ marginTop: 14 }}>See every AI your org uses.<br />Catch every leak.</h2>
          <p>Open Setup, enroll your agents, or inspect a payload through an active session.</p>
          <Link to="/app" className="btn btn-primary">Open the Command Center →</Link>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
