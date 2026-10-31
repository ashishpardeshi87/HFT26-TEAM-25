import { Link } from "react-router-dom";
import ShieldMark from "../components/ShieldMark.jsx";
import SiteFooter from "../components/SiteFooter.jsx";

const PIPE = [
  ["Telemetry Collection", "psutil · scapy · browser ext · PCAP/HAR upload", "src"],
  ["AI Provider Fingerprinting", "cloud hosts + local LLM ports", "det"],
  ["Secret / PII Detection", "regex + entropy · Aadhaar/Verhoeff · Luhn", "det"],
  ["Agent Behaviour + Injection", ".env/shell/flags · untrusted content", "det"],
  ["Risk Correlation Engine", "graph: who → what → where → so-what", "cor"],
  ["Threat Scoring", "explainable 0–100 · event-cited rules", "cor"],
  ["Guardian", "allow / warn / deny / pause at the gateway", "enf"],
  ["Featherless Copilot", "explain + remediate (masked evidence)", "ai"],
];

const LAYERS = [
  ["Injection Guard", "content ingress", "scan untrusted content, raise session taint"],
  ["Memory Guard", "memory write + retrieval", "provenance + revalidation; poisoned memory can't drive actions"],
  ["Tool Trust", "tool registration + runtime", "approved / unknown / revoked; deny unvetted plugins & MCP"],
  ["Agent Trust", "agent-to-agent messages", "authenticate A→B; no trust inheritance"],
  ["Behaviour Intelligence", "action sequences", "flag drift chains ending in egress"],
];

export default function HowItWorks() {
  return (
    <div>
      <header className="topbar">
        <div className="container inner">
          <Link to="/" className="logo"><ShieldMark size={20} /> SENTINEL APEX</Link>
          <nav className="navlinks">
            <Link to="/">Home</Link>
            <Link to="/app">Command Center</Link>
          </nav>
          <Link to="/app" className="btn btn-sm btn-primary">Open Command Center →</Link>
        </div>
      </header>

      <section className="hero" style={{ paddingBottom: 20 }}>
        <div className="container">
          <div className="eyebrow">// Architecture</div>
          <h1 className="display" style={{ marginTop: 14, fontSize: "clamp(2rem,5vw,3.4rem)" }}>
            One gate. Seven observation layers.
          </h1>
          <p className="lead" style={{ maxWidth: 820 }}>
            Detection produces signals at observation points; APEX Guardian is the only authority that
            allows, warns, denies, or pauses an action. Everything correlates into one incident with a cause chain.
          </p>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="sec-head"><span className="ix">01 /</span><h2 className="display">The pipeline</h2></div>
          <div className="grid g4">
            {PIPE.map(([t, p], i) => (
              <div className="cap ticked" key={t}>
                <div className="no" style={{ color: "var(--acid)" }}>/{String(i + 1).padStart(2, "0")}</div>
                <h3 className="display" style={{ fontSize: ".98rem", marginTop: 10 }}>{t}</h3>
                <p style={{ fontSize: ".8rem" }}>{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="sec-head"><span className="ix">02 /</span><h2 className="display">Agent-security modules</h2></div>
          <div className="grid g3">
            {LAYERS.map(([t, point, p]) => (
              <div className="panel panel-pad ticked" key={t}>
                <div className="mono-label" style={{ color: "var(--acid)" }}>{point}</div>
                <h3 className="display" style={{ fontSize: "1.05rem", marginTop: 8 }}>{t}</h3>
                <p style={{ fontSize: ".86rem", marginTop: 8, color: "var(--ink-dim)" }}>{p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <div className="banner" style={{ borderColor: "var(--warn)", background: "rgba(255,176,32,.06)", color: "var(--warn)" }}>
            <span>
              // Honest scope: HTTPS payloads are read only from pre-encryption sources (browser extension,
              local-LLM plaintext, hooks, uploads) — never arbitrary wire traffic. Guardian enforces for managed
              agents (gateway mode) and detects + contains for unmanaged ones (observe mode). DarkGuard external
              exposure is a lead, not attribution.
            </span>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
