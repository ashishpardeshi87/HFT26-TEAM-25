import { Link } from "react-router-dom";
import ShieldMark from "./ShieldMark.jsx";

export default function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="container sf-grid">
        <div className="sf-brand">
          <div className="logo"><ShieldMark size={20} /> SENTINEL APEX</div>
          <p>Non-invasive AI Shadow IT &amp; agentic data-exfiltration scanner. Discover unmonitored AI usage, catch secret/PII leaks, and stop rogue autonomous agents — all correlated into one incident. Defensive, authorized monitoring only.</p>
          <div className="sf-contact">
            <div><b>Team</b> · The Nice Guys · TEAM-25</div>
            <div><b>Event</b> · CBIT Hacktoberfest '26 · AI Security &amp; Data Privacy</div>
          </div>
        </div>
        <div className="sf-col">
          <h5>Platform</h5>
          <Link to="/">Home</Link>
          <Link to="/how-it-works">How it works</Link>
          <Link to="/app">Command Center</Link>
          <Link to="/app/agent-security">Agent Security</Link>
        </div>
        <div className="sf-col">
          <h5>Coverage</h5>
          <Link to="/app/agent-security">8 agent-security problems</Link>
          <Link to="/app/incidents">Incidents</Link>
          <Link to="/app/inspect">Payload inspection</Link>
          <Link to="/app/live">Live telemetry</Link>
        </div>
        <div className="sf-col">
          <h5>Project</h5>
          <Link to="/how-it-works">Architecture</Link>
          <a href="https://darkguard.in" target="_blank" rel="noreferrer">DarkGuard (threat intel)</a>
          <Link to="/app">Run a scan</Link>
        </div>
      </div>
      <div className="container sf-bottom">
        <span>© {new Date().getFullYear()} SENTINEL APEX — TEAM-25 · The Nice Guys. MIT licensed.</span>
        <div className="sf-social">
          <Link to="/how-it-works">How it works</Link>
          <Link to="/app">Command Center</Link>
        </div>
      </div>
    </footer>
  );
}
