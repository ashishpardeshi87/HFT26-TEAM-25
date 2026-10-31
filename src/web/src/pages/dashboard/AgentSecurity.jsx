import { useOutletContext } from "react-router-dom";
import { useEffect, useState } from "react";
import { getJSON } from "../../lib/api.js";

const NAMES = {
  1: "Unauthorized tool usage", 2: "Memory poisoning", 3: "Malicious plugins / tools",
  4: "Long-term goal manipulation", 5: "Harmful autonomous actions", 6: "Indirect prompt injection",
  7: "Multi-agent comms attacks", 8: "Identity & permission misuse",
};

export default function AgentSecurity() {
  const feed = useOutletContext();
  const [cov, setCov] = useState(null);
  useEffect(() => { getJSON("/api/coverage").then(setCov).catch(() => {}); }, [feed.stats?.incidents]);

  const fired = cov?.fired || {};
  const tools = cov?.tools || [];
  const trustColor = (t) => t === "approved" ? "var(--ok)" : t === "unknown" ? "var(--warn)" : "var(--alert)";

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// AI-agent security control map</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Agent Security</h1>
        </div>
        <span className="mono-label">8 problem classes · mode/telemetry limits apply</span>
      </div>

      <div className="grid g4" style={{ marginTop: 18 }}>
        {Object.entries(NAMES).map(([num, name]) => {
          const hits = fired[num] || 0;
          const lit = hits > 0;
          return (
            <div key={num} className="panel panel-pad ticked" style={{ borderColor: lit ? "var(--acid)" : "var(--line-hard)" }}>
              <div className="row between center">
                <span className="display" style={{ fontSize: "1.3rem", color: lit ? "var(--acid)" : "var(--ink-faint)" }}>P{num}</span>
                <span className="pill" style={{ color: lit ? "var(--acid)" : "var(--ink-faint)", borderColor: lit ? "var(--acid)" : "var(--line-hard)" }}>
                  {lit ? `${hits} fired` : "no signal"}
                </span>
              </div>
              <div style={{ marginTop: 8, fontSize: ".86rem", color: "var(--ink)" }}>{name}</div>
              <div className="snip" style={{ marginTop: 4 }}>{cov?.problems?.[num]?.module}</div>
            </div>
          );
        })}
      </div>

      <div className="panel ticked" style={{ marginTop: 18 }}>
        <div className="panel-head"><span>APEX Tool Trust · plugin / MCP inventory</span><span className="tag">{tools.length} tools</span></div>
        <div className="panel-pad">
          {tools.length === 0 && <div className="empty">No tools registered yet.</div>}
          {tools.map((t) => (
            <div key={t.tool_id} className="row between center" style={{ padding: "9px 0", borderBottom: "1px solid var(--line)", gap: 10 }}>
              <div style={{ minWidth: 0 }}>
                <b style={{ color: "var(--ink)" }}>{t.tool_id}</b>
                <span className="snip" style={{ marginLeft: 8 }}>{t.publisher || "—"}{t.endpoint ? ` · ${t.endpoint}` : ""}</span>
              </div>
              <span className="sev" style={{ color: trustColor(t.trust), borderColor: trustColor(t.trust) }}>{t.trust}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
