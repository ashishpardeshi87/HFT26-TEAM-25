import { useEffect, useState } from "react";
import { getJSON } from "../../lib/api.js";

export default function Landscape() {
  const [data, setData] = useState(null);
  useEffect(() => { getJSON("/api/gaps").then(setData).catch(() => {}); }, []);

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Existing solutions, loopholes, anti-requirements</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Landscape &amp; gaps</h1>
        </div>
        <span className="mono-label">we compete with products · we validate against benchmarks</span>
      </div>

      <div className="banner" style={{ marginTop: 16, borderColor: "var(--warn)", background: "rgba(255,176,32,.06)", color: "var(--warn)" }}>
        <span>Honest framing: Microsoft Defender and Check Point already ship AI-agent discovery and runtime protection. Our contribution is the <b>correlation layer</b> that joins behaviour, endpoint, sensitive-data, and network evidence into one explainable incident — across the gaps where each tool stops.</span>
      </div>

      <div className="panel ticked" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>Per-problem: existing solution → loophole → SENTINEL anti-requirement</span></div>
        <div className="panel-pad">
          <table>
            <thead>
              <tr><th style={{ width: 150 }}>Problem</th><th>Existing &amp; loophole</th><th>SENTINEL anti-requirement</th></tr>
            </thead>
            <tbody>
              {(data?.problems || []).map((p) => (
                <tr key={p.n}>
                  <td><div style={{ fontSize: ".8rem", color: "var(--ink)" }}>{p.n}. {p.problem}</div></td>
                  <td>
                    <div className="snip" style={{ color: "var(--ink-dim)" }}>{p.exists}</div>
                    <div className="snip" style={{ marginTop: 5, color: "var(--warn)" }}>Loophole: {p.loophole}</div>
                  </td>
                  <td><div className="snip" style={{ color: "var(--acid)", lineHeight: 1.55 }}>{p.anti}</div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel ticked" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>Cross-cutting loopholes we refuse (platform anti-requirements)</span></div>
        <div className="panel-pad">
          {(data?.cross_cutting || []).map((c, i) => (
            <div key={i} className="snip" style={{ padding: "7px 0", borderBottom: "1px dashed var(--line)", lineHeight: 1.6 }}>
              <span style={{ color: "var(--acid)", marginRight: 7 }}>✓</span>{c}
            </div>
          ))}
          <p className="snip" style={{ marginTop: 12, color: "var(--ink-faint)" }}>
            A competitor sees one observation column well. SENTINEL's contribution is correlating all of them into a single explainable incident — which is exactly where the landscape's loopholes live.
          </p>
        </div>
      </div>
    </div>
  );
}
