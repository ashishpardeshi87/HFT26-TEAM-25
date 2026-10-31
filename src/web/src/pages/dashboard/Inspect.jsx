import { useState } from "react";
import { postJSON } from "../../lib/api.js";

const EMPTY_PAYLOAD = "";

export default function Inspect() {
  const [text, setText] = useState(EMPTY_PAYLOAD);
  const [res, setRes] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function scan() {
    if (!text.trim()) { setError("Enter a payload to inspect."); return; }
    setBusy(true); setError("");
    try {
      const r = await postJSON("/api/scan", { text });
      setRes(r.findings || []);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Local detection</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Inspect Payload</h1>
        </div>
        <span className="mono-label">entropy + regex + PII · masked</span>
      </div>

      <div className="panel ticked" style={{ marginTop: 18 }}>
        <div className="panel-head"><span>Outgoing payload</span></div>
        <div className="panel-pad">
          <textarea className="input" rows={5} value={text} onChange={(e) => setText(e.target.value)}
            placeholder="Paste a prompt / request body to inspect for secrets & PII…" style={{ resize: "vertical" }} />
          <div className="row" style={{ marginTop: 12, gap: 10 }}>
            <button className="btn btn-primary" onClick={scan} disabled={busy}>{busy ? "Scanning…" : "Scan payload"}</button>
            <button className="btn" onClick={() => { setText(""); setRes(null); setError(""); }}>Clear</button>
          </div>
          {error && <div className="snip" style={{ color: "var(--alert)", marginTop: 8 }}>✕ {error}</div>}
        </div>
      </div>

      {res && (
        <div className="panel ticked" style={{ marginTop: 18 }}>
          <div className="panel-head"><span>Findings</span><span className="tag">{res.length}</span></div>
          <div className="panel-pad">
            {res.length === 0 && <div className="empty">No sensitive data found.</div>}
            <div style={{ display: "grid", gap: 8 }}>
              {res.map((f, i) => (
                <div key={i} className="row between center" style={{ gap: 10, padding: "8px 10px", border: "1.5px solid var(--line-hard)", background: "var(--bg)" }}>
                  <span><b style={{ color: "var(--ink)" }}>{f.label}</b> <span className="snip" style={{ marginLeft: 6 }}>{f.match_masked}</span></span>
                  <span className="row center" style={{ gap: 8 }}>
                    {f.fingerprint && <span className="snip" title="HMAC fingerprint">fp:{f.fingerprint.slice(0, 8)}</span>}
                    <span className={`sev sev-${f.severity}`}>{f.severity}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
