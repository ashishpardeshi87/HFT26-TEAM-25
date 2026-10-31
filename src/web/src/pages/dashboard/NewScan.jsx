import { useEffect, useRef, useState } from "react";
import { api } from "../../lib/api.js";
import Terminal from "../../components/Terminal.jsx";
import ScanResults from "../../components/ScanResults.jsx";
import ScanPipeline from "../../components/ScanPipeline.jsx";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const URL_RE = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i;
const detect = (v) => (EMAIL_RE.test(v) ? "email" : URL_RE.test(v) ? "website" : "keyword");

// What actually runs for each target type — honest about the real data source.
const SOURCES = {
  email: [["XposedOrNot", "breach database — breaches, exposed data classes, risk score"]],
  website: [["crt.sh", "certificate-transparency logs — subdomain & shadow-infra discovery"]],
  keyword: [["crt.sh", "certificate-transparency brand search — lookalikes & impersonation"]],
};

export default function NewScan() {
  const [value, setValue] = useState("");
  const [status, setStatus] = useState("");
  const [scan, setScan] = useState(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef(null);

  useEffect(() => () => clearInterval(timer.current), []);

  const kind = detect(value.trim());

  const poll = (id) => {
    clearInterval(timer.current);
    const tick = async () => {
      try {
        const { scan } = await api(`/scans/${id}`);
        setScan(scan);
        if (scan.status === "running") setStatus("Sweeping live sources — this can take a moment…");
        else if (scan.status === "queued") setStatus("Queued…");
        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(timer.current); setBusy(false);
          setStatus(scan.status === "failed" ? `Failed: ${scan.error || "unknown"}` : "");
        }
      } catch (e) { clearInterval(timer.current); setBusy(false); setStatus("Error: " + e.message); }
    };
    tick(); timer.current = setInterval(tick, 1500);
  };

  const run = async () => {
    const v = value.trim();
    if (!v) return;
    setBusy(true); setScan(null); setStatus("Queuing scan…");
    const body = kind === "email" ? { email: v }
      : kind === "website" ? { targetUrl: v }
      : { query: v };
    try {
      const { scan } = await api("/scans", { method: "POST", body });
      poll(scan.id);
    } catch (e) { setBusy(false); setStatus("Error: " + e.message); }
  };

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// New Scan</div>
          <h1 className="display">Run a sweep</h1>
          <p>Email, company domain, or brand keyword. Real breach databases and certificate-transparency logs — no API keys, no mock data.</p>
        </div>
      </div>

      <div className="panel ticked">
        <div className="panel-head"><span>// Target</span><span className="tag">type: {kind}</span></div>
        <div className="panel-pad">
          <div className="row">
            <input
              className="input grow"
              placeholder="you@company.com  ·  acme.com  ·  brand keyword"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
            />
            <button className="btn btn-primary" disabled={busy} onClick={run}>
              {busy ? "Scanning…" : "Execute"}
            </button>
          </div>

          <div className="engs" style={{ flexDirection: "column", alignItems: "flex-start", gap: 6 }}>
            <span className="mono-label">SOURCES FOR THIS TARGET</span>
            {(SOURCES[kind] || []).map(([name, desc]) => (
              <div key={name} className="row center" style={{ gap: 8 }}>
                <span className="aibadge" style={{ borderColor: "var(--acid)", color: "var(--acid)" }}>{name}</span>
                <span className="snip">{desc}</span>
              </div>
            ))}
          </div>

          {status && (
            <div className="row center" style={{ marginTop: 16, fontSize: ".8rem", color: "var(--ink-dim)" }}>
              <span className="dotpulse" /> {status}
            </div>
          )}
        </div>
      </div>

      {scan && (
        <div className="panel" style={{ marginTop: 20 }}>
          <div className="panel-head"><span>// Collection pipeline</span><span className="tag">{scan.status}</span></div>
          <ScanPipeline scan={scan} />
        </div>
      )}

      {scan && scan.status !== "completed" && (
        <div className="panel" style={{ marginTop: 20 }}>
          <div className="panel-head"><span>// Live sweep</span><span className="tag blink">_</span></div>
          <div className="panel-pad"><Terminal logs={scan.logs} /></div>
        </div>
      )}

      {scan && scan.status === "completed" && (
        <div style={{ marginTop: 20 }}><ScanResults scan={scan} /></div>
      )}
    </div>
  );
}
