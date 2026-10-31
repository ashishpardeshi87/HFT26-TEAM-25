import { useEffect, useRef, useState } from "react";
import { darkguardApi as api, downloadDarkguardFile } from "../../lib/darkguardApi.js";
import { useToast } from "../../lib/ui.jsx";
import ReconGraph from "../../components/ReconGraph.jsx";
import PipelineFlow from "../../components/PipelineFlow.jsx";
import ModelCard from "../../components/ModelCard.jsx";
import FindingEvidence from "../../components/FindingEvidence.jsx";
import { generateOsintReport } from "../../lib/osintReport.js";

// Curated, defensive OSINT resources for manual investigation of your own
// assets (domains, emails, infrastructure, leaks). Asset/breach focused.
const RESOURCES = [
  { group: "Breach & leak", links: [
    ["Have I Been Pwned", "https://haveibeenpwned.com"],
    ["Intelligence X", "https://intelx.io"],
    ["DeHashed", "https://dehashed.com"],
  ]},
  { group: "Infrastructure & DNS", links: [
    ["Shodan", "https://www.shodan.io"],
    ["crt.sh (cert transparency)", "https://crt.sh"],
    ["DNSDumpster", "https://dnsdumpster.com"],
    ["VirusTotal", "https://www.virustotal.com"],
  ]},
  { group: "Frameworks & code", links: [
    ["OSINT Framework", "https://osintframework.com"],
    ["GitHub code search", "https://github.com/search"],
    ["Ahmia (.onion search)", "https://ahmia.fi"],
  ]},
];

const LINE_CLASS = (line) => {
  const m = line.match(/^\[[^\]]+\]\s+(\w+)/);
  const lvl = (m?.[1] || "").toUpperCase();
  if (lvl === "ERR") return "e";
  if (lvl === "WARN") return "w";
  if (lvl === "OK" || lvl === "HEAD") return "o";
  return "";
};

export default function OSINT() {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [infra, setInfra] = useState(null);
  const [graph, setGraph] = useState(null);
  const [risk, setRisk] = useState(null);
  const [attack, setAttack] = useState([]);
  const [paths, setPaths] = useState([]);
  const [pathStats, setPathStats] = useState(null);
  const [recs, setRecs] = useState([]);
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyError, setHistoryError] = useState("");
  const termRef = useRef(null);
  const pollRef = useRef(null);

  const loadHistory = async () => {
    try {
      const data = await api("/osint/history");
      setHistory(data.investigations || []);
      setHistoryError("");
    } catch (error) {
      setHistory([]);
      setHistoryError(error.message || "Investigation history is unavailable.");
    }
  };
  useEffect(() => { loadHistory(); }, []);

  // Auto-scroll the terminal as new lines stream in.
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logs]);

  // Clean up polling on unmount.
  useEffect(() => () => clearInterval(pollRef.current), []);

  const run = async () => {
    const q = query.trim();
    if (q.length < 2) return toast("Enter a domain, email, or keyword", "warn");
    clearInterval(pollRef.current);
    setBusy(true); setLogs([]); setFindings([]); setInfra(null); setGraph(null); setRisk(null); setAttack([]); setPaths([]); setPathStats(null); setRecs([]); setJobId(null); setStatus("running");
    try {
      const { jobId } = await api("/osint/investigate", { method: "POST", body: { query: q } });
      setJobId(jobId);
      pollRef.current = setInterval(async () => {
        try {
          const job = await api(`/osint/jobs/${jobId}`);
          setLogs(job.logs || []);
          setFindings(job.findings || []);
          setInfra(job.infra || null);
          setGraph(job.graph || null);
          setRisk(job.risk || null);
          setAttack(job.attack || []);
          setPaths(job.attackPaths || []);
          setPathStats(job.attackPathStats || null);
          setRecs(job.recommendations || []);
          setStatus(job.status);
          if (job.status === "completed" || job.status === "failed") {
            clearInterval(pollRef.current);
            setBusy(false);
            loadHistory();
            toast(job.status === "failed" ? "Investigation failed" : `${(job.findings || []).length} finding(s)`, job.status === "failed" ? "error" : "ok");
          }
        } catch (e) {
          clearInterval(pollRef.current); setBusy(false); setStatus("failed");
          toast(e.message, "error");
        }
      }, 1200);
    } catch (e) {
      setBusy(false); setStatus(null);
      toast(e.message, "error");
    }
  };

  const summary = findings.reduce((a, f) => { a[f.severity] = (a[f.severity] || 0) + 1; return a; }, {});

  const exportJson = () => {
    if (!jobId) return;
    downloadDarkguardFile(`/osint/investigations/${jobId}/export.json`, `darkguard-investigation-${jobId.slice(0, 8)}.json`)
      .catch((e) => toast(e.message, "error"));
  };

  const openHistory = async (id) => {
    try {
      const { investigation: r } = await api(`/osint/investigations/${id}`);
      setJobId(r.id); setStatus("completed");
      setFindings(r.findings || []); setGraph(r.graph || null); setInfra(r.infra || null);
      setRisk({ score: r.risk_score, level: r.risk_level }); setAttack(r.attack || []); setRecs(r.recommendations || []);
      setPaths(r.attack_paths || []); setPathStats(r.attack_path_stats || null);
      setLogs(r.logs || []); setQuery(r.target?.domain || r.target?.email || r.target?.keyword || "");
      toast("Loaded investigation from history", "ok");
    } catch (e) { toast(e.message, "error"); }
  };

  const RISK_COLOR = risk ? (risk.score >= 70 ? "var(--alert)" : risk.score >= 40 ? "var(--warn)" : "var(--acid)") : "var(--ink-dim)";

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Incident Response</div>
          <h1 className="display">OSINT Console</h1>
          <p>All-in-one investigation for assets you own or are authorized to investigate — breach attribution, leaked secrets, infrastructure footprint &amp; dark-web exposure, streamed live.</p>
        </div>
      </div>

      <div className="panel ticked">
        <div className="panel-head"><span>// Target</span><span className="tag">domain · email · keyword</span></div>
        <div className="panel-pad row">
          <input
            className="input grow"
            placeholder="acme.com · admin@acme.com · brand name"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !busy && run()}
          />
          <button className="btn btn-primary" disabled={busy} onClick={run}>{busy ? "Investigating…" : "▶ Launch"}</button>
        </div>
      </div>

      {/* Pipeline canvas — always rendered. Before a run it shows the topology
          in its idle state so the architecture is legible without launching
          anything; during a run the same nodes light up from the log stream. */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <span>// Pipeline</span>
          <span className="tag" style={{
            color: status === "failed" ? "var(--alert)"
              : status === "completed" ? "var(--ok)"
              : status === "running" ? "var(--acid)" : "var(--ink-dim)",
          }}>
            {status === "running" ? "streaming" : status === "completed" ? "complete" : status === "failed" ? "failed" : "idle · awaiting target"}
          </span>
        </div>
        <PipelineFlow logs={logs} status={status} findings={findings} pathStats={pathStats} risk={risk} />
      </div>

      {/* What the classifier is, how well it measures, and where it fails. */}
      <ModelCard />

      {/* Live terminal */}
      {(logs.length > 0 || status) && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span>// Live investigation log</span>
            <span className="tag" style={{ color: status === "failed" ? "var(--alert)" : status === "completed" ? "var(--ok)" : "var(--info)" }}>
              {status === "running" ? "RUNNING" : status === "completed" ? "DONE" : status === "failed" ? "FAILED" : ""}
            </span>
          </div>
          <div className="terminal" ref={termRef}>
            {logs.map((l, i) => <div key={i} className={LINE_CLASS(l)}>{l}</div>)}
            {busy && <div className="o blink">▌</div>}
          </div>
        </div>
      )}

      {/* Recon graph — the route from the seed to each exposure */}
      {graph && graph.nodes?.length > 1 && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span>// Recon graph — route to root cause</span>
            <span className="tag">{graph.nodes.length} nodes · drag to rotate · click finding to open</span>
          </div>
          <ReconGraph graph={graph} />
        </div>
      )}

      {/* Risk + intelligence */}
      {risk && (status === "completed") && (
        <div className="grid g2" style={{ marginTop: 16 }}>
          <div className="panel">
            <div className="panel-head"><span>// Risk assessment</span>
              <span className="row" style={{ gap: 8 }}>
                <button className="btn btn-sm" disabled={!findings.length} onClick={() => generateOsintReport({ id: jobId, target: { keyword: query }, risk, findings, attack, recommendations: recs })}>↓ PDF</button>
                <button className="btn btn-sm" disabled={!jobId} onClick={exportJson}>↓ JSON</button>
              </span>
            </div>
            <div className="panel-pad row between center">
              <div>
                <div className="mono-label">CLASSIFICATION</div>
                <div className="display" style={{ fontSize: "1.8rem", color: RISK_COLOR }}>{risk.level}</div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div className="mono-label">RISK SCORE</div>
                <div className="metric" style={{ color: RISK_COLOR }}>{risk.score}<span style={{ fontSize: "1rem", color: "var(--ink-dim)" }}>/100</span></div>
              </div>
            </div>
            <div style={{ height: 8, background: "var(--bg)", margin: "0 22px 22px" }}>
              <div style={{ height: "100%", width: `${risk.score}%`, background: RISK_COLOR }} />
            </div>
          </div>

          <div className="panel">
            <div className="panel-head"><span>// MITRE ATT&CK techniques</span><span className="tag">{attack.length}</span></div>
            <div className="panel-pad">
              {attack.length ? (
                <div className="chips">
                  {attack.map((a) => (
                    <a key={a.id} className="chip" href={`https://attack.mitre.org/techniques/${a.id.replace(".", "/")}/`} target="_blank" rel="noreferrer noopener" title={a.tactic} style={{ borderColor: "var(--violet)", color: "var(--violet)" }}>
                      {a.id} · {a.name}
                    </a>
                  ))}
                </div>
              ) : <div className="empty">No techniques mapped.</div>}
            </div>
          </div>
        </div>
      )}

      {/* Attack paths — the join of leaked data against live perimeter state */}
      {status === "completed" && pathStats && (
        <div className="panel" style={{ marginTop: 16, borderColor: paths.length ? "var(--alert)" : "var(--line)" }}>
          <div className="panel-head">
            <span>// Attack paths — what an attacker can do with this</span>
            <span className="tag">
              {pathStats.leakSideFindings} leaked · {pathStats.perimeterSideFindings} live · {paths.length} chain{paths.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="panel-pad" style={{ paddingBottom: 0 }}>
            <div className="snip" style={{ marginBottom: 14 }}>
              Correlated {pathStats.rulesEvaluated} chain rules against this investigation.{" "}
              <b style={{ color: "var(--ink)" }}>{pathStats.rulesSuppressedForLackOfEvidence}</b> stayed silent for lack of
              evidence — a rule cannot fire unless every finding it cites is present.
              {pathStats.crossHalfChains > 0 && (
                <>
                  {" "}
                  <b style={{ color: "var(--alert)" }}>{pathStats.crossHalfChains}</b> chain
                  {pathStats.crossHalfChains === 1 ? "" : "s"} required both leaked data and live perimeter state, so
                  neither a breach monitor nor a port scanner would have surfaced {pathStats.crossHalfChains === 1 ? "it" : "them"} alone.
                </>
              )}
            </div>
          </div>

          {paths.length === 0 ? (
            <div className="panel-pad">
              <div className="empty">
                No exploitable chain found. Findings exist in isolation, but none combine into a route an attacker could walk.
              </div>
            </div>
          ) : (
            <div className="panel-pad" style={{ paddingTop: 0 }}>
              {paths.map((p) => (
                <div key={p.id} className={`chain ${p.severity === "critical" ? "chain-crit" : "chain-high"}`}>
                  <div className="chain-head">
                    <div className="row center" style={{ gap: 10 }}>
                      <span className={`sev sev-${p.severity}`}>{p.severity}</span>
                      <span className="chain-title">{p.title}</span>
                    </div>
                    <span className="chain-meta">{p.exploitability.replace(/-/g, " ")} · score {p.score}</span>
                  </div>

                  <p className="chain-narr">{p.narrative}</p>

                  {/* Audit trail: every claim above rests on these findings */}
                  <div className="mono-label" style={{ marginTop: 12, marginBottom: 4 }}>
                    EVIDENCE · {p.evidence.length} CITATION{p.evidence.length === 1 ? "" : "S"}
                  </div>
                  {p.evidence.map((e) => (
                    <div key={e.index} className="chain-ev">
                      <span className="ix">#{e.index}</span>
                      <span className={`sev sev-${e.severity}`} style={{ flexShrink: 0 }}>{e.severity}</span>
                      <span className="muted" style={{ flexShrink: 0 }}>{(e.category || "").replace(/_/g, " ")}</span>
                      <span className="brk grow">
                        {e.url ? (
                          <a href={e.url} target="_blank" rel="noreferrer noopener" style={{ color: "var(--info)" }}>{e.title}</a>
                        ) : (
                          e.title
                        )}
                      </span>
                      <span className="muted" style={{ flexShrink: 0 }}>{e.engine}</span>
                    </div>
                  ))}

                  <div className="chips" style={{ marginTop: 12 }}>
                    {p.techniques.map((t) => (
                      <a
                        key={t.id}
                        className="chip"
                        href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer noopener"
                        title={`${t.name} · ${t.tactic}`}
                        style={{ borderColor: "var(--violet)", color: "var(--violet)" }}
                      >
                        {t.id} · {t.name}
                      </a>
                    ))}
                  </div>

                  <div className="chain-fix">→ {p.remediation}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Recommendations */}
      {recs.length > 0 && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>// Prioritized remediation</span><span className="tag">{recs.length}</span></div>
          <div className="panel-pad">
            {recs.map((r, i) => (
              <div key={i} className="row" style={{ padding: "8px 0", borderBottom: "1px solid var(--line)", gap: 12 }}>
                <span className={`pill ${r.priority === "P1" ? "pill-failed" : r.priority === "P2" ? "pill-running" : ""}`} style={{ flexShrink: 0 }}>{r.priority}</span>
                <span>{r.text}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary */}
      {findings.length > 0 && (
        <div className="grid g4" style={{ marginTop: 16 }}>
          <Stat label="Findings" value={findings.length} acid />
          <Stat label="Critical" value={summary.critical || 0} alert />
          <Stat label="High" value={summary.high || 0} />
          <Stat label="Medium" value={summary.medium || 0} />
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>Findings</span><span className="tag">{findings.length}</span></div>
          <table>
            <thead><tr><th>Severity</th><th>Category</th><th>Detail</th><th>Source</th></tr></thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td>
                    <span className="mono-label" style={{ display: "block", color: "var(--ink-faint)", marginBottom: 3 }}>#{i}</span>
                    <span className={`sev sev-${f.severity}`}>{f.severity}</span>
                  </td>
                  <td className="muted">{(f.category || "").replace(/_/g, " ")}</td>
                  <td>
                    {f.title || "—"}
                    {/* Why this finding says what it says — hover any badge. */}
                    <FindingEvidence finding={f} />
                    <div className="snip brk">{f.snippet || ""}</div>
                    {f.onion_url && <div className="snip brk"><a href={f.onion_url} target="_blank" rel="noreferrer noopener" style={{ color: "var(--info)" }}>{f.onion_url}</a></div>}
                  </td>
                  <td className="muted">{f.engine}{f.confidence ? ` · ${f.confidence}` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Infrastructure snapshot */}
      {infra && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>Infrastructure footprint</span><span className="brk">{infra.host}</span></div>
          <div className="panel-pad grid g3" style={{ fontSize: ".82rem" }}>
            <KV k="IP addresses" v={(infra.ips || []).join(", ") || "—"} />
            <KV k="Open ports" v={(infra.ports || []).map((p) => `${p.port}${p.risky ? "⚠" : ""}`).join(", ") || "none"} />
            <KV k="Subdomains" v={(infra.subdomains || []).length} />
            <KV k="TLS" v={infra.ssl?.valid ? `valid · ${infra.ssl.daysLeft}d left` : "invalid"} />
            <KV k="Header grade" v={infra.http?.securityHeaders?.grade || "—"} />
            <KV k="SPF / DMARC" v={`${infra.email?.spf?.found ? "SPF✓" : "SPF✗"} · ${infra.email?.dmarc?.found ? "DMARC✓" : "DMARC✗"}`} />
          </div>
        </div>
      )}

      {historyError && (
        <div className="banner" style={{ marginTop: 16, borderColor: "var(--alert)", color: "var(--alert)" }}>
          <span>// Investigation history unavailable: {historyError}</span>
        </div>
      )}

      {/* Investigation history */}
      {history.length > 0 && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>// Investigation history</span><span className="tag">{history.length}</span></div>
          <table>
            <thead><tr><th>Target</th><th>Risk</th><th>Findings</th><th>When</th><th></th></tr></thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} className="clickable" onClick={() => openHistory(h.id)}>
                  <td className="brk">{h.target?.domain || h.target?.email || h.target?.keyword || "—"}</td>
                  <td><span className="sev" style={{ color: h.risk_score >= 70 ? "var(--alert)" : h.risk_score >= 40 ? "var(--warn)" : "var(--acid)", borderColor: "currentColor" }}>{h.risk_score} · {h.risk_level}</span></td>
                  <td>{h.findings_count}</td>
                  <td className="muted">{new Date(h.created_at).toLocaleString()}</td>
                  <td className="muted">↗ open</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Resources */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>// OSINT resources (manual investigation)</span></div>
        <div className="panel-pad grid g3">
          {RESOURCES.map((r) => (
            <div key={r.group}>
              <div className="mono-label" style={{ marginBottom: 8 }}>{r.group}</div>
              {r.links.map(([name, url]) => (
                <div key={url} style={{ padding: "5px 0" }}>
                  <a href={url} target="_blank" rel="noreferrer noopener" className="brk" style={{ color: "var(--acid)" }}>↗ {name}</a>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div className="banner" style={{ marginTop: 16, borderColor: "var(--info)", background: "rgba(76,201,240,.06)", color: "var(--info)" }}>
        <span>// Authorized, defensive monitoring only. Investigate assets you own or are permitted to assess.</span>
      </div>
    </div>
  );
}

function Stat({ label, value, acid, alert }) {
  return (
    <div className="panel panel-pad">
      <div className="mono-label">{label}</div>
      <div className={`metric ${alert ? "alert" : acid ? "acid" : ""}`} style={{ marginTop: 8 }}>{value}</div>
    </div>
  );
}
function KV({ k, v }) {
  return <div className="row between" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}><span className="muted">{k}</span><b className="brk">{v}</b></div>;
}
