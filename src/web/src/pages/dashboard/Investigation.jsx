import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { getJSON, postJSON } from "../../lib/api.js";

const ReconGraph = lazy(() => import("../../components/ReconGraph.jsx"));

// Turn the real forensic footprint (+ any OSINT overlay) into a 3D route map.
const TYPE_FOR = {
  email: "email", domain: "subdomain", destination: "subdomain", ip: "ip",
  eth_wallet: "finding", btc_wallet: "finding", handle: "tech", payload_hash: "neighbor",
};
function buildReconGraph(fp, osint) {
  if (!fp?.ok) return null;
  const nodes = [{ id: "root", type: "root", label: (fp.title || "INCIDENT").slice(0, 24) }];
  const edges = [];
  let k = 0;
  for (const [key, vals] of Object.entries(fp.parameters || {})) {
    for (const v of vals) {
      const id = `p${k++}`;
      nodes.push({
        id, type: TYPE_FOR[key] || "neighbor", label: String(v),
        severity: key.includes("wallet") ? "high" : undefined, snippet: key.replace(/_/g, " "),
      });
      edges.push({ source: "root", target: id, label: key });
    }
  }
  (fp.vectors || []).forEach((vec, i) => {
    const id = `v${i}`;
    nodes.push({ id, type: "finding", severity: "critical", label: vec, snippet: "attack vector" });
    edges.push({ source: "root", target: id, label: "vector" });
  });
  if (osint?.results) {
    osint.results.forEach((r, ri) => {
      const kw = nodes.find((n) => n.label === r.keyword);
      const base = kw ? kw.id : "root";
      r.findings.forEach((f, fi) => {
        const id = `o${ri}_${fi}`;
        nodes.push({ id, type: "tech", label: f.tool, snippet: f.detail, engine: f.tool });
        edges.push({ source: base, target: id, label: "osint" });
      });
    });
  }
  return { nodes, edges };
}

export default function Investigation() {
  const feed = useOutletContext();
  const incidents = feed.incidents || [];
  const [sel, setSel] = useState("");
  const [fp, setFp] = useState(null);
  const [wl, setWl] = useState([]);
  const [add, setAdd] = useState("");
  const [osint, setOsint] = useState(null);
  const [dark, setDark] = useState(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const incidentId = sel || incidents[0]?.incident_id || "";
  const recon = useMemo(() => buildReconGraph(fp, osint), [fp, osint]);

  useEffect(() => {
    setFp(null); setOsint(null); setDark(null); setJob(null); setError("");
    if (!incidentId) return;
    let alive = true; let timer;
    const poll = async () => {
      try {
        const r = await getJSON(`/api/investigations/${incidentId}`);
        if (!alive || !r.job) return;
        setJob(r.job);
        if (r.job.footprint) { setFp(r.job.footprint); setWl(r.job.wordlist || []); }
        if (r.job.overweb) setOsint(r.job.overweb);
        if (r.job.darkweb) setDark(r.job.darkweb);
        if (["queued", "running"].includes(r.job.status)) timer = setTimeout(poll, 1500);
      } catch { /* no automatic job yet */ }
    };
    poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [incidentId]);

  async function extract() {
    if (!incidentId) return;
    setBusy("trace"); setOsint(null); setDark(null); setError("");
    try { const r = await postJSON("/api/trace", { incident_id: incidentId }); setFp(r); setWl(r.wordlist || []); }
    catch (e) { setError(e.message); }
    finally { setBusy(""); }
  }
  async function editWl(addArr, removeArr) {
    try { const r = await postJSON("/api/wordlist", { incident_id: incidentId, add: addArr, remove: removeArr }); setWl(r.wordlist || []); }
    catch (e) { setError(e.message); }
  }
  async function runOsint() { setBusy("osint"); setError(""); try { setOsint(await postJSON("/api/osint", { keywords: wl })); } catch (e) { setError(e.message); } finally { setBusy(""); } }
  async function runDark() { setBusy("dark"); setError(""); try { setDark(await postJSON("/api/darkweb", { keywords: wl })); } catch (e) { setError(e.message); } finally { setBusy(""); } }
  async function runAll() { setBusy("all"); setError(""); try { const r = await postJSON(`/api/investigations/${incidentId}/start`, {}); setJob(r.job); } catch (e) { setError(e.message); } finally { setBusy(""); } }

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Stage 6–8 · Forensics → wordlist → OSINT + darkweb</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Investigation</h1>
        </div>
        <span className="mono-label">attacker footprint attribution</span>
      </div>

      <div className="panel ticked" style={{ marginTop: 18 }}>
        <div className="panel-pad row wrap center" style={{ gap: 10 }}>
          <select className="input" style={{ maxWidth: 440 }} value={incidentId} onChange={(e) => setSel(e.target.value)}>
            {incidents.length === 0 && <option value="">No incidents — waiting for authenticated live telemetry</option>}
            {incidents.map((i) => <option key={i.incident_id} value={i.incident_id}>[{i.level}] {i.title?.slice(0, 70)}</option>)}
          </select>
          <button className="btn btn-sm btn-primary" onClick={runAll} disabled={!incidentId || busy === "all"}>{busy === "all" ? "Starting…" : "Run full automated investigation"}</button>
          <button className="btn btn-sm" onClick={extract} disabled={!incidentId || busy === "trace"}>{busy === "trace" ? "Extracting…" : "Extract footprint only"}</button>
          {job && <span className="pill" style={{ color: job.status === "completed" ? "var(--ok)" : job.status === "failed" ? "var(--alert)" : "var(--acid)" }}>{job.status}</span>}
          {error && <span className="snip" style={{ color: "var(--alert)" }}>✕ {error}</span>}
        </div>
      </div>

      {fp?.ok && (
        <>
          {recon && recon.nodes.length > 1 && (
            <div className="panel ticked" style={{ marginTop: 16 }}>
              <div className="panel-head">
                <span>// Attribution route map · 3D</span>
                <span className="tag">{recon.nodes.length} nodes · drag to orbit{osint ? " · OSINT overlaid" : ""}</span>
              </div>
              <div className="proccanvas">
                <Suspense fallback={<div className="empty" style={{ minHeight: 520, display: "grid", placeItems: "center" }}>rendering recon graph…</div>}>
                  <ReconGraph graph={recon} />
                </Suspense>
              </div>
            </div>
          )}

          <div className="grid g2" style={{ marginTop: 16, alignItems: "start" }}>
            <div className="panel ticked">
              <div className="panel-head"><span>Attacker footprint</span><span className="tag">{fp.cause?.replace(/_/g, " ")}</span></div>
              <div className="panel-pad">
                {Object.entries(fp.parameters || {}).map(([k, v]) => (
                  <div key={k} className="row" style={{ gap: 10, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                    <span className="mono-label" style={{ minWidth: 120 }}>{k}</span>
                    <span className="snip" style={{ color: "var(--ink)" }}>{v.join(", ")}</span>
                  </div>
                ))}
                {fp.vectors?.length > 0 && <div className="snip" style={{ marginTop: 10 }}>vectors: {fp.vectors.join(" · ")}</div>}
              </div>
            </div>

            <div className="panel ticked">
              <div className="panel-head"><span>Search wordlist (editable)</span><span className="tag">{wl.length}</span></div>
              <div className="panel-pad">
                <div className="row wrap" style={{ gap: 6 }}>
                  {wl.map((w) => (
                    <span key={w} className="chip" style={{ gap: 6 }}>{w}
                      <button onClick={() => editWl([], [w])} style={{ cursor: "pointer", background: "none", border: 0, color: "var(--alert)" }}>×</button>
                    </span>
                  ))}
                  {wl.length === 0 && <span className="snip">no keywords yet</span>}
                </div>
                <div className="row" style={{ gap: 8, marginTop: 12 }}>
                  <input className="input" value={add} onChange={(e) => setAdd(e.target.value)} placeholder="add a keyword (e.g. an email you found in the logs)"
                    onKeyDown={(e) => { if (e.key === "Enter" && add.trim()) { editWl([add.trim()], []); setAdd(""); } }} />
                  <button className="btn btn-sm" onClick={() => { if (add.trim()) { editWl([add.trim()], []); setAdd(""); } }}>Add</button>
                </div>
                <div className="row" style={{ gap: 8, marginTop: 14 }}>
                  <button className="btn btn-sm btn-primary" onClick={runOsint} disabled={!wl.length || busy === "osint"}>{busy === "osint" ? "…" : "Run overweb OSINT"}</button>
                  <button className="btn btn-sm" onClick={runDark} disabled={!wl.length || busy === "dark"}>{busy === "dark" ? "…" : "Run DarkGuard (darkweb)"}</button>
                </div>
              </div>
            </div>
          </div>

          <div className="grid g2" style={{ marginTop: 16, alignItems: "start" }}>
            {osint && (
              <div className="panel ticked">
                <div className="panel-head"><span>Overweb OSINT</span><span className="tag">{osint.live ? "live passive" : osint.status || "unavailable"}</span></div>
                <div className="panel-pad">
                  {osint.results.map((r, i) => (
                    <div key={i} style={{ padding: "8px 0", borderBottom: "1px solid var(--line)" }}>
                      <div className="mono-label" style={{ color: "var(--acid)" }}>{r.keyword}</div>
                      {r.findings.map((f, j) => <div key={j} className="snip" style={{ marginTop: 3 }}>▸ <b style={{ color: "var(--ink)" }}>{f.tool}</b> — {f.detail}{f.source_url && <> · <a href={f.source_url} target="_blank" rel="noreferrer" style={{ color: "var(--info)" }}>source</a></>}<span className="muted"> · {f.evidence_type} · {f.confidence} · {f.verification_status}</span></div>)}
                      {(r.errors || []).map((e, j) => <div className="snip" style={{ color: "var(--warn)" }} key={`e${j}`}>△ {e}</div>)}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {dark && (
              <div className="panel ticked">
                <div className="panel-head"><span>Darkweb · DarkGuard</span><span className="tag">{dark.live ? `live · ${dark.status}` : dark.status || "unavailable"}</span></div>
                <div className="panel-pad">
                  <div className="row center" style={{ gap: 12 }}>
                    <div className="display" style={{ fontSize: "1.8rem", color: "var(--info)" }}>{dark.exposure_score ?? "—"}</div>
                    <div className="snip">exposure · sources: {(dark.sources || []).join(", ") || "none returned"}</div>
                  </div>
                  {(dark.personas || []).map((p, i) => (
                    <div key={i} className="snip" style={{ marginTop: 8, paddingTop: 8, borderTop: "1px dashed var(--line)" }}>
                      <b style={{ color: "var(--ink)" }}>{p.keyword}</b> — {p.note} ({p.markets.join(", ")})
                    </div>
                  ))}
                  {(dark.results || []).slice(0, 20).map((r, i) => (
                    <div key={`r${i}`} className="snip" style={{ marginTop: 8, paddingTop: 8, borderTop: "1px dashed var(--line)" }}>
                      <span className={`sev sev-${r.severity || "info"}`}>{r.severity || "info"}</span> <b>{r.title || r.category}</b> · {r.source}
                      {r.url && <> · <a href={r.url} target="_blank" rel="noreferrer" style={{ color: "var(--info)" }}>evidence</a></>}
                    </div>
                  ))}
                  {dark.error && <div className="snip" style={{ color: "var(--warn)", marginTop: 8 }}>△ {dark.error}</div>}
                  {(!dark.personas || dark.personas.length === 0) && <div className="snip" style={{ marginTop: 8 }}>No evidence-backed persona match returned. No identity is inferred from a keyword alone.</div>}
                </div>
              </div>
            )}
          </div>
        </>
      )}
      {fp && !fp.ok && <div className="empty" style={{ marginTop: 16 }}>{fp.error}</div>}
    </div>
  );
}
