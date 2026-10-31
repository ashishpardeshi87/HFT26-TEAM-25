import { useEffect, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { getJSON, postJSON } from "../../lib/api.js";
import { useToast } from "../../lib/ui.jsx";

const POLL_MS = 2000;
const STAGE_LABELS = {
  observe: "Observe",
  detect: "Detect",
  enforce: "Stop/Block",
  reground: "Re-ground",
  isolate: "Isolate",
  forensics: "Forensics",
  investigate: "Investigate",
  report: "Report",
};

const asArray = (value) => (Array.isArray(value) ? value : []);
const isObject = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const humanize = (value) => String(value ?? "").replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const firstArray = (...values) => values.find((value) => Array.isArray(value)) || [];
const firstObject = (...values) => values.find((value) => isObject(value)) || null;

function safeURL(value) {
  try {
    const url = new URL(String(value));
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function statusColor(status) {
  const value = String(status || "").toLowerCase();
  if (["completed", "complete", "ready", "live", "reachable", "ok", "success"].includes(value)) return "var(--ok)";
  if (["queued", "running", "pending", "active", "checking"].includes(value)) return "var(--acid)";
  if (["failed", "error", "unreachable", "blocked", "denied"].includes(value)) return "var(--alert)";
  if (["unavailable", "degraded", "not_required", "not_triggered", "observe_only"].includes(value)) return "var(--warn)";
  return "var(--ink-dim)";
}

function overviewParts(overview) {
  const incident = firstObject(overview?.triggering_incident, overview?.incident) || {};
  const investigation = firstObject(overview?.investigation, overview?.investigation_job, overview?.job) || {};
  const plan = firstObject(overview?.response_plan, overview?.plan, incident?.response_plan) || {};
  const stages = firstArray(overview?.response_stages, overview?.stages, plan?.stages, incident?.response_stages, incident?.stages);
  const wordlist = firstArray(overview?.wordlist, investigation?.wordlist);
  const overweb = firstObject(overview?.overweb, investigation?.overweb);
  const darkguard = firstObject(overview?.darkguard, overview?.darkweb, investigation?.darkguard, investigation?.darkweb);
  const workingLinks = firstArray(overview?.working_links, investigation?.working_links, darkguard?.working_links);
  const classification = overview?.classification || overview?.cause_class || incident?.classification || incident?.cause_class || plan?.cause_class || "";
  const incidentId = incident?.incident_id || incident?.id || overview?.incident_id || plan?.incident_id || investigation?.incident_id || "";
  const investigationStatus = overview?.investigation_status || investigation?.status || "";
  return { incident, investigation, plan, stages, wordlist, overweb, darkguard, workingLinks, classification, incidentId, investigationStatus };
}

function shouldPoll(overview) {
  if (!overview) return false;
  const parts = overviewParts(overview);
  const statuses = [
    overview.investigation_status,
    parts.investigation?.status,
    parts.plan?.investigation_status,
    ...parts.stages.filter((stage) => stage?.id === "investigate" || stage?.id === "forensics").map((stage) => stage?.status),
  ];
  return statuses.some((status) => ["queued", "running"].includes(String(status || "").toLowerCase()));
}

function Stat({ label, value, sub, color = "var(--ink)" }) {
  return (
    <div className="panel panel-pad ticked">
      <div className="mono-label">{label}</div>
      <div className="display brk" style={{ marginTop: 10, fontSize: "1.35rem", color }}>{value}</div>
      {sub && <div className="snip" style={{ marginTop: 8 }}>{sub}</div>}
    </div>
  );
}

function StageList({ stages }) {
  if (!stages.length) return <div className="empty">No response stages were returned for this exposure.</div>;
  return (
    <div style={{ display: "grid", gap: 8 }}>
      {stages.map((stage, index) => {
        const color = statusColor(stage?.status);
        return (
          <div key={`${stage?.id || "stage"}-${index}`} style={{ display: "grid", gridTemplateColumns: "minmax(110px,.45fr) minmax(100px,.35fr) 1.5fr", gap: 10, padding: "10px", border: "1px solid var(--line)", alignItems: "start" }}>
            <b className="snip" style={{ marginTop: 0, color: "var(--ink)" }}>{STAGE_LABELS[stage?.id] || humanize(stage?.id || "unknown stage")}</b>
            <span className="pill" style={{ width: "fit-content", color, borderColor: color }}>{humanize(stage?.status || "not returned")}</span>
            <span className="snip" style={{ marginTop: 0 }}>{stage?.detail == null ? "Detail not returned." : String(stage.detail)}</span>
          </div>
        );
      })}
    </div>
  );
}

function SummaryValue({ value }) {
  if (value == null || value === "") return null;
  if (Array.isArray(value)) return <span>{value.map(String).join(", ")}</span>;
  if (isObject(value)) return <span>{Object.entries(value).map(([key, item]) => `${humanize(key)}: ${Array.isArray(item) ? item.join(", ") : String(item)}`).join(" · ")}</span>;
  return <span>{String(value)}</span>;
}

function OverwebPanel({ overweb }) {
  const results = asArray(overweb?.results);
  const findingCount = results.reduce((count, result) => count + asArray(result?.findings).length, 0);
  return (
    <div className="panel ticked">
      <div className="panel-head"><span>Overweb result summaries</span><span className="tag">{overweb?.status || (overweb?.live === true ? "live passive" : "no status")}</span></div>
      <div className="panel-pad">
        {!overweb && <div className="empty">The backend has not returned Overweb results.</div>}
        {overweb && (
          <>
            <div className="row wrap" style={{ gap: 7, marginBottom: 10 }}>
              <span className="chip">{results.length} result group(s)</span>
              <span className="chip">{findingCount} finding(s)</span>
              {overweb.live != null && <span className="chip">Live: {overweb.live ? "yes" : "no"}</span>}
            </div>
            {overweb.summary != null && <div className="snip" style={{ color: "var(--ink)", padding: "8px 0" }}><SummaryValue value={overweb.summary} /></div>}
            {results.map((result, index) => {
              const findings = asArray(result?.findings);
              const errors = asArray(result?.errors);
              return (
                <div key={`${result?.keyword || result?.query || "result"}-${index}`} style={{ padding: "10px 0", borderTop: "1px solid var(--line)" }}>
                  <div className="row between center" style={{ gap: 8, flexWrap: "wrap" }}>
                    <b className="snip brk" style={{ color: "var(--ink)", marginTop: 0 }}>{result?.keyword || result?.query || result?.term || result?.title || `Result ${index + 1}`}</b>
                    <span className="pill">{humanize(result?.kind || result?.status || `${findings.length} findings`)}</span>
                  </div>
                  {result?.summary && <div className="snip"><SummaryValue value={result.summary} /></div>}
                  {findings.map((finding, findingIndex) => {
                    const href = safeURL(finding?.source_url);
                    return (
                      <div className="snip" key={findingIndex} style={{ marginTop: 6 }}>
                        ▸ <b style={{ color: "var(--ink)" }}>{finding?.tool || finding?.source || "Evidence"}</b>{finding?.detail ? ` — ${finding.detail}` : ""}
                        {href && <> · <a href={href} target="_blank" rel="noreferrer" style={{ color: "var(--info)" }}>source</a></>}
                        {(finding?.confidence || finding?.verification_status) && <span className="muted"> · {[finding.confidence, finding.verification_status].filter(Boolean).join(" · ")}</span>}
                      </div>
                    );
                  })}
                  {!findings.length && (result?.detail || result?.snippet) && <div className="snip">{result.detail || result.snippet}</div>}
                  {errors.map((error, errorIndex) => <div className="snip" style={{ color: "var(--warn)" }} key={errorIndex}>△ {String(error)}</div>)}
                </div>
              );
            })}
            {!results.length && overweb.summary == null && <div className="empty">Overweb returned no result summaries.</div>}
            {overweb.error && <div className="snip" style={{ color: "var(--alert)", marginTop: 8 }}>✕ {overweb.error}</div>}
          </>
        )}
      </div>
    </div>
  );
}

function DarkGuardPanel({ darkguard }) {
  const results = asArray(darkguard?.results);
  const personas = asArray(darkguard?.personas);
  const color = statusColor(darkguard?.status || (darkguard?.live ? "live" : ""));
  return (
    <div className="panel ticked">
      <div className="panel-head"><span>DarkGuard status &amp; results</span><span className="tag" style={{ color }}>{darkguard?.status || (darkguard?.live ? "live" : "not returned")}</span></div>
      <div className="panel-pad">
        {!darkguard && <div className="empty">The backend has not returned a DarkGuard result.</div>}
        {darkguard && (
          <>
            <div className="row wrap center" style={{ gap: 9 }}>
              <span className="pill" style={{ color, borderColor: color }}>{humanize(darkguard.status || (darkguard.live ? "live" : "status not returned"))}</span>
              {darkguard.exposure_score != null && <span className="chip">Exposure score: <b style={{ color: "var(--ink)" }}>{darkguard.exposure_score}</b></span>}
              {Array.isArray(darkguard.sources) && <span className="chip">Sources: {darkguard.sources.join(", ") || "none"}</span>}
            </div>

            <div className="mono-label" style={{ marginTop: 16 }}>Personas returned by DarkGuard</div>
            {personas.map((persona, index) => (
              <div key={`${persona?.keyword || persona?.handle || "persona"}-${index}`} className="snip" style={{ padding: "9px 0", borderBottom: "1px solid var(--line)" }}>
                <b style={{ color: "var(--ink)" }}>{persona?.keyword || persona?.handle || persona?.name || `Persona ${index + 1}`}</b>
                {persona?.note && <> — {persona.note}</>}
                {Array.isArray(persona?.markets) && persona.markets.length > 0 && <span className="muted"> · markets: {persona.markets.join(", ")}</span>}
                {persona?.confidence != null && <span className="muted"> · confidence: {String(persona.confidence)}</span>}
              </div>
            ))}
            {!personas.length && <div className="snip" style={{ marginTop: 8 }}>No evidence-backed personas were returned.</div>}

            <div className="mono-label" style={{ marginTop: 16 }}>Results</div>
            {results.map((result, index) => (
              <div key={`${result?.id || result?.title || "result"}-${index}`} className="snip" style={{ padding: "9px 0", borderBottom: "1px solid var(--line)" }}>
                {result?.severity && <span className={`sev sev-${result.severity}`} style={{ marginRight: 7 }}>{result.severity}</span>}
                <b style={{ color: "var(--ink)" }}>{result?.title || result?.category || result?.source || `Result ${index + 1}`}</b>
                {result?.source && result.source !== result.title && <> · {result.source}</>}
                {result?.snippet && <div className="snip">{result.snippet}</div>}
                {result?.confidence != null && <span className="muted"> · confidence: {String(result.confidence)}</span>}
              </div>
            ))}
            {!results.length && <div className="snip" style={{ marginTop: 8 }}>DarkGuard returned no results.</div>}
            {darkguard.error && <div className="snip" style={{ color: "var(--alert)", marginTop: 10 }}>✕ {darkguard.error}</div>}
          </>
        )}
      </div>
    </div>
  );
}

function WorkingLinks({ links }) {
  return (
    <div className="panel ticked" style={{ marginTop: 16, borderColor: "var(--info)" }}>
      <div className="panel-head"><span>// Working Links · backend-verified results only</span><span className="tag">{links.length} returned</span></div>
      <div className="panel-pad">
        {!links.length && <div className="empty">The exposure endpoint returned no working_links. No links are inferred from other results.</div>}
        <div style={{ display: "grid", gap: 12 }}>
          {links.map((link, index) => {
            const href = safeURL(link?.url);
            const availability = [
              link?.live != null ? `Live: ${link.live ? "yes" : "no"}` : "",
              link?.reachability != null ? `Reachability: ${humanize(link.reachability)}` : "",
              link?.status != null ? `Status: ${humanize(link.status)}` : "",
            ].filter(Boolean);
            const matchedTerms = asArray(link?.matched_terms).length ? asArray(link.matched_terms) : asArray(link?.matched);
            const priceEntries = Object.entries(link || {}).filter(([key, value]) => key.toLowerCase().includes("price") && value != null && value !== "");
            return (
              <article key={`${link?.url || "link"}-${index}`} style={{ padding: 14, border: "1px solid var(--line-hard)", background: "var(--bg)" }}>
                <div className="row between center" style={{ gap: 10, flexWrap: "wrap" }}>
                  {href
                    ? <a href={href} target="_blank" rel="noreferrer" className="snip brk" style={{ color: "var(--info)", marginTop: 0, fontWeight: 700 }}>{link.url}</a>
                    : <span className="snip brk" style={{ color: "var(--ink)", marginTop: 0 }}>{link?.url || "URL not returned"}</span>}
                  <span className="pill">{link?.market || link?.source || "market/source not returned"}</span>
                </div>
                {availability.length > 0 && <div className="row wrap" style={{ gap: 6, marginTop: 9 }}>{availability.map((item) => <span className="chip" key={item}>{item}</span>)}</div>}
                {matchedTerms.length > 0 && (
                  <div className="row wrap center" style={{ gap: 6, marginTop: 9 }}><span className="mono-label">Matched terms</span>{matchedTerms.map((term, termIndex) => <span className="chip brk" key={`${term}-${termIndex}`}>{term}</span>)}</div>
                )}
                {link?.snippet && <p className="snip" style={{ color: "var(--ink)", marginTop: 10, whiteSpace: "pre-wrap" }}>{link.snippet}</p>}
                <div className="row wrap" style={{ gap: 7, marginTop: 10 }}>
                  {link?.severity != null && <span className={`sev sev-${link.severity}`}>{link.severity}</span>}
                  {link?.category != null && <span className="chip">Category: {String(link.category)}</span>}
                  {link?.confidence != null && <span className="chip">Confidence: {String(link.confidence)}</span>}
                  {priceEntries.map(([key, value]) => <span className="chip" key={key}>{humanize(key)}: <SummaryValue value={value} /></span>)}
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function ExposureOverview() {
  const feed = useOutletContext();
  const toast = useToast();
  const [overview, setOverview] = useState(null);
  const [wordlist, setWordlist] = useState([]);
  const [newTerm, setNewTerm] = useState("");
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState("");
  const [error, setError] = useState("");

  const sessionId = feed.session?.session_id || "";
  const token = feed.session?.gateway_token || "";

  useEffect(() => {
    let active = true;
    let timer;
    let pollActive = false;

    if (!sessionId || !token) {
      setOverview(null);
      setWordlist([]);
      setLoading(false);
      setError("");
      return () => {};
    }

    const load = async (initial = false) => {
      if (initial) setLoading(true);
      try {
        const next = await getJSON("/api/exposure/overview");
        if (!active) return;
        setOverview(next);
        setWordlist(overviewParts(next).wordlist);
        setError("");
        pollActive = shouldPoll(next);
      } catch (requestError) {
        if (!active) return;
        setError(requestError.message || "Exposure Overview is unavailable.");
      } finally {
        if (!active) return;
        setLoading(false);
        if (pollActive) timer = window.setTimeout(() => load(false), POLL_MS);
      }
    };

    load(true);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [sessionId, token]);

  const parts = overviewParts(overview);

  async function editWordlist(add, remove) {
    if (!parts.incidentId) {
      setError("The exposure response did not include a triggering incident_id, so the wordlist cannot be edited.");
      return;
    }
    setEditing(add.length ? "add" : String(remove[0] || "remove"));
    setError("");
    try {
      const result = await postJSON("/api/wordlist", { incident_id: parts.incidentId, add, remove });
      if (result?.ok === false) throw new Error(result.error || "The backend rejected the wordlist update.");
      setWordlist(asArray(result?.wordlist));
      toast("Exposure wordlist updated", "ok");
    } catch (requestError) {
      setError(`Wordlist update failed: ${requestError.message}`);
    } finally {
      setEditing("");
    }
  }

  function addTerm(event) {
    event.preventDefault();
    const term = newTerm.trim();
    if (!term || editing) return;
    editWordlist([term], []);
    setNewTerm("");
  }

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Evidence-gated exposure investigation</div>
          <h1 className="display" style={{ fontSize: "1.9rem", marginTop: 6 }}>Exposure Overview</h1>
          <p>Overweb and DarkGuard evidence for an externally triggered incident. This page never creates scans or substitutes sample findings.</p>
        </div>
        {parts.investigationStatus && <span className="pill" style={{ color: statusColor(parts.investigationStatus), borderColor: statusColor(parts.investigationStatus) }}>{humanize(parts.investigationStatus)}</span>}
      </div>

      {!sessionId && (
        <div className="panel ticked" style={{ borderColor: "var(--warn)" }}>
          <div className="panel-head"><span>// Exposure locked</span><span className="tag">no active session</span></div>
          <div className="panel-pad"><div className="empty">Exposure activates only after evidence-linked external intervention. This direct page shell remains available for UI review, but protected exposure data requires an active verified session.</div></div>
        </div>
      )}

      {sessionId && loading && !overview && <div className="panel ticked"><div className="panel-pad"><div className="empty">Loading the evidence-gated exposure overview…</div></div></div>}
      {error && <div className="banner" style={{ borderColor: "var(--alert)", color: "var(--alert)" }}><span>Exposure data unavailable: {error}</span></div>}

      {sessionId && overview && overview.eligible !== true && (
        <div className="panel ticked" style={{ borderColor: "var(--warn)" }}>
          <div className="panel-head"><span>// Exposure not activated</span><span className="tag">eligible: false</span></div>
          <div className="panel-pad">
            <div className="empty">Exposure activates only after evidence-linked external intervention. No exposure findings or links are shown for this session.</div>
            {(overview.reason || overview.detail) && <p className="snip" style={{ textAlign: "center", marginTop: 0 }}>{overview.reason || overview.detail}</p>}
          </div>
        </div>
      )}

      {sessionId && overview?.eligible === true && (
        <>
          <div className="grid g4">
            <Stat label="Eligibility" value="ACTIVE" sub="evidence-linked external intervention" color="var(--ok)" />
            <Stat label="Classification" value={parts.classification ? humanize(parts.classification) : "Not returned"} sub={parts.classification || "classification missing"} color={parts.classification === "external_intervention_suspected" ? "var(--alert)" : "var(--warn)"} />
            <Stat label="Triggering incident" value={parts.incidentId || "Not returned"} sub={parts.incident?.title || parts.incident?.summary || "incident identifier"} color="var(--acid)" />
            <Stat label="Investigation" value={humanize(parts.investigationStatus || "not returned")} sub={parts.investigation?.id || parts.investigation?.job_id || "status from exposure endpoint"} color={statusColor(parts.investigationStatus)} />
          </div>

          <div className="grid g2" style={{ marginTop: 16, alignItems: "start" }}>
            <div className="panel ticked">
              <div className="panel-head"><span>Triggering incident &amp; classification</span><span className="tag">{parts.incidentId || "ID not returned"}</span></div>
              <div className="panel-pad">
                <div className="row wrap" style={{ gap: 7 }}>
                  {parts.classification && <span className="pill" style={{ color: parts.classification === "external_intervention_suspected" ? "var(--alert)" : "var(--warn)", borderColor: parts.classification === "external_intervention_suspected" ? "var(--alert)" : "var(--warn)" }}>{humanize(parts.classification)}</span>}
                  {(parts.incident?.severity || parts.incident?.level) && <span className={`sev sev-${parts.incident.severity || parts.incident.level}`}>{parts.incident.severity || parts.incident.level}</span>}
                  {parts.incident?.status && <span className="pill">{humanize(parts.incident.status)}</span>}
                </div>
                {(parts.incident?.title || parts.incident?.summary) && <h2 className="display" style={{ fontSize: "1.15rem", marginTop: 12 }}>{parts.incident.title || parts.incident.summary}</h2>}
                {(overview.cause_evidence || parts.incident?.cause_evidence || parts.plan?.cause_evidence) && <p className="snip" style={{ color: "var(--ink)", marginTop: 10 }}>{overview.cause_evidence || parts.incident.cause_evidence || parts.plan.cause_evidence}</p>}
                {(parts.incident?.created_at || parts.incident?.updated_at) && <div className="snip" style={{ marginTop: 8 }}>Recorded {parts.incident.created_at || parts.incident.updated_at}</div>}
                {!parts.incidentId && !parts.incident?.title && <div className="empty">The backend marked this response eligible but did not return triggering incident details.</div>}
              </div>
            </div>

            <div className="panel ticked">
              <div className="panel-head"><span>Search wordlist (editable)</span><span className="tag">{wordlist.length}</span></div>
              <div className="panel-pad">
                <div className="row wrap" style={{ gap: 6 }}>
                  {wordlist.map((term, index) => (
                    <span className="chip brk" key={`${term}-${index}`}>{term}
                      <button type="button" aria-label={`Remove ${term}`} disabled={Boolean(editing)} onClick={() => editWordlist([], [term])} style={{ cursor: editing ? "not-allowed" : "pointer", background: "none", border: 0, color: "var(--alert)", marginLeft: 6 }}>×</button>
                    </span>
                  ))}
                  {!wordlist.length && <span className="snip">The backend returned no search terms.</span>}
                </div>
                <form className="row" style={{ gap: 8, marginTop: 12 }} onSubmit={addTerm}>
                  <input className="input" value={newTerm} maxLength={200} onChange={(event) => setNewTerm(event.target.value)} placeholder="Add evidence-linked search term" />
                  <button className="btn btn-sm" type="submit" disabled={!newTerm.trim() || Boolean(editing)}>{editing === "add" ? "Adding…" : "Add"}</button>
                </form>
                {!parts.incidentId && <div className="snip" style={{ color: "var(--warn)", marginTop: 8 }}>Editing is unavailable because incident_id was not returned.</div>}
              </div>
            </div>
          </div>

          <div className="panel ticked" style={{ marginTop: 16 }}>
            <div className="panel-head"><span>Response stages</span><span className="tag">{parts.stages.length} returned</span></div>
            <div className="panel-pad"><StageList stages={parts.stages} /></div>
          </div>

          <div className="grid g2" style={{ marginTop: 16, alignItems: "start" }}>
            <OverwebPanel overweb={parts.overweb} />
            <DarkGuardPanel darkguard={parts.darkguard} />
          </div>

          <WorkingLinks links={parts.workingLinks} />
        </>
      )}
    </div>
  );
}
