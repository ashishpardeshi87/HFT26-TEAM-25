import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { clearSessionCredentials, getJSON, postJSON } from "../../lib/api.js";
import { useDialog, useToast } from "../../lib/ui.jsx";
import { Doughnut } from "react-chartjs-2";
import { Chart, ArcElement, Tooltip, Legend } from "chart.js";
import Terminal from "../../components/Terminal.jsx";

Chart.register(ArcElement, Tooltip, Legend);

const SEVC = { critical: "#ff453a", high: "#ffb020", medium: "#4cc9f0", low: "#3ddc97" };
const FINAL_REPORT_KEY = "sentinel.apex.final-report.v1";
const CLASSIFICATIONS = [
  {
    id: "self_drift",
    label: "Self drift",
    detail: "Agent deviation with no evidence-linked external trigger.",
    color: "var(--warn)",
  },
  {
    id: "external_intervention_suspected",
    label: "External intervention suspected",
    detail: "Evidence links an external trigger to the monitored behavior.",
    color: "var(--alert)",
  },
  {
    id: "unresolved",
    label: "Unresolved",
    detail: "Available evidence does not yet support either attribution.",
    color: "var(--info)",
  },
];
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
const stageLabel = (value) => STAGE_LABELS[value] || humanize(value || "Unknown stage");

function statusColor(status) {
  const value = String(status || "").toLowerCase();
  if (["completed", "complete", "ready", "contained", "ended", "ok", "success"].includes(value)) return "var(--ok)";
  if (["queued", "running", "active", "monitoring", "pending"].includes(value)) return "var(--acid)";
  if (["failed", "error", "blocked", "denied", "exposed"].includes(value)) return "var(--alert)";
  if (["observe_only", "not_required", "not_triggered", "unresolved"].includes(value)) return "var(--warn)";
  return "var(--ink-dim)";
}

function safeURL(value) {
  try {
    const url = new URL(String(value));
    return ["http:", "https:"].includes(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function readStoredFinalReport() {
  try {
    const parsed = JSON.parse(localStorage.getItem(FINAL_REPORT_KEY) || "null");
    return parsed && Object.prototype.hasOwnProperty.call(parsed, "report") ? parsed : null;
  } catch {
    return null;
  }
}

export function eventLine(event) {
  const time = (event.ts || "").slice(11, 19);
  const destination = event.destination?.provider && event.destination.provider !== "unknown"
    ? event.destination.provider : (event.destination?.host || event.tool || event.event_type);
  const findings = event.findings?.length ? ` ⚠ ${event.findings.length} finding(s)` : "";
  const behavior = event.behavior?.length ? ` · ${event.behavior.map((item) => item.type).join(",")}` : "";
  return `[${time}] ${event.source} ${event.process?.name || ""} → ${destination}${findings}${behavior}`;
}

function Metric({ label, value, color = "var(--acid)", sub }) {
  return (
    <div className="panel panel-pad ticked">
      <div className="mono-label">{label}</div>
      <div className="display brk" style={{ fontSize: "2.4rem", marginTop: 6, color }}>{value}</div>
      {sub && <div className="snip" style={{ marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function StageRows({ stages }) {
  if (!stages.length) return <div className="empty" style={{ padding: "14px 0" }}>No response stages were returned.</div>;
  return (
    <div style={{ display: "grid", gap: 8, marginTop: 10 }}>
      {stages.map((stage, index) => {
        const color = statusColor(stage?.status);
        return (
          <div key={`${stage?.id || "stage"}-${index}`} style={{ display: "grid", gridTemplateColumns: "minmax(110px,.45fr) minmax(100px,.35fr) 1.5fr", gap: 10, padding: "9px 10px", border: "1px solid var(--line)", alignItems: "start" }}>
            <b className="snip" style={{ color: "var(--ink)", marginTop: 0 }}>{stageLabel(stage?.id)}</b>
            <span className="pill" style={{ width: "fit-content", color, borderColor: color }}>{humanize(stage?.status || "not returned")}</span>
            <span className="snip" style={{ marginTop: 0, color: "var(--ink-dim)" }}>{stage?.detail == null ? "Detail not returned." : String(stage.detail)}</span>
          </div>
        );
      })}
    </div>
  );
}

function ResponsePlan({ plan, index }) {
  const classification = CLASSIFICATIONS.find((item) => item.id === plan?.cause_class);
  const stages = asArray(plan?.stages || plan?.response_stages);
  const color = classification?.color || "var(--ink-dim)";
  return (
    <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
      <div className="row between center" style={{ gap: 12, flexWrap: "wrap" }}>
        <div>
          <div className="row wrap center" style={{ gap: 7 }}>
            <span className="pill" style={{ color, borderColor: color }}>{classification?.label || humanize(plan?.cause_class || "classification not returned")}</span>
            <span className="snip" style={{ marginTop: 0 }}>Incident {plan?.incident_id || index + 1}</span>
          </div>
          {plan?.cause_evidence && <div className="snip" style={{ marginTop: 6 }}>{plan.cause_evidence}</div>}
        </div>
        <span className="pill" style={{ color: plan?.quarantined ? "var(--alert)" : "var(--ok)", borderColor: plan?.quarantined ? "var(--alert)" : "var(--ok)" }}>
          {plan?.quarantined ? "isolated" : "tracking"}
        </span>
      </div>
      <div className="row wrap" style={{ gap: 8, marginTop: 9 }}>
        <span className="chip">Next view: <b style={{ color: "var(--ink)" }}>{plan?.next_view || "not returned"}</b></span>
        <span className="chip">Next action: <b style={{ color: "var(--ink)" }}>{humanize(plan?.next_action || "not returned")}</b></span>
        <span className="chip">Guardian: <b style={{ color: "var(--ink)" }}>{humanize(plan?.guardian_decision || "not returned")}</b></span>
      </div>
      <StageRows stages={stages} />
    </div>
  );
}

function ReportValue({ value, field = "", depth = 0 }) {
  if (value == null || value === "") return <span className="snip" style={{ marginTop: 0 }}>—</span>;
  if (typeof value === "boolean") return <span className="pill">{value ? "yes" : "no"}</span>;
  if (typeof value === "number") return <b className="display" style={{ fontSize: "1rem" }}>{value}</b>;
  if (typeof value === "string") {
    const href = safeURL(value);
    if (href) return <a className="snip brk" href={href} target="_blank" rel="noreferrer" style={{ color: "var(--info)", marginTop: 0 }}>{value}</a>;
    if (["status", "severity", "classification", "cause_class"].includes(field)) {
      const color = statusColor(value);
      return <span className="pill" style={{ color, borderColor: color }}>{humanize(value)}</span>;
    }
    return <span className="snip brk" style={{ color: "var(--ink)", marginTop: 0, whiteSpace: "pre-wrap" }}>{value}</span>;
  }
  if (Array.isArray(value)) {
    if (!value.length) return <span className="snip" style={{ marginTop: 0 }}>None returned.</span>;
    if (["stages", "response_stages"].includes(field)) return <StageRows stages={value} />;
    if (value.every((item) => item == null || ["string", "number", "boolean"].includes(typeof item))) {
      return <div className="row wrap" style={{ gap: 6 }}>{value.map((item, index) => <span className="chip brk" key={`${item}-${index}`}>{String(item)}</span>)}</div>;
    }
    return (
      <div style={{ display: "grid", gap: 8 }}>
        {value.map((item, index) => (
          <div key={index} style={{ border: "1px solid var(--line)", padding: 10, background: "var(--surface-2)" }}>
            <ReportValue value={item} field={`${field}_${index + 1}`} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }
  if (isObject(value)) {
    if (depth > 4) return <pre className="terminal" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(value, null, 2)}</pre>;
    const entries = Object.entries(value);
    if (!entries.length) return <span className="snip" style={{ marginTop: 0 }}>No values returned.</span>;
    return (
      <div style={{ display: "grid", gap: 8 }}>
        {entries.map(([key, item]) => (
          <div key={key} style={{ display: "grid", gridTemplateColumns: depth < 2 ? "minmax(130px,.4fr) 1.6fr" : "1fr", gap: 7, paddingBottom: 7, borderBottom: "1px solid var(--line)" }}>
            <span className="mono-label">{humanize(key)}</span>
            <ReportValue value={item} field={key} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }
  return <span className="snip">{String(value)}</span>;
}

function CumulativeReport({ record }) {
  if (!record) return null;
  const report = record.report;
  const entries = isObject(report) ? Object.entries(report) : [["report", report]];
  return (
    <div className="panel ticked" style={{ marginTop: 18, borderColor: record.final ? "var(--ok)" : "var(--acid)" }}>
      <div className="panel-head">
        <span>// {record.final ? "Final cumulative report" : "Cumulative session report"}</span>
        <span className="tag">{record.session_id || report?.session_id || "session not returned"}</span>
      </div>
      <div className="panel-pad">
        <div className="row wrap center" style={{ gap: 8, marginBottom: 14 }}>
          <span className="pill" style={{ color: record.final ? "var(--ok)" : "var(--acid)", borderColor: record.final ? "var(--ok)" : "var(--acid)" }}>{record.final ? "session ended" : "live snapshot"}</span>
          {record.session?.status && <span className="pill">Session {humanize(record.session.status)}</span>}
          {record.received_at && <span className="snip" style={{ marginTop: 0 }}>Received {new Date(record.received_at).toLocaleString()}</span>}
        </div>
        {!entries.length && <div className="empty">The backend returned an empty report.</div>}
        <div style={{ display: "grid", gap: 12 }}>
          {entries.map(([key, value]) => (
            <section key={key} style={{ padding: 12, border: "1px solid var(--line-hard)", background: "var(--bg)" }}>
              <div className="mono-label" style={{ marginBottom: 9, color: "var(--acid)" }}>{humanize(key)}</div>
              <ReportValue value={value} field={key} />
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Overview() {
  const feed = useOutletContext();
  const toast = useToast();
  const { confirm } = useDialog();
  const [telemetry, setTelemetry] = useState(null);
  const [integrity, setIntegrity] = useState(null);
  const [sessionInfo, setSessionInfo] = useState(null);
  const [dataError, setDataError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState("");
  const [reportRecord, setReportRecord] = useState(readStoredFinalReport);
  const [externalExposure, setExternalExposure] = useState(null);
  const [wordlistError, setWordlistError] = useState("");

  const sessionId = feed.session?.session_id || "";
  const newestEvent = feed.events?.[0]?.id || feed.events?.[0]?.ts || "";

  useEffect(() => {
    let active = true;
    const load = async () => {
      const requests = [
        ["telemetry", getJSON("/api/telemetry")],
        ["evidence integrity", getJSON("/api/evidence/integrity")],
      ];
      if (sessionId) requests.push(["session", getJSON(`/api/sessions/${sessionId}`)]);
      const settled = await Promise.allSettled(requests.map(([, request]) => request));
      if (!active) return;

      const failures = [];
      settled.forEach((result, index) => {
        const label = requests[index][0];
        if (result.status === "rejected") {
          failures.push(`${label}: ${result.reason?.message || "request failed"}`);
          return;
        }
        if (label === "telemetry") setTelemetry(result.value);
        if (label === "evidence integrity") setIntegrity(result.value);
        if (label === "session") setSessionInfo(result.value?.session || null);
      });
      if (!sessionId) setSessionInfo(null);
      setDataError(failures.join(" · "));
    };
    load();
    return () => { active = false; };
  }, [sessionId, newestEvent]);

  async function loadReport() {
    if (!sessionId) {
      setActionError("No active session is available. Complete Setup before requesting a live report.");
      return;
    }
    setBusy("report");
    setActionError("");
    try {
      const report = await getJSON(`/api/sessions/${sessionId}/report`);
      setReportRecord({ report, session_id: sessionId, final: false, received_at: new Date().toISOString() });
      toast("Cumulative session report loaded", "ok");
    } catch (error) {
      setActionError(`Report unavailable: ${error.message}`);
    } finally {
      setBusy("");
    }
  }

  async function endSession() {
    if (!sessionId) {
      setActionError("No active session is available to end.");
      return;
    }
    const accepted = await confirm({
      title: "End this monitoring session?",
      message: "SENTINEL will stop this session and return its final cumulative report. This action cannot be undone from the Command Center.",
      okText: "End session",
      cancelText: "Keep monitoring",
      danger: true,
    });
    if (!accepted) return;

    setBusy("end");
    setActionError("");
    try {
      const result = await postJSON(`/api/sessions/${sessionId}/end`, {});
      if (result?.ok !== true || !Object.prototype.hasOwnProperty.call(result, "report")) {
        throw new Error("The backend did not confirm the session end or return its final report.");
      }
      const record = {
        report: result.report,
        session: result.session || null,
        session_id: result.session?.session_id || sessionId,
        final: true,
        received_at: new Date().toISOString(),
      };
      let persistenceError = "";
      try {
        localStorage.setItem(FINAL_REPORT_KEY, JSON.stringify(record));
      } catch (error) {
        persistenceError = `The final report is visible now, but this browser could not persist it for refresh: ${error.message}`;
      }
      setReportRecord(record);
      setSessionInfo(result.session || null);
      clearSessionCredentials();
      setActionError(persistenceError);
      toast("Session ended. Final cumulative report retained on this page.", "ok");
    } catch (error) {
      setActionError(`Session was not ended: ${error.message}`);
    } finally {
      setBusy("");
    }
  }

  const stats = feed.stats || {};
  const levels = stats.by_level || { critical: 0, high: 0, medium: 0, low: 0 };
  const riskColor = stats.risk_score >= 75 ? SEVC.critical : stats.risk_score >= 50 ? SEVC.high : stats.risk_score >= 25 ? SEVC.medium : SEVC.low;
  const plans = asArray(feed.orchestratorStatus?.plans);
  const externalPlan = plans.find((plan) => plan?.cause_class === "external_intervention_suspected") || null;
  const classificationCounts = Object.fromEntries(CLASSIFICATIONS.map((item) => [item.id, plans.filter((plan) => plan?.cause_class === item.id).length]));
  const unknownClassifications = plans.filter((plan) => !CLASSIFICATIONS.some((item) => item.id === plan?.cause_class));

  useEffect(() => {
    let active = true;
    if (!sessionId) {
      setExternalExposure(null);
      setWordlistError("");
      return () => { active = false; };
    }
    getJSON("/api/exposure/overview")
      .then((value) => {
        if (!active) return;
        setExternalExposure(value);
        setWordlistError("");
      })
      .catch((error) => {
        if (!active) return;
        setWordlistError(error.message || "External investigation wordlist is unavailable.");
      });
    return () => { active = false; };
  }, [sessionId, externalPlan?.incident_id, externalPlan?.next_view, feed.orchestratorStatus?.active_jobs, newestEvent]);

  const externalWordlist = asArray(externalExposure?.wordlist || externalExposure?.investigation?.wordlist);
  const hasExternalInvestigation = Boolean(externalPlan || externalExposure?.eligible);

  const donut = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [{
      data: [levels.critical || 0, levels.high || 0, levels.medium || 0, levels.low || 0],
      backgroundColor: [SEVC.critical, SEVC.high, SEVC.medium, SEVC.low],
      borderColor: "#0f0f11", borderWidth: 2,
    }],
  };
  const providers = Object.entries(isObject(stats.providers) ? stats.providers : {});
  const logs = asArray(feed.events).slice(0, 40).map(eventLine).reverse();

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Command Center</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Overview</h1>
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          <button className="btn btn-primary btn-sm" onClick={loadReport} disabled={!sessionId || Boolean(busy)}>{busy === "report" ? "Loading report…" : "Report"}</button>
          <button className="btn btn-danger btn-sm" onClick={endSession} disabled={!sessionId || Boolean(busy)}>{busy === "end" ? "Ending session…" : "End Session"}</button>
        </div>
      </div>

      {!sessionId && (
        <div className="banner" style={{ borderColor: "var(--warn)", color: "var(--warn)" }}>
          <span>No active session credentials are stored in this browser. Live Command Center APIs remain locked; page shells and any persisted final report stay available for UI review.</span>
        </div>
      )}
      {dataError && <div className="banner" style={{ borderColor: "var(--warn)", color: "var(--warn)" }}><span>Some Command Center data is unavailable: {dataError}</span></div>}
      {feed.orchestratorError && <div className="banner" style={{ borderColor: "var(--alert)", color: "var(--alert)" }}><span>Orchestrator status unavailable: {feed.orchestratorError}</span></div>}
      {actionError && <div className="banner" style={{ borderColor: "var(--alert)", color: "var(--alert)" }}><span>{actionError}</span></div>}

      <div className="panel ticked" style={{ marginTop: 18 }}>
        <div className="panel-head"><span>// Active security boundary</span><span className="tag">policy {sessionInfo?.policy?.version || "—"}</span></div>
        <div className="panel-pad grid g4">
          <Metric label="Monitoring target" value={sessionInfo?.target_host || "—"} color="var(--ink)" sub={sessionInfo?.objective || ""} />
          <Metric label="Registered agents" value={sessionInfo?.agents?.length ?? 0} sub={`${sessionInfo?.coverage_mode || "—"} mode`} />
          <Metric label="Telemetry" value={feed.connected ? "ACTIVE" : (telemetry?.monitoring_state || "OFFLINE").toUpperCase()} color={feed.connected ? "var(--ok)" : "var(--alert)"} sub={telemetry?.note} />
          <Metric label="Evidence chain" value={integrity?.ok ? "VERIFIED" : "CHECK"} color={integrity?.ok ? "var(--ok)" : "var(--alert)"} sub={`${integrity?.checked ?? 0} records · ${integrity?.remote_anchor_configured ? "off-box anchored" : "local chain"}`} />
        </div>
      </div>

      <div className="panel ticked" style={{ marginTop: 18, borderColor: hasExternalInvestigation ? "var(--info)" : "var(--line-hard)" }}>
        <div className="panel-head"><span>// Investigation wordlist</span><span className="tag">{externalWordlist.length} term(s)</span></div>
        <div className="panel-pad">
          {hasExternalInvestigation ? (
            <>
              <p className="snip">Evidence-derived terms passed automatically to passive Overweb and DarkGuard investigation. Use the embedded APEX Agent to add or remove terms, or edit them in Exposure Overview.</p>
              <div className="row wrap" style={{ gap: 7, marginTop: 10 }}>
                {externalWordlist.map((term, index) => <span className="chip brk" key={`${term}-${index}`}>{String(term)}</span>)}
                {!externalWordlist.length && <span className="snip" style={{ color: "var(--warn)" }}>{externalExposure?.status === "running" || externalExposure?.status === "queued" ? "Wordlist extraction is still running." : "No searchable indicators were extracted from the recorded evidence."}</span>}
              </div>
              <div className="row wrap" style={{ gap: 8, marginTop: 12 }}>
                <Link to="/app/exposure" className="btn btn-sm">Open Exposure Overview</Link>
                {externalExposure?.incident_id && <span className="snip">Incident {externalExposure.incident_id}</span>}
              </div>
            </>
          ) : (
            <div className="empty">Waiting for evidence-linked external intervention. Self-drift and unresolved incidents do not create an attacker-search wordlist.</div>
          )}
          {wordlistError && <div className="snip" style={{ color: "var(--alert)", marginTop: 8 }}>✕ {wordlistError}</div>}
        </div>
      </div>

      <div className="grid g3" style={{ marginTop: 18 }}>
        {CLASSIFICATIONS.map((item) => (
          <div className="panel panel-pad ticked" key={item.id} style={{ borderColor: classificationCounts[item.id] ? item.color : "var(--line-hard)" }}>
            <div className="mono-label" style={{ color: item.color }}>{item.id}</div>
            <div className="display" style={{ fontSize: "1.15rem", marginTop: 8 }}>{item.label}</div>
            <div className="snip" style={{ marginTop: 6 }}>{item.detail}</div>
            <div className="display" style={{ color: item.color, fontSize: "1.4rem", marginTop: 10 }}>{classificationCounts[item.id] || 0}</div>
          </div>
        ))}
      </div>
      {unknownClassifications.length > 0 && (
        <div className="banner" style={{ marginTop: 14, borderColor: "var(--warn)", color: "var(--warn)" }}>
          <span>{unknownClassifications.length} response plan(s) used an unrecognized cause_class. They remain visible below without being remapped.</span>
        </div>
      )}

      <div className="panel ticked" style={{ marginTop: 18, borderLeft: "3px solid var(--acid)" }}>
        <div className="panel-head"><span>// SENTINEL AI Orchestrator</span><span className="tag">{feed.orchestratorLoading && !feed.orchestratorStatus ? "loading" : `${feed.orchestratorStatus?.active_jobs ?? 0} active job(s)`}</span></div>
        <div className="panel-pad">
          <div className="row wrap" style={{ gap: 6 }}>{asArray(feed.orchestratorStatus?.controls).map((control) => <span className="chip" key={control}>{control}</span>)}</div>
          {plans.map((plan, index) => <ResponsePlan key={plan?.incident_id || `plan-${index}`} plan={plan} index={index} />)}
          {!plans.length && <div className="empty" style={{ padding: "18px 0 2px" }}>{sessionId ? "No response plans have been returned for this session." : "Complete Setup to load authenticated response plans."}</div>}
        </div>
      </div>

      <CumulativeReport record={reportRecord} />

      <div className="grid g4" style={{ marginTop: 18 }}>
        <Metric label="Org risk posture" value={stats.risk_score ?? 0} color={riskColor} sub={`${levels.critical || 0} critical incidents`} />
        <Metric label="Incidents" value={stats.incidents ?? 0} />
        <Metric label="Unapproved AI" value={stats.unapproved ?? 0} color="var(--alert)" sub="shadow destinations" />
        <Metric label="Data leaks" value={stats.data_leaks ?? 0} color="var(--warn)" />
      </div>

      <div className="grid g2" style={{ marginTop: 18, gridTemplateColumns: "1fr 1.4fr" }}>
        <div className="panel ticked">
          <div className="panel-head"><span>Severity mix</span><span className="tag">incidents</span></div>
          <div className="panel-pad" style={{ display: "grid", placeItems: "center", minHeight: 240 }}>
            {(stats.incidents ?? 0) > 0
              ? <div style={{ width: 220, height: 220 }}><Doughnut data={donut} options={{ plugins: { legend: { labels: { color: "#8d8d85", font: { family: "JetBrains Mono" } } } }, cutout: "62%" }} /></div>
              : <div className="empty">No incidents yet. Waiting for authenticated sensor or Guardian-gateway telemetry.</div>}
          </div>
        </div>

        <div className="panel ticked">
          <div className="panel-head"><span>Live telemetry</span><span className="tag">{asArray(feed.events).length} events</span></div>
          <div className="panel-pad"><Terminal logs={logs} /></div>
        </div>
      </div>

      <div className="grid g2" style={{ marginTop: 18 }}>
        <div className="panel ticked">
          <div className="panel-head"><span>AI destinations (shadow)</span></div>
          <div className="panel-pad">
            {providers.length === 0 && <div className="empty">No AI destinations observed yet.</div>}
            {providers.map(([provider, count]) => (
              <div key={provider} className="row between center" style={{ padding: "8px 0", borderBottom: "1px solid var(--line)" }}>
                <span>{provider}</span>
                <span className="row center" style={{ gap: 10 }}><span className="sev sev-high">unapproved</span><b className="display" style={{ fontSize: "1.1rem" }}>{count}</b></span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel ticked">
          <div className="panel-head"><span>Recent incidents</span><Link to="/app/incidents" className="tag" style={{ color: "var(--acid)" }}>view all →</Link></div>
          <div className="panel-pad">
            {asArray(feed.incidents).length === 0 && <div className="empty">No incidents yet.</div>}
            {asArray(feed.incidents).slice(0, 6).map((incident) => (
              <Link key={incident.incident_id} to="/app/incidents" className="row between center" style={{ padding: "9px 0", borderBottom: "1px solid var(--line)", gap: 10 }}>
                <span className="snip" style={{ color: "var(--ink)", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{incident.title}</span>
                <span className={`sev sev-${incident.level}`}>{incident.status}</span>
                <b className="display">{incident.score}</b>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
