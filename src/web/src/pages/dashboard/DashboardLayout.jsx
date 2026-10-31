import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import ShieldMark from "../../components/ShieldMark.jsx";
import NetworkField from "../../components/NetworkField.jsx";
import AnalystDock from "../../components/AnalystDock.jsx";
import { getJSON, useLiveFeed, uploadFile } from "../../lib/api.js";
import { useToast } from "../../lib/ui.jsx";

const ORCHESTRATOR_POLL_MS = 3000;
const EXTERNAL_CLASSIFICATION = "external_intervention_suspected";

function exposesExternalInvestigation(status) {
  if (!status || typeof status !== "object") return false;

  const plans = Array.isArray(status.plans) ? status.plans : [];
  if (plans.some((plan) => plan?.cause_class === EXTERNAL_CLASSIFICATION
    && (plan.next_view === "exposure_overview" || plan.investigation_job_id || plan.investigation_job))) {
    return true;
  }

  if (status.external_investigation_job) return true;
  if (Array.isArray(status.external_investigation_jobs) && status.external_investigation_jobs.length > 0) return true;

  const jobs = [
    ...(Array.isArray(status.investigation_jobs) ? status.investigation_jobs : []),
    ...(Array.isArray(status.jobs) ? status.jobs : []),
  ];
  return jobs.some((job) => job?.cause_class === EXTERNAL_CLASSIFICATION
    || job?.classification === EXTERNAL_CLASSIFICATION
    || job?.incident_classification === EXTERNAL_CLASSIFICATION
    || job?.external === true
    || job?.kind === "external_investigation");
}

export default function DashboardLayout() {
  const feed = useLiveFeed();
  const nav = useNavigate();
  const toast = useToast();
  const fileRef = useRef(null);
  const statusRequest = useRef(0);
  const [orchestratorStatus, setOrchestratorStatus] = useState(null);
  const [orchestratorError, setOrchestratorError] = useState("");
  const [orchestratorLoading, setOrchestratorLoading] = useState(false);

  const refreshOrchestrator = useCallback(async () => {
    const request = ++statusRequest.current;
    if (!feed.session?.session_id || !feed.session?.gateway_token) {
      setOrchestratorStatus(null);
      setOrchestratorError("");
      setOrchestratorLoading(false);
      return null;
    }

    setOrchestratorLoading(true);
    try {
      const status = await getJSON("/api/orchestrator/status");
      if (request !== statusRequest.current) return null;
      setOrchestratorStatus(status);
      setOrchestratorError("");
      return status;
    } catch (error) {
      if (request !== statusRequest.current) return null;
      setOrchestratorError(error.message || "Orchestrator status is unavailable.");
      return null;
    } finally {
      if (request === statusRequest.current) setOrchestratorLoading(false);
    }
  }, [feed.session?.gateway_token, feed.session?.session_id]);

  useEffect(() => {
    let active = true;
    let timer;

    if (!feed.session?.session_id || !feed.session?.gateway_token) {
      statusRequest.current += 1;
      setOrchestratorStatus(null);
      setOrchestratorError("");
      setOrchestratorLoading(false);
      return () => {};
    }

    const poll = async () => {
      await refreshOrchestrator();
      if (active) timer = window.setTimeout(poll, ORCHESTRATOR_POLL_MS);
    };
    poll();

    return () => {
      active = false;
      window.clearTimeout(timer);
      statusRequest.current += 1;
    };
  }, [feed.session?.gateway_token, feed.session?.session_id, refreshOrchestrator]);

  async function onUpload(event) {
    const file = event.target.files?.[0];
    if (!file || !feed.session) return;
    try {
      const result = await uploadFile(file);
      toast(`Ingested ${result.ingested ?? 0} event(s) from ${file.name}`, "ok");
    } catch (error) {
      toast(error.message, "error");
    } finally {
      event.target.value = "";
    }
  }

  const showExposure = exposesExternalInvestigation(orchestratorStatus);
  const navSections = [
    {
      heading: null,
      links: [["", "Setup"], ["command", "Command Center"]],
    },
    ...(showExposure ? [
      {
        heading: "Exposure",
        links: [
          ["exposure", "Exposure Overview"],
          ["findings", "Findings"],
          ["watchtower", "Watchtower"],
          ["assets", "Assets"],
          ["reports", "Reports"],
        ],
      },
      {
        heading: "DarkGuard APEX",
        links: [
          ["apex", "APEX Console"],
          ["attribution", "Attribution"],
          ["evaluation", "Evaluation Lab"],
          ["network", "Network Status"],
          ["torfinder", "Tor Finder"],
          ["osint", "OSINT"],
        ],
      },
      {
        heading: null,
        links: [["guide", "Guide"]],
      },
    ] : []),
  ];
  const outletContext = {
    ...feed,
    orchestratorStatus,
    orchestratorError,
    orchestratorLoading,
    refreshOrchestrator,
  };

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand" style={{ cursor: "pointer" }} onClick={() => nav("/")}><ShieldMark size={18} /> SENTINEL APEX</div>
        <nav>
          {navSections.flatMap((section, index) => [
            ...(section.heading ? [<div className="sect" key={`heading-${index}`}>{section.heading}</div>] : []),
            ...section.links.map(([to, label]) => (
              <NavLink key={to} to={to} end={to === ""} className={({ isActive }) => (isActive ? "on" : "")}>
                {label}
              </NavLink>
            )),
          ])}
        </nav>
        <div className="usr">
          <div className="row center" style={{ gap: 8, marginBottom: 8 }}>
            <span className="livedot" style={{ background: feed.connected ? "var(--ok)" : feed.session ? "var(--warn)" : "var(--alert)" }} />
            <span className="mono-label">{feed.connected ? "monitoring · authenticated" : feed.session ? "sensor offline / connecting" : "setup required"}</span>
          </div>
          {feed.session && <div className="snip brk" style={{ marginBottom: 9 }}>{feed.session.session_id}</div>}
          <button className="btn btn-sm" disabled={!feed.session} style={{ width: "100%" }} onClick={() => fileRef.current?.click()}>Upload HAR / JSONL</button>
          <input ref={fileRef} type="file" accept=".har,.json,.jsonl" className="hidden" onChange={onUpload} />
        </div>
      </aside>
      <main className="main" style={{ position: "relative" }}>
        <NetworkField opacity={0.22} speed={0.16} linkDist={130} />
        <div style={{ position: "relative", zIndex: 1 }}>
          <Outlet context={outletContext} />
        </div>
      </main>
      <AnalystDock feed={feed} />
    </div>
  );
}
