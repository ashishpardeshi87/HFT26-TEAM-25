import { Navigate, Route, Routes } from "react-router-dom";
import ScrollToTop from "./components/ScrollToTop.jsx";
import Landing from "./pages/Landing.jsx";
import HowItWorks from "./pages/HowItWorks.jsx";
import DashboardLayout from "./pages/dashboard/DashboardLayout.jsx";
// Exposure Overview is the evidence-gated DarkGuard investigation surface.
import ExposureOverview from "./pages/dashboard/ExposureOverview.jsx";
import Findings from "./pages/dashboard/Findings.jsx";
import Watchtower from "./pages/dashboard/Watchtower.jsx";
import Assets from "./pages/dashboard/Assets.jsx";
import Reports from "./pages/dashboard/Reports.jsx";
import TorFinder from "./pages/dashboard/TorFinder.jsx";
import OSINT from "./pages/dashboard/OSINT.jsx";
import Evaluation from "./pages/dashboard/Evaluation.jsx";
import NetworkStatus from "./pages/dashboard/NetworkStatus.jsx";
import Guide from "./pages/dashboard/Guide.jsx";
// APEX panel (AI-agent security + attribution console)
import Overview from "./pages/dashboard/Overview.jsx";
import Incidents from "./pages/dashboard/Incidents.jsx";
import AgentSecurity from "./pages/dashboard/AgentSecurity.jsx";
import Inspect from "./pages/dashboard/Inspect.jsx";
import LiveEvents from "./pages/dashboard/LiveEvents.jsx";
import Approvals from "./pages/dashboard/Approvals.jsx";
import Apex from "./pages/dashboard/Apex.jsx";
import Attribution from "./pages/dashboard/Attribution.jsx";
import Setup from "./pages/dashboard/Setup.jsx";
import Policy from "./pages/dashboard/Policy.jsx";
import Flow from "./pages/dashboard/Flow.jsx";
import Landscape from "./pages/dashboard/Landscape.jsx";
import Investigation from "./pages/dashboard/Investigation.jsx";

// Keep every page navigable for UI development and fine-tuning. This is not
// an authorization boundary: protected backend endpoints still require the
// verified session ID and Gateway token before returning data or taking action.
function Secured({ children }) {
  return children;
}

export default function App() {
  return (
    <>
      <ScrollToTop />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/how-it-works" element={<HowItWorks />} />
        <Route path="/app" element={<DashboardLayout />}>
          {/* Setup is always the first page */}
          <Route index element={<Setup />} />
          <Route path="setup" element={<Navigate to="/app" replace />} />
          {/* Exposure */}
          <Route path="exposure" element={<Secured><ExposureOverview /></Secured>} />
          <Route path="findings" element={<Secured><Findings /></Secured>} />
          <Route path="watchtower" element={<Secured><Watchtower /></Secured>} />
          <Route path="assets" element={<Secured><Assets /></Secured>} />
          <Route path="reports" element={<Secured><Reports /></Secured>} />
          <Route path="scan" element={<Navigate to="/app/command" replace />} />
          <Route path="scans" element={<Navigate to="/app/command" replace />} />
          <Route path="scans/:id" element={<Navigate to="/app/command" replace />} />
          {/* APEX */}
          <Route path="command" element={<Secured><Overview /></Secured>} />
          <Route path="incidents" element={<Secured><Incidents /></Secured>} />
          <Route path="agent-security" element={<Secured><AgentSecurity /></Secured>} />
          <Route path="inspect" element={<Secured><Inspect /></Secured>} />
          <Route path="live" element={<Secured><LiveEvents /></Secured>} />
          <Route path="approvals" element={<Secured><Approvals /></Secured>} />
          <Route path="apex" element={<Secured><Apex /></Secured>} />
          <Route path="attribution" element={<Secured><Attribution /></Secured>} />
          <Route path="evaluation" element={<Secured><Evaluation /></Secured>} />
          <Route path="network" element={<Secured><NetworkStatus /></Secured>} />
          <Route path="torfinder" element={<Secured><TorFinder /></Secured>} />
          <Route path="osint" element={<Secured><OSINT /></Secured>} />
          <Route path="guide" element={<Secured><Guide /></Secured>} />
          <Route path="policy" element={<Policy />} />
          <Route path="flow" element={<Flow />} />
          <Route path="landscape" element={<Secured><Landscape /></Secured>} />
          <Route path="investigation" element={<Secured><Investigation /></Secured>} />
          <Route path="console" element={<Navigate to="/app/command" replace />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}
