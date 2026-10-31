import { useOutletContext } from "react-router-dom";
import Terminal from "../../components/Terminal.jsx";
import { eventLine } from "./Overview.jsx";

export default function LiveEvents() {
  const feed = useOutletContext();
  const logs = feed.events.slice(0, 120).map(eventLine).reverse();
  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Normalized event stream</div>
          <h1 className="display" style={{ fontSize: "1.8rem", marginTop: 6 }}>Live Telemetry</h1>
        </div>
        <span className="mono-label">{feed.connected ? "● live" : "○ offline"} · {feed.events.length} events</span>
      </div>
      <div className="panel ticked" style={{ marginTop: 18 }}>
        <div className="panel-head"><span>sentinel@apex ~ % tail -f telemetry</span><span className="tag">{feed.events.length}</span></div>
        <div className="panel-pad">
          <Terminal logs={logs.length ? logs : ["waiting for authenticated telemetry… start an enrolled sensor or route an action through Guardian"]} />
        </div>
      </div>
    </div>
  );
}
