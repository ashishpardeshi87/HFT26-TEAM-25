import { useEffect, useState } from "react";

export default function App() {
  const [health, setHealth] = useState(null);
  const [agentName, setAgentName] = useState("sample-agent");
  const [receipt, setReceipt] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/health")
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("Backend unavailable")))
      .then(setHealth)
      .catch((reason) => setError(reason.message));
  }, []);

  async function sendHeartbeat(event) {
    event.preventDefault();
    setError("");
    setReceipt(null);
    try {
      const response = await fetch("/sample/heartbeat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: agentName, status: "online" }),
      });
      if (!response.ok) throw new Error("Heartbeat was rejected");
      setReceipt(await response.json());
    } catch (reason) {
      setError(reason.message);
    }
  }

  return (
    <main>
      <section className="hero">
        <p className="eyebrow">// PUBLIC PROTOTYPE SLICE</p>
        <h1>SENTINEL <span>APEX</span></h1>
        <p className="lead">A sanitized service-wiring sample for the project repository.</p>
        <div className={`status ${health ? "online" : "waiting"}`}>
          <i /> {health ? `${health.service} backend online` : "checking backend"}
        </div>
      </section>

      <section className="panel">
        <header>Sample heartbeat</header>
        <form onSubmit={sendHeartbeat}>
          <label htmlFor="agent">Sample name</label>
          <div className="row">
            <input id="agent" value={agentName} maxLength={80} onChange={(event) => setAgentName(event.target.value)} required />
            <button type="submit">Send heartbeat</button>
          </div>
        </form>
        {receipt && <p className="result">Accepted: {receipt.agent_name} · {receipt.status}</p>}
        {error && <p className="error">{error}</p>}
      </section>

      <p className="note">This sample stores no heartbeat data and includes no production security logic.</p>
    </main>
  );
}
