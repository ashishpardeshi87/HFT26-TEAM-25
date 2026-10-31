// REST helpers + a live WebSocket hook for SENTINEL APEX.
import { useEffect, useRef, useState } from "react";

const base = "";

export async function getJSON(path) {
  const r = await fetch(base + path);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

export async function postJSON(path, body) {
  const r = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

export async function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  const r = await fetch("/api/ingest/upload", { method: "POST", body: fd });
  return r.json();
}

// Live feed: keeps stats, incidents and events in sync over WebSocket,
// with REST snapshot fallback and auto-reconnect.
export function useLiveFeed() {
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [flash, setFlash] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        const [s, inc, ev] = await Promise.all([
          getJSON("/api/stats"),
          getJSON("/api/incidents"),
          getJSON("/api/events"),
        ]);
        if (!alive) return;
        setStats(s);
        setIncidents(inc);
        setEvents(ev);
      } catch (_) {}
    })();

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (alive) setTimeout(connect, 1500);
      };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "snapshot") {
          setStats(msg.stats);
          setIncidents(msg.incidents);
          setEvents(msg.events);
        } else if (msg.type === "update") {
          setStats(msg.stats);
          setEvents((prev) => [msg.event, ...prev].slice(0, 80));
          setIncidents((prev) => {
            const rest = prev.filter((i) => i.incident_id !== msg.incident.incident_id);
            return [msg.incident, ...rest].slice(0, 60);
          });
          setFlash(msg.incident);
          setTimeout(() => setFlash(null), 900);
        }
      };
    };
    connect();

    return () => {
      alive = false;
      wsRef.current && wsRef.current.close();
    };
  }, []);

  return { stats, incidents, events, connected, flash };
}

export const SEV = {
  critical: "bg-crit",
  high: "bg-high",
  medium: "bg-med",
  low: "bg-low",
  info: "bg-paper",
};
