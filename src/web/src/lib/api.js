// SENTINEL APEX authenticated REST + WebSocket client.
import { useEffect, useRef, useState } from "react";

const SESSION_KEY = "sentinel.apex.session.v1";

export function getSessionCredentials() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY) || "null"); }
  catch { return null; }
}

export function setSessionCredentials(value) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(value));
  window.dispatchEvent(new Event("sentinel-session-changed"));
}

export function clearSessionCredentials() {
  localStorage.removeItem(SESSION_KEY);
  window.dispatchEvent(new Event("sentinel-session-changed"));
}

function authHeaders(extra = {}) {
  const s = getSessionCredentials();
  return {
    ...extra,
    ...(s?.session_id ? { "X-Sentinel-Session": s.session_id } : {}),
    ...(s?.gateway_token ? { "X-Sentinel-Token": s.gateway_token } : {}),
  };
}

async function decode(res, path) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    const message = typeof d === "string" ? d
      : Array.isArray(d?.errors) ? d.errors.join("; ")
      : d?.detail || d?.error || data.error || `Request failed (${res.status})`;
    const err = new Error(message);
    err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

export async function getJSON(path) {
  const r = await fetch(path, { headers: authHeaders() });
  return decode(r, path);
}

export async function postJSON(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  return decode(r, path);
}

export async function uploadFile(file) {
  const fd = new FormData(); fd.append("file", file);
  const r = await fetch("/api/ingest/upload", { method: "POST", headers: authHeaders(), body: fd });
  return decode(r, "/api/ingest/upload");
}

export function useSessionCredentials() {
  const [session, setSession] = useState(() => getSessionCredentials());
  useEffect(() => {
    const update = () => setSession(getSessionCredentials());
    window.addEventListener("sentinel-session-changed", update);
    window.addEventListener("storage", update);
    return () => { window.removeEventListener("sentinel-session-changed", update); window.removeEventListener("storage", update); };
  }, []);
  return session;
}

export function useLiveFeed() {
  const session = useSessionCredentials();
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [flash, setFlash] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    let alive = true;
    let retry = null;
    setStats(null); setIncidents([]); setEvents([]); setConnected(false);
    if (!session?.session_id || !session?.gateway_token) return () => {};

    (async () => {
      try {
        const [s, inc, ev] = await Promise.all([
          getJSON("/api/stats"), getJSON("/api/incidents"), getJSON("/api/events"),
        ]);
        if (!alive) return;
        setStats(s); setIncidents(inc); setEvents(ev);
      } catch { /* websocket will expose connection state */ }
    })();

    const connect = () => {
      if (!alive) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const qs = new URLSearchParams({ session_id: session.session_id, token: session.gateway_token });
      const ws = new WebSocket(`${proto}://${location.host}/ws?${qs}`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); if (alive) retry = setTimeout(connect, 1800); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "snapshot") {
          setStats(msg.stats); setIncidents(msg.incidents); setEvents(msg.events);
        } else if (msg.type === "update") {
          setStats(msg.stats);
          setEvents((p) => [msg.event, ...p].slice(0, 120));
          setIncidents((p) => [msg.incident, ...p.filter((i) => i.incident_id !== msg.incident.incident_id)].slice(0, 80));
          setFlash(msg.incident); setTimeout(() => setFlash(null), 1000);
        }
      };
    };
    connect();
    return () => {
      alive = false; clearTimeout(retry); wsRef.current?.close();
    };
  }, [session?.session_id, session?.gateway_token]);

  return { stats, incidents, events, connected, flash, session };
}

export const sevClass = (lvl) => `sev sev-${lvl || "info"}`;

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method,
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: body ? JSON.stringify(body) : undefined,
  });
  return decode(res, "/api" + path);
}
