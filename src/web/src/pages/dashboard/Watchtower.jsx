import { useEffect, useState } from "react";
import { darkguardApi as api } from "../../lib/darkguardApi.js";
import { useDialog, useToast } from "../../lib/ui.jsx";

const fmt = (d) => { try { return new Date(d + "Z").toLocaleString(); } catch { return d; } };

export default function Watchtower() {
  const toast = useToast();
  const { confirm } = useDialog();
  const [monitors, setMonitors] = useState([]);
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loadError, setLoadError] = useState("");

  const load = async () => {
    try {
      const { monitors: upstreamMonitors } = await api("/monitors");
      setMonitors(upstreamMonitors || []);
      setLoadError("");
    } catch (error) {
      setMonitors([]);
      setLoadError(error.message || "Monitor service is unavailable.");
    }
  };
  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!domain.trim()) return;
    setBusy(true);
    try { await api("/monitors", { method: "POST", body: { domain: domain.trim() } }); setDomain(""); load(); }
    catch (e) { toast(e.message, "error"); }
    finally { setBusy(false); }
  };

  const open = async (id) => {
    setSel(id); setDetail(null);
    try { const d = await api(`/monitors/${id}`); setDetail(d); }
    catch (e) { setDetail({ error: e.message }); }
  };

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Watchtower</div>
          <h1 className="display">Perimeter monitor</h1>
          <p>Add your domains. We watch DNS, IPs, TLS, security posture &amp; raise incidents on change.</p>
        </div>
      </div>

      {loadError && (
        <div className="banner" style={{ marginBottom: 16, borderColor: "var(--alert)", color: "var(--alert)" }}>
          <span>// Monitor service unavailable: {loadError}</span>
        </div>
      )}

      <div className="banner" style={{ borderColor: "var(--info)", background: "rgba(76,201,240,.06)", color: "var(--info)" }}>
        <span>// OSINT / perimeter monitoring — DNS, TLS, headers, IP &amp; change-detection. Host-level IDS &amp; packet forensics require an installed agent (roadmap).</span>
      </div>

      <div className="panel ticked">
        <div className="panel-head"><span>// Add domain</span></div>
        <div className="panel-pad row">
          <input className="input grow" placeholder="acme.com" value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
          <button className="btn btn-primary" disabled={busy} onClick={add}>{busy ? "Checking…" : "Monitor"}</button>
        </div>
      </div>

      <div className="grid g3" style={{ marginTop: 16 }}>
        {monitors.map((m) => {
          const s = m.snapshot || {};
          const grade = s.http?.securityHeaders?.grade || "—";
          const up = s.http?.reachable;
          return (
            <div key={m.id} className="panel" style={{ cursor: "pointer" }} onClick={() => open(m.id)}>
              <div className="panel-head"><span className="brk">{m.domain}</span><span className="tag">{up ? "UP" : "DOWN"}</span></div>
              <div className="panel-pad">
                <div className="row between"><span className="muted">TLS</span><b style={{ color: s.ssl?.valid ? "var(--ok)" : "var(--alert)" }}>{s.ssl?.valid ? `${s.ssl.daysLeft}d left` : "invalid"}</b></div>
                <div className="row between" style={{ marginTop: 6 }}><span className="muted">Headers</span><b className={`badge sev-${grade === "A" ? "low" : grade === "F" ? "critical" : "high"}`}>{grade}</b></div>
                <div className="row between" style={{ marginTop: 6 }}><span className="muted">IPs</span><b>{(s.ips || []).length}</b></div>
                <div className="row between" style={{ marginTop: 6 }}><span className="muted">Open ports</span><b style={{ color: (s.ports || []).some((p) => p.risky) ? "var(--alert)" : "var(--ink)" }}>{(s.ports || []).length}</b></div>
                <div className="row between" style={{ marginTop: 6 }}><span className="muted">Subdomains</span><b>{(s.subdomains || []).length}</b></div>
                <div className="snip" style={{ marginTop: 8 }}>checked {fmt(m.last_checked)}</div>
              </div>
            </div>
          );
        })}
        {monitors.length === 0 && !loadError && <div className="empty">No domains monitored yet.</div>}
      </div>

      {sel && (
        <MonitorDetail
          detail={detail}
          onClose={() => { setSel(null); setDetail(null); }}
          onRefresh={() => open(sel)}
          onDelete={async () => {
            const ok = await confirm({
              eyebrow: "// Remove monitor",
              title: "Stop monitoring?",
              message: "This removes the domain and its incident history. This can't be undone.",
              okText: "Delete",
              danger: true,
            });
            if (!ok) return;
            try {
              await api(`/monitors/${sel}`, { method: "DELETE" });
              toast("Monitor removed", "ok");
              setSel(null);
              await load();
            } catch (error) {
              toast(error.message || "Could not remove monitor.", "error");
            }
          }}
        />
      )}
    </div>
  );
}

function MonitorDetail({ detail, onClose, onRefresh, onDelete }) {
  if (!detail) return <div className="panel" style={{ marginTop: 16 }}><div className="empty">Inspecting domain over the network…</div></div>;
  if (detail.error) return <div className="panel" style={{ marginTop: 16 }}><div className="empty">{detail.error}</div></div>;
  const { monitor, events } = detail;
  const s = monitor.snapshot || {};
  const rec = s.records || {};

  return (
    <div style={{ marginTop: 20 }}>
      <div className="row between center" style={{ marginBottom: 12 }}>
        <h2 className="display" style={{ fontSize: "1.3rem" }}>{monitor.domain}</h2>
        <div className="row">
          <button className="btn btn-sm" onClick={onRefresh}>↻ Re-check</button>
          <button className="btn btn-sm btn-danger" onClick={onDelete}>Delete</button>
          <button className="btn btn-sm" onClick={onClose}>Close</button>
        </div>
      </div>

      <div className="grid g2">
        <div className="panel">
          <div className="panel-head"><span>DNS records</span></div>
          <div className="panel-pad" style={{ fontSize: ".82rem" }}>
            <Rec label="A" items={rec.A} />
            <Rec label="AAAA" items={rec.AAAA} />
            <Rec label="MX" items={rec.MX} />
            <Rec label="NS" items={rec.NS} />
            <Rec label="CNAME" items={rec.CNAME} />
            <Rec label="TXT" items={rec.TXT} />
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>TLS &amp; HTTP</span></div>
          <div className="panel-pad" style={{ fontSize: ".84rem" }}>
            <KV k="Status" v={s.http?.reachable ? `HTTP ${s.http.status}` : "unreachable"} alert={!s.http?.reachable} />
            <KV k="Response time" v={s.http?.responseMs != null ? `${s.http.responseMs} ms` : "—"} />
            <KV k="Server" v={s.http?.server || "—"} />
            <KV k="TLS issuer" v={s.ssl?.valid ? s.ssl.issuer : "—"} />
            <KV k="TLS expires" v={s.ssl?.valid ? `${s.ssl.validTo} (${s.ssl.daysLeft}d)` : "no valid cert"} alert={s.ssl?.valid && s.ssl.daysLeft <= 30} />
            <KV k="Header grade" v={s.http?.securityHeaders?.grade || "—"} />
            <div className="snip" style={{ marginTop: 8 }}>Missing: {(s.http?.securityHeaders?.missing || []).join(", ") || "none"}</div>
          </div>
        </div>
      </div>

      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head"><span>IP intelligence &amp; ASN</span></div>
          <div className="panel-pad" style={{ fontSize: ".82rem" }}>
            {(s.ipIntel || []).length ? s.ipIntel.map((i, k) => (
              <div key={k} style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                <b className="brk">{i.ip}</b>
                <div className="snip">{[i.city, i.country].filter(Boolean).join(", ") || "location unknown"}{i.as ? ` · ${i.as}` : ""}</div>
                {i.isp && <div className="snip">{i.isp}</div>}
              </div>
            )) : <span className="muted">No resolved IPs.</span>}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>Email authentication</span></div>
          <div className="panel-pad" style={{ fontSize: ".84rem" }}>
            <KV k="SPF" v={s.email?.spf?.found ? "present" : "missing"} alert={!s.email?.spf?.found} />
            <KV k="DMARC" v={s.email?.dmarc?.found ? `p=${s.email.dmarc.policy}` : "missing"} alert={!s.email?.dmarc?.found} />
            <KV k="DKIM" v={s.email?.dkim?.found ? s.email.dkim.selectors.join(", ") : "none found"} alert={!s.email?.dkim?.found} />
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>Open ports</span><span className="tag">{(s.ports || []).length}</span></div>
          <div className="panel-pad">
            {(s.ports || []).length ? (
              <div className="chips">
                {s.ports.map((p, k) => (
                  <span key={k} className="chip" style={{ borderColor: p.risky ? "var(--alert)" : "var(--line-hard)", color: p.risky ? "var(--alert)" : "var(--ink-dim)" }}>
                    {p.port} {p.service}{p.risky ? " ⚠" : ""}
                  </span>
                ))}
              </div>
            ) : <span className="muted">No common ports detected open.</span>}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>Domain registration</span></div>
          <div className="panel-pad" style={{ fontSize: ".84rem" }}>
            {s.domainInfo ? (
              <>
                <KV k="Registrar" v={s.domainInfo.registrar || "—"} />
                <KV k="Created" v={s.domainInfo.created ? new Date(s.domainInfo.created).toLocaleDateString() : "—"} />
                <KV k="Expires" v={s.domainInfo.expires ? `${new Date(s.domainInfo.expires).toLocaleDateString()} (${s.domainInfo.daysToExpiry}d)` : "—"} alert={s.domainInfo.daysToExpiry != null && s.domainInfo.daysToExpiry <= 30} />
              </>
            ) : <span className="muted">WHOIS/RDAP data unavailable.</span>}
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>Subdomains (cert transparency)</span><span className="tag">{(s.subdomains || []).length}</span></div>
        <div className="panel-pad">
          {(s.subdomains || []).length ? (
            <div className="chips">{s.subdomains.map((sd, k) => <span key={k} className="chip brk">{sd}</span>)}</div>
          ) : <span className="muted">No subdomains found via certificate transparency.</span>}
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>// Incident &amp; event timeline</span><span className="tag">{events?.length || 0}</span></div>
        {events?.length ? (
          <table>
            <thead><tr><th>Severity</th><th>Type</th><th>Event</th><th>When</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td><span className={`sev sev-${e.severity}`}>{e.severity}</span></td>
                  <td className="muted">{e.type}</td>
                  <td>{e.message}</td>
                  <td className="muted">{fmt(e.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <div className="empty">No incidents recorded. All clear.</div>}
      </div>
    </div>
  );
}

function Rec({ label, items }) {
  return (
    <div style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="mono-label">{label}</span>
      <div className="brk" style={{ marginTop: 3 }}>{items?.length ? items.join("  ·  ") : <span className="muted">none</span>}</div>
    </div>
  );
}
function KV({ k, v, alert }) {
  return <div className="row between" style={{ padding: "6px 0", borderBottom: "1px solid var(--line)" }}><span className="muted">{k}</span><b className="brk" style={{ color: alert ? "var(--alert)" : "var(--ink)" }}>{v}</b></div>;
}
