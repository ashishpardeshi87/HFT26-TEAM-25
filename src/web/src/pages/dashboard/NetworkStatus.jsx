import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { darkguardApi as api } from "../../lib/darkguardApi.js";
import { useToast } from "../../lib/ui.jsx";
import { BarChart, DoughnutChart } from "../../components/Charts.jsx";
import Terminal from "../../components/Terminal.jsx";

// ── Network status ──────────────────────────────────────────────────────────
//
// WHAT THIS REPLACED
// -----------------
// The public site had a "live cyber attack map" whose events were produced by a
// browser-side generator picking random city pairs, random vectors and random IP
// addresses every 700ms. Nothing on it was observed. That page and its generator
// are deleted.
//
// This is the honest version of the same idea: every number below is read from a
// running service at the moment you load the page. Where a value is not available
// the panel says so rather than substituting a plausible-looking one. Nothing here
// is generated, interpolated or animated to look busy.
//
// Sources, all real:
//   GET /hunt/readiness            scraper liveness + Tor bootstrap state
//   GET /tor/ip                    the actual current exit IP, via the control port
//   GET /attribution/live/services the marketplace directory the hunt uses
//   GET /attribution/status        the engine's own capability scorecard
//
// The only thing that repeats on a timer is the Tor bootstrap poll, because that
// value genuinely changes while a circuit is being built.

const ts = () => new Date().toLocaleTimeString();

export default function NetworkStatus() {
  const toast = useToast();
  const [readiness, setReadiness] = useState(null);
  const [torIp, setTorIp] = useState(null);
  const [services, setServices] = useState(null);
  const [status, setStatus] = useState(null);
  const [errors, setErrors] = useState({});
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const logRef = useRef([]);
  const poll = useRef(null);

  const log = useCallback((m) => {
    logRef.current = [...logRef.current, `[${ts()}] ${m}`].slice(-120);
    setLogs(logRef.current);
  }, []);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) { setLoading(true); log("Querying services…"); }
    const next = {};

    // Each request is independent: one failure must not blank the page, because
    // "the scraper is down" is itself a real status worth displaying.
    const [r, ip, svc, st] = await Promise.allSettled([
      api("/hunt/readiness"),
      api("/tor/ip"),
      api("/attribution/live/services"),
      api("/attribution/status"),
    ]);

    if (r.status === "fulfilled") {
      setReadiness(r.value);
      if (!quiet) log(`Scraper ${r.value.scraperUp ? "up" : "DOWN"} · Tor bootstrap ${r.value.tor?.bootstrapped ?? "?"}%`);
    } else { next.readiness = r.reason?.message ?? "unavailable"; }

    if (ip.status === "fulfilled") {
      setTorIp(ip.value);
      if (!quiet && ip.value?.ip) log(`Tor exit IP ${ip.value.ip}`);
    } else { next.torIp = ip.reason?.message ?? "unavailable"; }

    if (svc.status === "fulfilled") {
      setServices(svc.value);
      if (!quiet) log(`Marketplace directory: ${(svc.value.services || []).length} service(s)`);
    } else { next.services = svc.reason?.message ?? "unavailable"; }

    if (st.status === "fulfilled") setStatus(st.value);
    else next.status = st.reason?.message ?? "unavailable";

    setErrors(next);
    setLoading(false);
  }, [log]);

  useEffect(() => { load(); }, [load]);

  // Bootstrap percentage is the one genuinely live value, so it is the only thing
  // polled. Stops once Tor reports done.
  useEffect(() => {
    const done = readiness?.tor?.bootstrapped === 100;
    clearInterval(poll.current);
    if (done) return;
    poll.current = setInterval(() => {
      api("/hunt/readiness").then(setReadiness).catch(() => {});
    }, 5000);
    return () => clearInterval(poll.current);
  }, [readiness?.tor?.bootstrapped]);

  const tor = readiness?.tor ?? {};
  const svcList = services?.services ?? [];

  // Real composition of the directory, grouped by where each address came from.
  const bySource = useMemo(() => {
    const m = {};
    for (const s of svcList) m[s.source || "unknown"] = (m[s.source || "unknown"] || 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [svcList]);

  const marketCount = svcList.filter((s) => s.likelyMarket).length;
  const otherCount = svcList.length - marketCount;

  const newIdentity = async () => {
    log("Requesting a new Tor identity (SIGNAL NEWNYM)…");
    try {
      const d = await api("/tor/newnym", { method: "POST" });
      if (d.ok) {
        setTorIp({ ip: d.new_ip, reachable: true });
        log(`Exit IP ${d.old_ip || "?"} → ${d.new_ip || "?"} ${d.changed ? "(changed)" : "(same relay, retry)"}`);
      } else { log("Could not change identity: " + (d.error || "unknown")); }
    } catch (e) { toast(e.message, "error"); log("ERROR " + e.message); }
  };

  const built = status?.capabilities?.reduce((a, c) => a + c.built, 0) ?? 0;
  const ofTotal = status?.capabilities?.reduce((a, c) => a + c.of, 0) ?? 0;

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Network status</div>
          <h1 className="display">Live service state</h1>
          <p>
            Every figure on this page is read from a running service. Nothing is generated or simulated —
            where a value is unavailable, it says so.
          </p>
        </div>
        <button className="btn btn-sm" disabled={loading} onClick={() => load()}>
          {loading ? "…" : "↻ Refresh"}
        </button>
      </div>

      {/* ── Service reachability ── */}
      <div className="grid g4">
        <StatCard
          label="Scraper service"
          value={errors.readiness ? "unknown" : readiness?.scraperUp ? "UP" : "DOWN"}
          tone={errors.readiness ? "dim" : readiness?.scraperUp ? "ok" : "alert"}
          sub={errors.readiness ? errors.readiness : "FastAPI, owns the Tor session"}
        />
        <StatCard
          label="Tor bootstrap"
          value={tor.bootstrapped != null ? `${tor.bootstrapped}%` : "—"}
          tone={tor.bootstrapped === 100 ? "ok" : tor.bootstrapped > 0 ? "warn" : "alert"}
          sub={tor.detail || (errors.readiness ? "scraper unreachable" : "waiting for daemon")}
        />
        <StatCard
          label="SOCKS proxy"
          value={tor.socks_open == null ? "—" : tor.socks_open ? "OPEN" : "CLOSED"}
          tone={tor.socks_open ? "ok" : "alert"}
          sub={tor.proxy || "127.0.0.1:9050"}
        />
        <StatCard
          label="Tor exit IP"
          value={errors.torIp ? "—" : torIp?.ip || "…"}
          tone={torIp?.reachable ? "acid" : "dim"}
          sub={errors.torIp ? "unavailable" : "current circuit"}
          mono
        />
      </div>

      {/* ── Directory composition ── */}
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head">
            <span>// Marketplace directory</span>
            <span className="tag">{svcList.length} service(s)</span>
          </div>
          <div className="panel-pad">
            {errors.services ? (
              <div className="empty">
                Directory unavailable — {errors.services}. This needs the scraper service running.
              </div>
            ) : svcList.length === 0 ? (
              <div className="empty">
                No services in the directory yet. The scraper fetches dark.fail, tor.taxi and onion.live on first use.
              </div>
            ) : (
              <>
                <div className="snip" style={{ marginBottom: 14 }}>
                  Addresses harvested from public clearnet directories. Reachability is only known once a service is
                  actually probed over Tor — so this is a candidate list, not an uptime claim.
                </div>
                <div style={{ height: 210 }}>
                  {/* Labels say what the split actually measures. The classifier is a
                      conservative name-pattern match, so the larger group means "not
                      confidently classified", NOT "confirmed to be something else".
                      Labelling it "forum / other" would overstate what we know. */}
                  <DoughnutChart
                    labels={["Name matches market pattern", "Not classified"]}
                    data={[marketCount, otherCount]}
                    colors={["#c6ff3a", "#4cc9f0"]}
                    showLegend
                  />
                </div>
                <div className="snip" style={{ marginTop: 12, color: "var(--ink-faint)" }}>
                  Classification is a conservative keyword match on the directory's own title for each address.
                  {marketCount} of {svcList.length} match. The remainder are unclassified rather than ruled out —
                  the only way to know what a service is, is to fetch it.
                </div>
              </>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span>// Where the addresses came from</span>
            <span className="tag">{bySource.length} source(s)</span>
          </div>
          <div className="panel-pad">
            {bySource.length === 0 ? (
              <div className="empty">No directory data.</div>
            ) : (
              <div style={{ height: 210 }}>
                <BarChart
                  labels={bySource.map((s) => s[0])}
                  data={bySource.map((s) => s[1])}
                  horizontal
                  color="#b56cff"
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Engine scorecard, read from the API ── */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <span>// Engine capability scorecard</span>
          <span className="tag" style={{ color: "var(--warn)" }}>
            {ofTotal ? `${built} / ${ofTotal} sub-capabilities built` : "unavailable"}
          </span>
        </div>
        <div className="panel-pad">
          {errors.status ? (
            <div className="empty">Scorecard unavailable — {errors.status}</div>
          ) : !status ? (
            <div className="empty">Loading…</div>
          ) : (
            <>
              <div className="snip" style={{ marginBottom: 12 }}>
                Reported by the engine itself at <span className="mono-label">GET /attribution/status</span>, so this
                panel cannot claim more than the implementation does.
              </div>
              <table>
                <thead><tr><th>Capability</th><th style={{ width: 92 }}>Built</th><th>Note</th></tr></thead>
                <tbody>
                  {status.capabilities.map((c) => {
                    const pct = (c.built / c.of) * 100;
                    const tint = pct >= 80 ? "var(--acid)" : pct >= 50 ? "var(--warn)" : "var(--alert)";
                    return (
                      <tr key={c.id}>
                        <td>{c.name}</td>
                        <td>
                          <span className="chip" style={{ borderColor: tint, color: tint }}>{c.built}/{c.of}</span>
                          <div className="metricbar" style={{ marginTop: 5 }}>
                            <i style={{ width: `${pct}%`, background: tint }} />
                          </div>
                        </td>
                        <td className="snip" style={{ marginTop: 0 }}>{c.note}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="snip" style={{ marginTop: 12, color: "var(--ink-faint)" }}>
                Corpus: {status.corpus}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Circuit control + log ── */}
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head"><span>// Tor circuit</span></div>
          <div className="panel-pad">
            <div className="snip" style={{ marginBottom: 14 }}>
              Requesting a new identity tears down the current circuit and builds a fresh relay path. Useful before a
              crawl if a service has started refusing the current exit.
            </div>
            <button className="btn btn-sm" disabled={!tor.socks_open} onClick={newIdentity}>
              ↻ New identity / change exit IP
            </button>
            {!tor.socks_open && (
              <div className="snip" style={{ marginTop: 10, color: "var(--warn)" }}>
                Unavailable while the SOCKS proxy is closed.
              </div>
            )}
            <div className="chips" style={{ marginTop: 16 }}>
              <span className="chip">control {tor.control_open ? "open" : "closed"}</span>
              <span className="chip">reachable {String(tor.reachable ?? "—")}</span>
              <Link to="../apex" className="chip" style={{ borderColor: "var(--acid)", color: "var(--acid)" }}>
                APEX Console →
              </Link>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>// Request log</span><span className="tag blink">_</span></div>
          <div className="panel-pad"><Terminal logs={logs} /></div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, sub, tone = "dim", mono }) {
  const color = {
    ok: "var(--ok)", acid: "var(--acid)", warn: "var(--warn)",
    alert: "var(--alert)", dim: "var(--ink-dim)",
  }[tone];
  return (
    <div className="panel panel-pad">
      <div className="mono-label">{label}</div>
      <div
        className={mono ? "brk" : "metric"}
        style={{
          marginTop: 10, color,
          fontSize: mono ? ".82rem" : "1.6rem",
          fontFamily: mono ? "var(--mono)" : "var(--display)",
          fontWeight: 700, lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      <div className="snip" style={{ marginTop: 8 }}>{sub}</div>
    </div>
  );
}
