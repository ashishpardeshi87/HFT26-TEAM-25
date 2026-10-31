import { useEffect, useRef, useState } from "react";
import { api, getJSON } from "../../lib/api.js";
import Terminal from "../../components/Terminal.jsx";

const ts = () => new Date().toLocaleTimeString();

// Turn raw proxy/socket errors into a plain-English explanation.
function friendly(err = "") {
  const e = String(err);
  if (/host unreachable|0x04|NewConnectionError|Connection refused/i.test(e))
    return "This .onion service is offline or unreachable right now (very common on the dark web).";
  if (/timed out|timeout|0x06/i.test(e)) return "The site took too long to respond over Tor and timed out.";
  if (/0x05|connection not allowed/i.test(e)) return "The Tor exit refused this connection.";
  return e.length > 160 ? e.slice(0, 160) + "…" : e;
}

export default function TorFinder() {
  const [ip, setIp] = useState(null);
  const [reachable, setReachable] = useState(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(null);
  const [logs, setLogs] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const logRef = useRef([]);

  const log = (m) => { logRef.current = [...logRef.current, `[${ts()}] ${m}`].slice(-200); setLogs(logRef.current); };

  const inited = useRef(false);
  useEffect(() => {
    if (inited.current) return; // guard React StrictMode double-mount
    inited.current = true;
    log("Connecting to Tor SOCKS proxy (127.0.0.1:9050)…");
    api("/tor/ip").then((d) => {
      setIp(d.ip); setReachable(d.reachable);
      log(d.reachable ? `Tor circuit active. Exit IP: ${d.ip || "unknown"}` : "Tor proxy unreachable.");
    }).catch((e) => log("ERROR: " + e.message));
    getJSON("/api/exposure/overview").then((d) => {
      const kws = Array.isArray(d.keywords) ? d.keywords : [];
      setSuggestions(kws.filter((w) => w && !/[@./:\s]/.test(String(w))).slice(0, 6));
    }).catch(() => {});
  }, []);

  const newIdentity = async () => {
    setBusy(true);
    log("Requesting new Tor identity (SIGNAL NEWNYM)…");
    log("Tearing down current circuit · building new relay path…");
    try {
      const d = await api("/tor/newnym", { method: "POST" });
      if (d.ok) {
        setIp(d.new_ip);
        log(`Old exit IP: ${d.old_ip || "?"}`);
        log(`New exit IP: ${d.new_ip || "?"} ${d.changed ? "✓ IP changed" : "(same node, retry)"}`);
      } else log("ERROR: " + (d.error || "could not change identity"));
    } catch (e) { log("ERROR: " + e.message); }
    finally { setBusy(false); }
  };

  const search = async () => {
    if (!query.trim()) return;
    setBusy(true); setResults([]); setPage(null);
    log(`Searching .onion engines for "${query}" over Tor…`);
    try {
      const d = await api("/tor/search", { method: "POST", body: { query: query.trim(), engines: ["ahmia", "tor66"], limit: 2 } });
      setResults(d.links || []);
      log(`Discovery complete — ${d.count} .onion link(s) found.`);
    } catch (e) { log("ERROR: " + e.message); }
    finally { setBusy(false); }
  };

  const open = async (url) => {
    setBusy(true); setPage({ url, loading: true });
    log(`Routing request through Tor → ${url.slice(0, 50)}…`);
    try {
      const d = await api("/tor/open", { method: "POST", body: { url } });
      if (d.ok) { setPage(d); log(`Loaded ${url.slice(0, 40)}… (HTTP ${d.status})`); }
      else {
        const msg = d.blocked ? "Content blocked by the safety filter." : friendly(d.error);
        setPage({ url, error: msg });
        log(d.blocked ? "Blocked by safety filter." : `Could not load: ${msg}`);
      }
    } catch (e) { const msg = friendly(e.message); setPage({ url, error: msg }); log("Could not load: " + msg); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Tor Finder</div>
          <h1 className="display">Onion browser</h1>
          <p>Search and open .onion sites over the Tor network. Rotate your exit IP on demand.</p>
        </div>
        <div style={{ textAlign: "right" }}>
          <div className="mono-label">Tor exit IP</div>
          <div className="display" style={{ fontSize: "1.2rem", color: reachable ? "var(--acid)" : "var(--alert)" }}>{ip || (reachable === false ? "OFFLINE" : "…")}</div>
          <button className="btn btn-sm" style={{ marginTop: 8 }} disabled={busy} onClick={newIdentity}>↻ New identity / Change IP</button>
        </div>
      </div>

      {suggestions.length > 0 && (
        <div className="panel ticked">
          <div className="panel-head"><span>// Investigation keywords · click to search</span><span className="tag">{suggestions.length}</span></div>
          <div className="panel-pad">
            <p className="snip">Evidence-derived keywords from the external-intervention incident. Click one to search .onion services over Tor.</p>
            <div className="row wrap" style={{ gap: 7, marginTop: 10 }}>
              {suggestions.map((term) => <button type="button" className="chip" key={term} onClick={() => setQuery(term)} style={{ cursor: "pointer" }}>{term}</button>)}
            </div>
          </div>
        </div>
      )}

      <div className="panel ticked" style={{ marginTop: suggestions.length > 0 ? 16 : 0 }}>
        <div className="panel-head"><span>// Search .onion</span></div>
        <div className="panel-pad row">
          <input className="input grow" placeholder="search term — e.g. leaked database" value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && search()} />
          <button className="btn btn-primary" disabled={busy} onClick={search}>{busy ? "…" : "Search"}</button>
        </div>
      </div>

      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head"><span>Results</span><span className="tag">{results.length}</span></div>
          <div className="panel-pad" style={{ maxHeight: 360, overflowY: "auto" }}>
            {results.length === 0 ? <div className="empty">No results yet.</div> : results.map((r, i) => (
              <div key={i} style={{ padding: "10px 0", borderBottom: "1px solid var(--line)", cursor: "pointer" }} onClick={() => open(r.url)}>
                <b style={{ fontSize: ".84rem" }}>{r.name || "(untitled)"}</b>
                <div className="snip brk acid">{r.url}</div>
                <div className="mono-label">via {r.engine}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>// Tor circuit log</span><span className="tag blink">_</span></div>
          <div className="panel-pad"><Terminal logs={logs} /></div>
        </div>
      </div>

      {page && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head"><span className="brk">{page.url}</span><span className="tag">in-app render</span></div>
          <div className="panel-pad">
            {page.loading ? <div className="empty">Loading over Tor…</div>
              : page.error ? <div className="empty" style={{ color: "var(--alert)" }}>{page.error}</div>
              : (
                <div>
                  <h3 className="display" style={{ fontSize: "1.1rem", marginBottom: 8 }}>{page.title || "(no title)"}</h3>
                  <div className="snip" style={{ whiteSpace: "pre-wrap", maxHeight: 300, overflowY: "auto" }}>{page.text || "(no readable text)"}</div>
                  {page.onion_links?.length > 0 && (
                    <div style={{ marginTop: 14 }}>
                      <div className="mono-label">Linked .onion ({page.onion_links.length})</div>
                      <div className="chips" style={{ marginTop: 8 }}>
                        {page.onion_links.map((l, i) => <span key={i} className="chip brk" style={{ cursor: "pointer" }} onClick={() => open(l)}>{l.slice(0, 40)}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              )}
          </div>
        </div>
      )}
    </div>
  );
}
