import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { clearSessionCredentials, getJSON, postJSON, setSessionCredentials, useSessionCredentials } from "../../lib/api.js";
import { useToast } from "../../lib/ui.jsx";

const split = (v) => v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
const emptyAgent = () => ({ id: "", process: "", pid: "" });
const MAX_RULE_FILE_BYTES = 256 * 1024;
const MAX_CUSTOM_RULES = 100;
const MATCH_KEYS = new Set(["tool", "scope", "destination", "path", "event_type", "data_type"]);
const ENFORCEMENTS = new Set(["allow", "warn", "require_approval", "deny"]);
const SEVERITIES = new Set(["medium", "high", "critical"]);
const RULE_TEMPLATE = {
  rules: [
    {
      operation: "add",
      id: "CUSTOM-BLOCK-EXTERNAL-POST",
      title: "Block HTTP posts to unapproved destinations",
      enforcement: "deny",
      severity: "high",
      match: { tool: "http_post", destination: "*.unapproved.example" },
    },
    {
      operation: "override",
      id: "AG-23",
      enforcement: "deny",
      severity: "critical",
    },
    {
      operation: "disable",
      id: "AG-39",
    },
  ],
};

function parseRulesFile(text) {
  let document;
  try { document = JSON.parse(text); }
  catch { throw new Error("The rules file is not valid JSON."); }

  const source = Array.isArray(document) ? document : document?.rules ?? document?.custom_rules;
  if (!Array.isArray(source)) throw new Error('Use a JSON array or an object containing a "rules" array.');
  if (source.length > MAX_CUSTOM_RULES) throw new Error(`A rules file may contain at most ${MAX_CUSTOM_RULES} rules.`);

  const normalizeMatch = (raw, at) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${at}: match must be an object.`);
    const invalidKeys = Object.keys(raw).filter((key) => !MATCH_KEYS.has(key));
    if (invalidKeys.length) throw new Error(`${at}: unsupported match key(s): ${invalidKeys.join(", ")}.`);
    const match = Object.fromEntries(Object.entries(raw).filter(([, value]) => {
      if (Array.isArray(value)) return value.some((item) => String(item).trim());
      return String(value ?? "").trim();
    }));
    if (!Object.keys(match).length) throw new Error(`${at}: match must contain at least one value.`);
    return match;
  };

  const ids = new Set();
  return source.map((raw, index) => {
    const at = `Rule ${index + 1}`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${at} must be a JSON object.`);
    const operation = String(raw.operation || "add").toLowerCase();
    if (!["add", "override", "disable"].includes(operation)) throw new Error(`${at}: operation must be add, override, or disable.`);
    const id = String(raw.id || "").trim().toUpperCase();
    if (!id) throw new Error(`${at}: id is required.`);
    if (ids.has(id)) throw new Error(`${at}: duplicate id ${id}.`);
    ids.add(id);

    if (operation === "disable") {
      if (!/^AG-\d{2}$/.test(id)) throw new Error(`${at}: disable must reference a baseline AG-* rule.`);
      return { operation, id };
    }

    const enforcement = raw.enforcement == null ? undefined : String(raw.enforcement).toLowerCase();
    if (enforcement && !ENFORCEMENTS.has(enforcement)) throw new Error(`${at}: invalid enforcement value.`);
    const severity = raw.severity == null ? undefined : String(raw.severity).toLowerCase();
    if (severity && !SEVERITIES.has(severity)) throw new Error(`${at}: invalid severity value.`);
    const title = raw.title == null ? undefined : String(raw.title).trim();
    const match = raw.match == null ? undefined : normalizeMatch(raw.match, at);

    if (operation === "add") {
      if (!/^CUSTOM-[A-Z0-9_-]+$/.test(id)) throw new Error(`${at}: added rule id must start with CUSTOM-.`);
      if (!title) throw new Error(`${at}: title is required for an added rule.`);
      if (!match) throw new Error(`${at}: match is required for an added rule.`);
      return { operation, id, title, enforcement: enforcement || "warn", severity: severity || "high", match };
    }

    if (!/^AG-\d{2}$/.test(id)) throw new Error(`${at}: override must reference a baseline AG-* rule.`);
    const patch = { operation, id };
    if (title) patch.title = title;
    if (enforcement) patch.enforcement = enforcement;
    if (severity) patch.severity = severity;
    if (match) patch.match = match;
    if (Object.keys(patch).length === 2) throw new Error(`${at}: override must change at least one field.`);
    return patch;
  });
}

export default function Setup() {
  const toast = useToast();
  const nav = useNavigate();
  const saved = useSessionCredentials();
  const [step, setStep] = useState(1);
  const [target, setTarget] = useState("");
  const [objective, setObjective] = useState("");
  const [agents, setAgents] = useState([emptyAgent()]);
  const [scenario, setScenario] = useState("production");
  const [allowedFiles, setAllowedFiles] = useState("README*\ndocs/**\nsrc/**");
  const [allowedTools, setAllowedTools] = useState("read_file\nhttp_get\nread_inbox");
  const [allowedHosts, setAllowedHosts] = useState("");
  const [customRules, setCustomRules] = useState([]);
  const [rulesFile, setRulesFile] = useState(null);
  const [rulesInputKey, setRulesInputKey] = useState(0);
  const [challenge, setChallenge] = useState(null);
  const [method, setMethod] = useState("http_token");
  const [ssh, setSsh] = useState({ host: "", port: "22", username: "", password: "", private_key: "", host_key_sha256: "", trust_on_first_use: false });
  const [db, setDb] = useState({ engine: "postgresql", host: "", port: "5432", database: "", username: "", password: "", sslmode: "prefer", ssl: true });
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [created, setCreated] = useState(null);
  const [existing, setExisting] = useState(null);
  const [sessionProbeError, setSessionProbeError] = useState("");
  const [sessionProbeTick, setSessionProbeTick] = useState(0);

  useEffect(() => {
    let active = true;
    if (!saved?.session_id) {
      setExisting(null);
      setSessionProbeError("");
      return () => { active = false; };
    }
    setSessionProbeError("");
    getJSON(`/api/sessions/${saved.session_id}`)
      .then((data) => { if (active) setExisting(data.session); })
      .catch((error) => {
        if (!active) return;
        setExisting(null);
        setSessionProbeError(error.message || "The backend could not verify the saved session.");
      });
    return () => { active = false; };
  }, [saved?.session_id, sessionProbeTick]);

  function patchAgent(index, patch) {
    setAgents((items) => items.map((item, current) => current === index ? { ...item, ...patch } : item));
  }

  async function uploadRules(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setBusy("rules"); setErr("");
    try {
      if (file.size > MAX_RULE_FILE_BYTES) throw new Error("The rules file must be 256 KB or smaller.");
      const parsed = parseRulesFile(await file.text());
      const preview = await postJSON("/api/policy/preview", { scenario, custom_rules: parsed });
      setCustomRules(parsed);
      setRulesFile({ name: file.name, size: file.size, count: parsed.length, accepted: preview.applied?.length || 0 });
      setStep((current) => Math.max(current, 3));
      toast(`${parsed.length} custom rule${parsed.length === 1 ? "" : "s"} validated`, "ok");
    } catch (error) {
      setCustomRules([]); setRulesFile(null);
      setErr(`Rules file rejected: ${error.message}`);
    } finally { setBusy(""); }
  }

  function removeRulesFile() {
    setCustomRules([]); setRulesFile(null); setRulesInputKey((value) => value + 1); setErr("");
  }

  function downloadRulesTemplate() {
    const blob = new Blob([JSON.stringify(RULE_TEMPLATE, null, 2) + "\n"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = "sentinel-custom-rules.template.json";
    document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
  }

  async function issueToken() {
    if (!target.trim()) { setErr("Enter the monitoring target first."); return; }
    setBusy("challenge"); setErr(""); setChallenge(null);
    try {
      const result = await postJSON("/api/setup/token", { target });
      setChallenge(result); toast("Single-use ownership challenge issued", "info"); setStep(4);
      if (!allowedHosts.trim()) setAllowedHosts(new URL(result.target).hostname);
      setSsh((value) => ({ ...value, host: value.host || new URL(result.target).hostname }));
    } catch (error) { setErr(error.message); }
    finally { setBusy(""); }
  }

  function proofPayload() {
    if (method === "http_token") return { method };
    if (method.startsWith("ssh_")) return { method, ...ssh, port: Number(ssh.port || 22) };
    return {
      method, ...db, port: Number(db.port || (db.engine === "postgresql" ? 5432 : 3306)),
      token: method === "database_token" ? challenge?.token : undefined,
    };
  }

  async function start() {
    const cleanAgents = agents.filter((agent) => agent.id.trim() && agent.process.trim()).map((agent) => ({ ...agent, pid: agent.pid ? Number(agent.pid) : null }));
    if (!challenge) { setErr("Issue an ownership challenge first."); return; }
    if (!objective.trim() || !cleanAgents.length) { setErr("Objective and at least one agent identity/process are required."); return; }
    setBusy("start"); setErr("");
    try {
      if (customRules.length) await postJSON("/api/policy/preview", { scenario, custom_rules: customRules });
      const body = {
        target: challenge.target, challenge_id: challenge.challenge_id,
        objective, agents: cleanAgents, scenario,
        manifest: {
          allowed_files: split(allowedFiles), allowed_tools: split(allowedTools), allowed_hosts: split(allowedHosts),
          allowed_scopes: buildScopes(split(allowedTools)),
        },
        custom_rules: customRules,
        auto_investigate: true,
        auto_isolate: true,
        proof: proofPayload(),
      };
      const result = await postJSON("/api/sessions", body);
      setSessionCredentials({ session_id: result.session.session_id, gateway_token: result.gateway_token, target: result.session.target });
      setCreated(result); setExisting(result.session); setSessionProbeError("");
      setSsh((value) => ({ ...value, password: "", private_key: "" }));
      setDb((value) => ({ ...value, password: "" }));
      toast("Ownership verified. Monitoring session active.", "ok");
    } catch (error) { setErr(error.message); }
    finally { setBusy(""); }
  }

  function forgetLocalSession() {
    clearSessionCredentials(); setExisting(null); setCreated(null); setSessionProbeError("");
    toast("Local session credential removed", "info");
  }

  return (
    <div>
      <div className="page-title">
        <div><div className="eyebrow">// Stage 1 · required before monitoring</div><h1 className="display" style={{ fontSize: "1.9rem", marginTop: 6 }}>Set up the security boundary</h1><p>Prove control, register each agent, compile policy, then enroll sensors and the Guardian gateway.</p></div>
        <span className="pill" style={{ color: existing?.status === "monitoring" ? "var(--ok)" : "var(--warn)", borderColor: existing?.status === "monitoring" ? "var(--ok)" : "var(--warn)" }}>{existing?.status || "setup required"}</span>
      </div>

      <SetupRail step={existing ? 5 : step} />

      {saved?.session_id && !existing && sessionProbeError && (
        <div className="panel ticked" style={{ marginTop: 16, borderColor: "var(--warn)" }}>
          <div className="panel-head"><span style={{ color: "var(--warn)" }}>// Saved monitoring session unavailable</span><span className="tag">credential retained</span></div>
          <div className="panel-pad">
            <p className="snip">{sessionProbeError}</p>
            <p className="snip" style={{ marginTop: 6 }}>A temporary backend outage will not erase your local enrollment. Retry after the backend recovers, or forget it explicitly.</p>
            <div className="row wrap" style={{ marginTop: 12 }}><button className="btn btn-primary btn-sm" onClick={() => setSessionProbeTick((value) => value + 1)}>Retry session</button><button className="btn btn-sm" onClick={forgetLocalSession}>Forget local session</button></div>
          </div>
        </div>
      )}

      {existing?.status === "monitoring" && (
        <div className="panel ticked" style={{ marginTop: 16, borderColor: "var(--ok)" }}>
          <div className="panel-head"><span style={{ color: "var(--ok)" }}>// Monitoring active</span><span className="tag">{existing.session_id}</span></div>
          <div className="panel-pad">
            <div className="grid g4">
              <Stat label="Target" value={existing.target_host} /><Stat label="Agents" value={existing.agents?.length || 0} /><Stat label="Scenario" value={existing.scenario} /><Stat label="Policy" value={`v${existing.policy?.version}`} />
            </div>
            <p className="snip" style={{ marginTop: 12 }}>Ownership: {existing.proof?.method} · {existing.proof?.privilege} · credentials stored: <b style={{ color: "var(--ok)" }}>NO</b></p>
            {created && (
              <div style={{ marginTop: 12, padding: 12, border: "1px solid var(--warn)", background: "rgba(255,176,32,.05)" }}>
                <div className="mono-label" style={{ color: "var(--warn)" }}>ONE-TIME SENSOR ENROLLMENT SECRET — COPY NOW</div>
                <div className="snip brk" style={{ marginTop: 7 }}>SENTINEL_SESSION_ID={created.session.session_id}<br />SENTINEL_GATEWAY_TOKEN={created.gateway_token}</div>
                <p className="snip" style={{ marginTop: 6 }}>This token is stored only as SHA-256 on the server. It will not be shown again.</p>
              </div>
            )}
            <div className="row wrap" style={{ marginTop: 14 }}><button className="btn btn-primary" onClick={() => nav("/app/command")}>Enter Command Center →</button></div>
          </div>
        </div>
      )}

      {!existing && <>
        <div className="grid g2" style={{ marginTop: 16, gridTemplateColumns: "1.1fr .9fr", alignItems: "start" }}>
          <div className="panel ticked">
            <div className="panel-head"><span>1 · Target, objective &amp; agents</span><span className="tag">required</span></div>
            <div className="panel-pad" style={{ display: "grid", gap: 13 }}>
              <Field label="Monitoring target URL / host"><input className="input" value={target} onChange={(event) => { setTarget(event.target.value); setChallenge(null); }} placeholder="https://agents.your-company.com" /></Field>
              <Field label="Declared objective"><textarea className="input" rows="3" value={objective} onChange={(event) => setObjective(event.target.value)} placeholder="Read project documentation and summarize architecture; never transmit protected files." /></Field>
              <div className="mono-label">REGISTERED AGENT IDENTITIES + PROCESSES</div>
              {agents.map((agent, index) => <div key={index} className="grid" style={{ gridTemplateColumns: "1fr 1fr 90px 34px", gap: 7 }}><input className="input" value={agent.id} onChange={(event) => patchAgent(index, { id: event.target.value })} placeholder="agent-id" /><input className="input" value={agent.process} onChange={(event) => patchAgent(index, { process: event.target.value })} placeholder="process (python.exe)" /><input className="input" value={agent.pid} onChange={(event) => patchAgent(index, { pid: event.target.value })} placeholder="PID opt." /><button className="btn btn-sm" onClick={() => setAgents((items) => items.filter((_, current) => current !== index))}>×</button></div>)}
              <button className="btn btn-sm" onClick={() => setAgents((items) => [...items, emptyAgent()])}>+ Register agent</button>
              <div><span className="mono-label">Scenario posture</span><div className="row wrap" style={{ marginTop: 7 }}>{["testing", "production"].map((value) => <button className="chip" key={value} onClick={() => setScenario(value)} style={{ cursor: "pointer", borderColor: scenario === value ? "var(--acid)" : "var(--line-hard)", color: scenario === value ? "var(--acid)" : "var(--ink-dim)" }}>{value === "testing" ? "TESTING · aggressive intervention" : "PRODUCTION · disruption-aware"}</button>)}</div></div>
            </div>
          </div>

          <div className="panel ticked">
            <div className="panel-head"><span>2 · Capability manifest</span><span className="tag">least privilege</span></div>
            <div className="panel-pad" style={{ display: "grid", gap: 12 }}>
              <Field label="Allowed file globs"><textarea className="input" rows="4" value={allowedFiles} onChange={(event) => setAllowedFiles(event.target.value)} /></Field>
              <Field label="Allowed tools"><textarea className="input" rows="4" value={allowedTools} onChange={(event) => setAllowedTools(event.target.value)} /></Field>
              <Field label="Allowed destinations (exact host or *.subdomain)"><textarea className="input" rows="3" value={allowedHosts} onChange={(event) => setAllowedHosts(event.target.value)} placeholder={"api.openai.com\n*.your-company.com"} /></Field>
            </div>
          </div>
        </div>

        <div className="panel ticked" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>3 · Custom security rules</span><span className="tag">optional JSON file</span></div>
          <div className="panel-pad">
            <p className="snip">Upload organization policy changes as JSON. You may add CUSTOM-* rules, tighten or edit baseline rules, and disable only non-floor rules. The backend rejects any attempt to remove or weaken a protected floor rule.</p>
            <div className="row wrap center" style={{ marginTop: 12 }}>
              <input key={rulesInputKey} className="input grow" type="file" accept=".json,application/json" onChange={uploadRules} disabled={busy === "rules"} />
              <button className="btn btn-sm" type="button" onClick={downloadRulesTemplate}>Download template</button>
              {rulesFile && <button className="btn btn-sm" type="button" onClick={removeRulesFile}>Remove</button>}
            </div>
            {busy === "rules" && <p className="snip" style={{ marginTop: 10 }}>Validating rules against the backend policy compiler…</p>}
            {rulesFile && <div style={{ marginTop: 12, padding: 12, border: "1px solid var(--ok)", background: "rgba(61,220,151,.05)" }}><div className="mono-label" style={{ color: "var(--ok)" }}>RULE FILE VALIDATED</div><div className="snip brk" style={{ marginTop: 6 }}>{rulesFile.name} · {rulesFile.count} accepted rule{rulesFile.count === 1 ? "" : "s"}</div></div>}
          </div>
        </div>

        <div className="panel ticked" style={{ marginTop: 16 }}>
          <div className="panel-head"><span>4 · Real ownership proof</span><span className="tag">credentials used once · never stored</span></div>
          <div className="panel-pad">
            <div className="row wrap">{[["http_token", "HTTPS token"], ["ssh_token", "SSH token file"], ["ssh_privileged", "SSH root / sudo"], ["database_token", "DB token row"], ["database_privileged", "DB admin"]].map(([key, label]) => <button key={key} className="chip" onClick={() => setMethod(key)} style={{ cursor: "pointer", borderColor: method === key ? "var(--acid)" : "var(--line-hard)", color: method === key ? "var(--acid)" : "var(--ink-dim)" }}>{label}</button>)}</div>
            <button className="btn btn-sm" style={{ marginTop: 12 }} onClick={issueToken} disabled={busy === "challenge"}>{busy === "challenge" ? "Issuing…" : challenge ? "Reissue challenge" : "Issue single-use challenge"}</button>

            {challenge && <div style={{ marginTop: 12, padding: 12, border: "1px solid var(--line-hard)", background: "var(--bg)" }}><div className="mono-label" style={{ color: "var(--acid)" }}>TOKEN · SHOWN ONCE · EXPIRES IN 10 MINUTES</div><div className="snip brk" style={{ marginTop: 6, color: "var(--ink)" }}>{challenge.token}</div><div className="snip" style={{ marginTop: 8 }}>HTTPS: publish exact token at <b>{challenge.locations.http_url}</b><br />SSH: write exact token to <b>{challenge.locations.ssh_path}</b><br />Database: create <b>{challenge.locations.database.table}</b> and insert the token.</div></div>}

            {method === "http_token" && <p className="snip" style={{ marginTop: 12 }}>SENTINEL performs a real GET against the exact target origin. Redirects are refused; HTTP 200 and exact token content are required.</p>}
            {method.startsWith("ssh_") && <div className="grid g2" style={{ marginTop: 12 }}><Field label="SSH host"><input className="input" value={ssh.host} onChange={(event) => setSsh({ ...ssh, host: event.target.value })} /></Field><Field label="Port"><input className="input" value={ssh.port} onChange={(event) => setSsh({ ...ssh, port: event.target.value })} /></Field><Field label="Username"><input className="input" value={ssh.username} onChange={(event) => setSsh({ ...ssh, username: event.target.value })} /></Field><Field label="Password (request memory only)"><input className="input" type="password" value={ssh.password} onChange={(event) => setSsh({ ...ssh, password: event.target.value })} /></Field><Field label="Private key instead of password"><textarea className="input" rows="4" value={ssh.private_key} onChange={(event) => setSsh({ ...ssh, private_key: event.target.value })} /></Field><div><Field label="Host-key SHA256 fingerprint"><input className="input" value={ssh.host_key_sha256} onChange={(event) => setSsh({ ...ssh, host_key_sha256: event.target.value })} placeholder="SHA256:…" /></Field><label className="row center" style={{ marginTop: 8 }}><input type="checkbox" checked={ssh.trust_on_first_use} onChange={(event) => setSsh({ ...ssh, trust_on_first_use: event.target.checked })} /><span className="snip">Allow one-time unknown host key (less strict)</span></label></div></div>}
            {method.startsWith("database_") && <div className="grid g2" style={{ marginTop: 12 }}><Field label="Engine"><select className="input" value={db.engine} onChange={(event) => setDb({ ...db, engine: event.target.value, port: event.target.value === "postgresql" ? "5432" : "3306" })}><option value="postgresql">PostgreSQL</option><option value="mysql">MySQL / MariaDB</option></select></Field><Field label="DB host"><input className="input" value={db.host} onChange={(event) => setDb({ ...db, host: event.target.value })} /></Field><Field label="Port"><input className="input" value={db.port} onChange={(event) => setDb({ ...db, port: event.target.value })} /></Field><Field label="Database"><input className="input" value={db.database} onChange={(event) => setDb({ ...db, database: event.target.value })} /></Field><Field label="Username"><input className="input" value={db.username} onChange={(event) => setDb({ ...db, username: event.target.value })} /></Field><Field label="Password (request memory only)"><input className="input" type="password" value={db.password} onChange={(event) => setDb({ ...db, password: event.target.value })} /></Field></div>}

            <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={start} disabled={!challenge || busy === "start"}>{busy === "start" ? "Verifying target + compiling policy…" : "Verify ownership & start monitoring →"}</button>
            {err && <div className="snip" style={{ marginTop: 10, color: "var(--alert)" }}>✕ {err}</div>}
          </div>
        </div>
      </>}
    </div>
  );
}

function Field({ label, children }) { return <label className="fld"><span>{label}</span>{children}</label>; }
function Stat({ label, value }) { return <div className="panel panel-pad"><div className="mono-label">{label}</div><div className="snip brk" style={{ color: "var(--ink)", marginTop: 7 }}>{value}</div></div>; }
function SetupRail({ step }) { const labels = ["Target", "Manifest", "Policy", "Ownership", "Monitoring"]; return <div className="liveflow-rail" style={{ border: "1px solid var(--line-hard)", padding: 12 }}>{labels.map((label, index) => <div className="liveflow-stage" key={label}><span className="liveflow-dot" style={{ background: index + 1 < step ? "var(--ok)" : index + 1 === step ? "var(--acid)" : "var(--line-hard)", boxShadow: index + 1 === step ? "0 0 0 4px rgba(198,255,58,.15)" : "none" }} /><span style={{ color: index + 1 <= step ? "var(--ink)" : "var(--ink-faint)" }}>{index + 1}. {label}</span>{index < labels.length - 1 && <span className="liveflow-arrow">→</span>}</div>)}</div>; }
function buildScopes(tools) { const output = {}; for (const tool of tools) { if (tool === "send_email" || tool === "transmit" || tool === "upload" || tool === "http_post") output[tool] = ["transmit"]; else if (tool === "delete_file" || tool === "delete") output[tool] = ["delete"]; else if (tool === "modify_permissions" || tool === "chmod") output[tool] = ["modify_permissions"]; else if (tool === "run_shell") output[tool] = ["shell"]; else output[tool] = ["read"]; } return output; }
