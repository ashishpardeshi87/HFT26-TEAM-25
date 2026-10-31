import { useEffect, useState } from "react";
import { darkguardApi as api } from "../../lib/darkguardApi.js";
import { useToast } from "../../lib/ui.jsx";

const splitList = (s) => (s || "").split(",").map((x) => x.trim()).filter(Boolean);

export default function Assets() {
  const toast = useToast();
  const [assets, setAssets] = useState([]);
  const [loadError, setLoadError] = useState("");
  const [f, setF] = useState({ companyName: "", primaryDomain: "", brands: "", emails: "" });

  const load = async () => {
    try {
      const { assets: upstreamAssets } = await api("/assets");
      setAssets(upstreamAssets || []);
      setLoadError("");
    } catch (error) {
      setAssets([]);
      setLoadError(error.message || "Monitoring profiles are unavailable.");
    }
  };
  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!f.companyName.trim()) return toast("Company name required", "warn");
    try {
      await api("/assets", { method: "POST", body: {
        companyName: f.companyName.trim(),
        primaryDomain: f.primaryDomain.trim() || undefined,
        brands: splitList(f.brands), emails: splitList(f.emails), execNames: [],
      }});
      setF({ companyName: "", primaryDomain: "", brands: "", emails: "" });
      toast("Profile saved", "ok");
      load();
    } catch (e) { toast(e.message, "error"); }
  };

  const set = (k) => (e) => setF((cur) => ({ ...cur, [k]: e.target.value }));

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Assets</div>
          <h1 className="display">Monitoring profiles</h1>
          <p>Define what we hunt for — companies, domains, brands, emails.</p>
        </div>
      </div>

      {loadError && (
        <div className="banner" style={{ marginBottom: 16, borderColor: "var(--alert)", color: "var(--alert)" }}>
          <span>// Monitoring profiles unavailable: {loadError}</span>
        </div>
      )}

      <div className="grid g2">
        <div className="panel">
          <div className="panel-head"><span>// Add profile</span></div>
          <div className="panel-pad">
            <label className="fld"><span>Company name</span><input className="input" value={f.companyName} onChange={set("companyName")} placeholder="Acme Inc" /></label>
            <label className="fld"><span>Primary domain</span><input className="input" value={f.primaryDomain} onChange={set("primaryDomain")} placeholder="acme.com" /></label>
            <label className="fld"><span>Brands (comma separated)</span><input className="input" value={f.brands} onChange={set("brands")} placeholder="Acme, AcmePay" /></label>
            <label className="fld"><span>Emails (comma separated)</span><input className="input" value={f.emails} onChange={set("emails")} placeholder="admin@acme.com" /></label>
            <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={add}>Save profile</button>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span>Your profiles</span><span className="tag">{assets.length}</span></div>
          <div className="panel-pad">
            {assets.length === 0 ? <div className="empty">{loadError ? "Profiles could not be loaded." : "No profiles yet."}</div> : assets.map((a) => (
              <div key={a.id} style={{ borderBottom: "1px solid var(--line)", padding: "12px 0" }}>
                <b>{a.companyName}</b> <span className="muted">{a.primaryDomain || ""}</span>
                {a.brands?.length > 0 && <div className="chips">{a.brands.map((b, i) => <span className="chip" key={i}>{b}</span>)}</div>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
