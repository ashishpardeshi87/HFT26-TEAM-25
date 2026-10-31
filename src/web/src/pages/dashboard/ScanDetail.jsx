import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../../lib/api.js";
import ScanResults from "../../components/ScanResults.jsx";

const fmt = (d) => { try { return new Date(d + "Z").toLocaleString(); } catch { return d; } };

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api(`/scans/${id}`).then(({ scan }) => setScan(scan)).catch((e) => setErr(e.message));
  }, [id]);

  if (err) return <div className="empty">{err}</div>;
  if (!scan) return <div className="empty">Loading…</div>;

  return (
    <div>
      <Link to="/app/scans" className="backlink">← All scans</Link>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Scan report</div>
          <h1 className="display brk" style={{ fontSize: "1.6rem" }}>{scan.target_url || scan.query}</h1>
          <p>{scan.summary || ""} · {fmt(scan.created_at)}</p>
          {scan.keywords?.length > 0 && (
            <div className="chips">{scan.keywords.map((k, i) => <span className="chip" key={i}>{k}</span>)}</div>
          )}
        </div>
        <span className={`pill pill-${scan.status}`}>{scan.status}</span>
      </div>
      <ScanResults scan={scan} />
    </div>
  );
}
