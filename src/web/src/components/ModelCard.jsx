import { useEffect, useState } from "react";
import { darkguardApi as api } from "../lib/darkguardApi.js";

// ── Model card ──────────────────────────────────────────────────────────────
// Shows what the exposure classifier is and how well it actually performs,
// including where it performs badly.
//
// Every figure here is read from backend/eval/results.json, written by
// `npm run eval:classifier`. Nothing is hardcoded, so the panel cannot claim a
// number the evaluation harness did not produce. If the eval has never been run
// the panel says so instead of showing placeholder figures.

const pct = (n) => (typeof n === "number" ? `${(n * 100).toFixed(1)}%` : "—");

export default function ModelCard() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api("/osint/model").then(setData).catch((e) => setErr(e.message));
  }, []);

  if (err) {
    return (
      <div className="panel" style={{ marginTop: 16, borderColor: "var(--alert)" }}>
        <div className="panel-head"><span>// Exposure classifier</span><span className="tag" style={{ color: "var(--alert)" }}>unavailable</span></div>
        <div className="empty">{err}</div>
      </div>
    );
  }
  if (!data) return <div className="panel" style={{ marginTop: 16 }}><div className="empty">Loading classifier status…</div></div>;

  const rt = data.runtime || {};
  const ev = data.evaluation;

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-head">
        <span>// Exposure classifier</span>
        <span className="row center" style={{ gap: 10 }}>
          <span className="tag" style={{ color: rt.loaded ? "var(--ok)" : "var(--warn)" }}>
            {rt.loaded ? "loaded" : "not loaded"}
          </span>
          {ev && (
            <button className="btn btn-sm" onClick={() => setOpen((v) => !v)}>
              {open ? "− detail" : "+ detail"}
            </button>
          )}
        </span>
      </div>

      <div className="panel-pad">
        <div className="row wrap" style={{ gap: 22, marginBottom: ev ? 18 : 0 }}>
          <KV k="Model" v={rt.model || "—"} />
          <KV k="Runtime" v={rt.backend || "—"} />
          {ev && <KV k="Inference" v={`${ev.meanInferenceMs}ms / item · CPU`} />}
          {ev && <KV k="Eval set" v={`${ev.evalSet.size} labelled items`} />}
        </div>

        {!ev ? (
          <div className="empty" style={{ marginTop: 12 }}>
            No evaluation results on disk. Run <code>npm run eval:classifier</code> in <code>backend/</code> to
            generate them — this panel deliberately shows nothing rather than placeholder numbers.
          </div>
        ) : (
          <>
            {/* The metric that drives behaviour: is this an exposure, or not? */}
            <div className="mono-label" style={{ marginBottom: 8 }}>
              Exposure detection · regex baseline → shipped
            </div>
            <table style={{ marginBottom: 4 }}>
              <thead>
                <tr><th>Path</th><th>Precision</th><th>Recall</th><th>F1</th><th>False pos.</th><th>Missed</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td className="muted">regex cascade</td>
                  <td>{pct(ev.exposureDetection.regex.precision)}</td>
                  <td>{pct(ev.exposureDetection.regex.recall)}</td>
                  <td>{pct(ev.exposureDetection.regex.f1)}</td>
                  <td className="muted">{ev.exposureDetection.regex.fp}</td>
                  <td style={{ color: "var(--alert)" }}>{ev.exposureDetection.regex.fn}</td>
                </tr>
                <tr>
                  <td><b>shipped (model)</b></td>
                  <td style={{ color: "var(--acid)" }}><b>{pct(ev.exposureDetection.shipped.precision)}</b></td>
                  <td style={{ color: "var(--acid)" }}><b>{pct(ev.exposureDetection.shipped.recall)}</b></td>
                  <td style={{ color: "var(--acid)" }}><b>{pct(ev.exposureDetection.shipped.f1)}</b></td>
                  <td className="muted">{ev.exposureDetection.shipped.fp}</td>
                  <td style={{ color: "var(--ok)" }}>{ev.exposureDetection.shipped.fn}</td>
                </tr>
              </tbody>
            </table>
            <div className="snip" style={{ marginBottom: 18 }}>
              Recall {pct(ev.exposureDetection.regex.recall)} → {pct(ev.exposureDetection.shipped.recall)} at
              comparable precision. In plain terms: the regex baseline missed{" "}
              <b>{ev.exposureDetection.regex.fn}</b> real exposures out of{" "}
              {ev.exposureDetection.regex.tp + ev.exposureDetection.regex.fn}; the model misses{" "}
              <b>{ev.exposureDetection.shipped.fn}</b>.
            </div>

            {open && (
              <>
                <div className="mono-label" style={{ marginBottom: 8 }}>Five-class detail</div>
                <div className="row wrap" style={{ gap: 22, marginBottom: 18 }}>
                  <KV k="Accuracy" v={`${pct(ev.multiclass.regex.accuracy)} → ${pct(ev.multiclass.shipped.accuracy)}`} />
                  <KV k="Macro F1" v={`${pct(ev.multiclass.regex.macroF1)} → ${pct(ev.multiclass.shipped.macroF1)}`} />
                  <KV k="False criticals" v={`${ev.multiclass.regex.falseCriticals} → ${ev.multiclass.shipped.falseCriticals}`} />
                  <KV k="Abstained" v={`${ev.abstained} / ${ev.evalSet.size}`} />
                </div>

                <table style={{ marginBottom: 18 }}>
                  <thead><tr><th>Class</th><th>F1 (regex)</th><th>F1 (shipped)</th><th>Support</th></tr></thead>
                  <tbody>
                    {Object.keys(ev.multiclass.shipped.per).map((k) => (
                      <tr key={k}>
                        <td className="muted">{k.replace(/_/g, " ")}</td>
                        <td className="muted">{pct(ev.multiclass.regex.per[k]?.f1)}</td>
                        <td style={{ color: "var(--acid)" }}>{pct(ev.multiclass.shipped.per[k]?.f1)}</td>
                        <td className="muted">{ev.multiclass.shipped.per[k]?.support}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* Publishing the weaknesses is the point, not a disclaimer. */}
                <div className="mono-label" style={{ marginBottom: 8, color: "var(--warn)" }}>
                  Known weaknesses
                </div>
                {(ev.knownWeaknesses || []).map((w, i) => (
                  <div key={i} className="snip" style={{ padding: "6px 0", borderBottom: "1px dashed var(--line)" }}>
                    {w}
                  </div>
                ))}

                {!!(ev.exceptions || []).length && (
                  <>
                    <div className="mono-label" style={{ margin: "18px 0 8px" }}>
                      Cases the model still gets wrong
                    </div>
                    {ev.exceptions.map((x, i) => (
                      <div key={i} className="chain-ev">
                        <span className="ix">{x.score ?? "—"}</span>
                        <span className="muted" style={{ flexShrink: 0 }}>
                          {x.trueLabel} → {x.predicted}
                        </span>
                        <span className="brk grow">{x.text}</span>
                      </div>
                    ))}
                  </>
                )}
              </>
            )}

            <div className="snip" style={{ marginTop: 16, color: "var(--ink-faint)" }}>
              {ev.evalSet.note} Evaluated {new Date(ev.generatedAt).toLocaleString()} ·
              regenerate with <code>npm run eval:classifier</code>.
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function KV({ k, v }) {
  return (
    <div>
      <div className="mono-label">{k}</div>
      <div style={{ fontSize: ".84rem", marginTop: 3 }}>{v}</div>
    </div>
  );
}
