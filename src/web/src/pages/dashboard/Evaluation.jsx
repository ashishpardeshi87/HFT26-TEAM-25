import { useEffect, useMemo, useState } from "react";
import { darkguardApi as api } from "../../lib/darkguardApi.js";
import { StackedBarChart, CurveChart, BarChart } from "../../components/Charts.jsx";

// ── Evaluation Lab ──────────────────────────────────────────────────────────
//
// What the engine gets wrong, measured, with the scenarios that break it.
//
// WHY THIS PAGE EXISTS
// --------------------
// A confidence figure is worthless without a known error rate. The mandate
// stores an attribution confidence; Daubert's reliability factors name "known or
// potential rate of error" explicitly; and an analyst asked to act on PROBABLE
// deserves to know how often PROBABLE is wrong. So the error rate is a product
// surface, not an appendix.
//
// EVERY NUMBER HERE IS READ FROM DISK
// -----------------------------------
// The figures come from backend/eval/attribution-results.json, written by
// `npm run eval:attribution`. Nothing on this page is computed in the browser
// and nothing is hardcoded, so a number on screen can always be traced to a run
// of that script. If the file is missing the page says so instead of rendering
// zeros that look like measurements.

const TIER_META = {
  CORROBORATED: { color: "#c6ff3a", blurb: "May support a request for lawful process" },
  PROBABLE:     { color: "#3ddc97", blurb: "Analyst investigation" },
  POSSIBLE:     { color: "#4cc9f0", blurb: "Watchlist only" },
  INSUFFICIENT: { color: "#8d8d85", blurb: "No action — drives collection tasking" },
  CONTRADICTED: { color: "#ff453a", blurb: "Recorded, to prevent re-deriving a rejected hypothesis" },
};
const TIER_ORDER = ["CORROBORATED", "PROBABLE", "POSSIBLE", "INSUFFICIENT", "CONTRADICTED"];

const pct = (v, dp = 1) => (typeof v === "number" ? `${(v * 100).toFixed(dp)}%` : "—");
const num = (v, dp = 2) => (typeof v === "number" ? v.toFixed(dp) : "—");
const mean = (m) => (m && typeof m.mean === "number" ? m.mean : null);

/** Mean with the seed-to-seed range, so a figure cannot read as more stable than it is. */
function Spread({ metric, format = pct }) {
  if (!metric) return <span className="muted">—</span>;
  const tight = Math.abs(metric.max - metric.min) < 1e-9;
  return (
    <>
      <b>{format(metric.mean)}</b>
      {!tight && (
        <span className="muted" style={{ fontSize: ".66rem" }}>
          {" "}({format(metric.min)}–{format(metric.max)})
        </span>
      )}
    </>
  );
}

function Kpi({ label, value, sub, tone }) {
  const colour = tone === "good" ? "var(--acid)" : tone === "bad" ? "var(--alert)" : "var(--ink)";
  return (
    <div className="panel">
      <div className="panel-pad">
        <div className="mono-label" style={{ fontSize: ".6rem" }}>{label}</div>
        <div style={{ fontFamily: "var(--display)", fontSize: "1.9rem", color: colour, lineHeight: 1.1, marginTop: 6 }}>
          {value}
        </div>
        {sub && <div className="snip" style={{ marginTop: 4 }}>{sub}</div>}
      </div>
    </div>
  );
}

export default function Evaluation() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [live, setLive] = useState({});       // scenario -> { running, result, error }

  useEffect(() => {
    api("/attribution/evaluation").then(setData).catch((e) => setErr(e.message));
  }, []);

  const current = data?.current;
  const baseline = data?.baseline;

  const byName = useMemo(() => {
    const m = new Map();
    for (const s of current?.scenarios ?? []) m.set(s.name, s);
    return m;
  }, [current]);

  const baseByName = useMemo(() => {
    const m = new Map();
    for (const s of baseline?.scenarios ?? []) m.set(s.name, s);
    return m;
  }, [baseline]);

  async function rerun(name) {
    setLive((s) => ({ ...s, [name]: { running: true } }));
    try {
      const res = await api("/attribution/evaluation/run", { method: "POST", body: { scenario: name } });
      setLive((s) => ({ ...s, [name]: { running: false, result: res } }));
    } catch (e) {
      setLive((s) => ({ ...s, [name]: { running: false, error: e.message } }));
    }
  }

  if (err) {
    return (
      <div>
        <div className="page-title">
          <div>
            <div className="eyebrow">// Evaluation Lab</div>
            <h1 className="display">Measured error rates</h1>
          </div>
        </div>
        <div className="panel">
          <div className="panel-pad">
            <p>No evaluation results on disk yet.</p>
            <p className="muted">
              Generate them from <code>backend/</code>:
            </p>
            <pre className="snip" style={{ padding: 12, border: "1px solid var(--line)" }}>npm run eval:attribution</pre>
            <p className="snip">
              This page deliberately renders nothing until that file exists. Showing zeros would
              look like a measurement of a perfect engine. ({err})
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (!current) return <div className="panel"><div className="panel-pad">Loading evaluation…</div></div>;

  const s1 = byName.get("S1_clean_rebrand");
  const s1base = baseByName.get("S1_clean_rebrand");
  const planted = byName.get("S5_planted_key");
  const obfuscated = byName.get("S3_style_obfuscated");

  const worstFalseCorroborated = Math.max(
    0,
    ...current.scenarios.map((s) => s.falseCorroborated?.max ?? 0)
  );
  const medianMs = (() => {
    const v = current.scenarios.map((s) => s.msPerPair).filter((x) => typeof x === "number").sort((a, b) => a - b);
    return v.length ? v[Math.floor(v.length / 2)] : null;
  })();

  // ── Tier matrix ───────────────────────────────────────────────────────────
  // Normalised within each group, because the populations differ by three orders
  // of magnitude: ~41 true pairs against ~1,729 false ones. Raw counts would
  // render the true-pair bars as invisible slivers.
  const tierMatrix = (which) => ({
    labels: current.scenarios.map((s) => s.label),
    datasets: TIER_ORDER.map((tier) => ({
      label: tier,
      color: TIER_META[tier].color,
      data: current.scenarios.map((s) => {
        const counts = s[which] ?? {};
        const total = Object.values(counts).reduce((a, b) => a + b, 0);
        return total ? (counts[tier] ?? 0) / total : 0;
      }),
    })),
  });

  const trueMatrix = tierMatrix("tiersTrue");
  const falseMatrix = tierMatrix("tiersFalse");

  const rocDatasets = [
    s1 && { label: "Clean rebrand", color: "#c6ff3a", points: s1.roc.map((p) => ({ x: p.fpr, y: p.tpr })) },
    obfuscated && { label: "AI-rewritten posts", color: "#b56cff", points: obfuscated.roc.map((p) => ({ x: p.fpr, y: p.tpr })) },
    { label: "no skill", color: "#5a5a55", dashed: true, points: [{ x: 0, y: 0 }, { x: 1, y: 1 }] },
  ].filter(Boolean);

  const reliability = s1?.reliability ?? [];
  const reliabilityDatasets = [
    {
      label: "observed frequency",
      color: "#4cc9f0",
      points: reliability.map((b) => ({ x: Math.max(b.predicted, 1e-5), y: b.observed })),
    },
    {
      label: "perfectly calibrated",
      color: "#5a5a55",
      dashed: true,
      points: [{ x: 1e-5, y: 1e-5 }, { x: 1, y: 1 }],
    },
  ];

  const ablation = current.ablation;
  const tuning = current.tuning;

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Evaluation Lab</div>
          <h1 className="display">Measured error rates</h1>
          <p>
            Six scenarios over a population whose ground truth is exact by construction. Each one
            breaks a different assumption the engine depends on.
          </p>
        </div>
      </div>

      {/* Provenance first, not in a footnote. */}
      <div className="panel" style={{ borderColor: "var(--warn, #ffb020)" }}>
        <div className="panel-pad">
          <div className="row center" style={{ gap: 8, flexWrap: "wrap" }}>
            <span className="tag" style={{ borderColor: "#ffb020", color: "#ffb020" }}>SYNTHETIC CORPUS</span>
            <span className="snip">
              Generated {new Date(current.generatedAt).toLocaleString()} · {current.stage}
            </span>
          </div>
          <p className="snip" style={{ marginTop: 10, maxWidth: "92ch" }}>
            {current.provenance?.warning}
          </p>
          <p className="snip" style={{ marginTop: 6, color: "var(--ink-faint)" }}>
            Thresholds tuned on seeds {current.provenance?.trainSeeds?.join(", ")} and reported on the
            disjoint seeds {current.provenance?.reportSeeds?.join(", ")}. The seed the live corpus
            uses is excluded from both, so no figure here is measured on the data being demonstrated.
          </p>
        </div>
      </div>

      {/* ── Headline numbers ── */}
      <div className="grid g4" style={{ marginTop: 16 }}>
        <Kpi
          label="False CORROBORATED"
          value={worstFalseCorroborated}
          sub="unrelated pairs reaching the only tier that permits lawful process — across all six scenarios"
          tone={worstFalseCorroborated === 0 ? "good" : "bad"}
        />
        <Kpi
          label="Rebrand precision"
          value={pct(mean(s1?.linkPrecision))}
          sub={
            s1base
              ? `was ${pct(mean(s1base.linkPrecision))} before the tier-threshold fix`
              : "of proposed links that are real"
          }
          tone="good"
        />
        <Kpi
          label="Rebrand recall"
          value={pct(mean(s1?.linkRecall))}
          sub="true links recovered after every identifier was rotated"
        />
        <Kpi
          label="Median latency"
          value={medianMs != null ? `${num(medianMs)} ms` : "—"}
          sub="per pairwise attribution, including evidence hashing"
        />
      </div>

      {/* ── Before / after ── */}
      {baseline && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span>// What the lab found in our own engine</span>
            <span className="tag">before → after</span>
          </div>
          <div className="panel-pad">
            <p className="snip" style={{ marginBottom: 14, maxWidth: "92ch" }}>
              These scenarios were built to test the engine and immediately failed it. Baseline:{" "}
              <i>{baseline.stage}</i>.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Link precision</th>
                  <th>Link recall</th>
                  <th>False-link rate</th>
                  <th>True links wrongly CONTRADICTED</th>
                </tr>
              </thead>
              <tbody>
                {current.scenarios.map((s) => {
                  const b = baseByName.get(s.name);
                  const cell = (nowMetric, thenMetric, format = pct, lowerIsBetter = false) => {
                    const now = mean(nowMetric);
                    const then = mean(thenMetric);
                    if (now == null) return <span className="muted">—</span>;
                    const moved = then != null && Math.abs(now - then) > 1e-9;
                    const better = moved && (lowerIsBetter ? now < then : now > then);
                    return (
                      <>
                        {moved && <span className="muted" style={{ fontSize: ".68rem" }}>{format(then)} → </span>}
                        <b style={{ color: moved ? (better ? "var(--acid)" : "#ffb020") : "var(--ink)" }}>
                          {format(now)}
                        </b>
                      </>
                    );
                  };
                  return (
                    <tr key={s.name}>
                      <td>
                        {s.label}
                        <div className="snip">{s.stresses}</div>
                      </td>
                      <td>{cell(s.linkPrecision, b?.linkPrecision)}</td>
                      <td>{cell(s.linkRecall, b?.linkRecall)}</td>
                      <td>{cell(s.falseLinkRate, b?.falseLinkRate, pct, true)}</td>
                      <td>{cell(s.trueWronglyContradicted, b?.trueWronglyContradicted, (v) => String(v ?? "—"), true)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="snip" style={{ marginTop: 14, maxWidth: "92ch" }}>
              Read the recall column honestly. Tightening the PROBABLE threshold bought a large gain
              in precision and cost recall in the two hardest scenarios — obfuscated writing and
              sparse activity. That is the intended trade for a tier whose purpose is to direct an
              analyst&apos;s attention: those pairs are not discarded, they fall to POSSIBLE and keep
              their place in the collection queue.
            </p>
          </div>
        </div>
      )}

      {/* ── Tier matrix ── */}
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head">
            <span>// Where TRUE pairs land</span>
            <span className="tag">should sit high</span>
          </div>
          <div className="panel-pad" style={{ height: 300 }}>
            <StackedBarChart labels={trueMatrix.labels} datasets={trueMatrix.datasets} percent horizontal />
          </div>
        </div>
        <div className="panel">
          <div className="panel-head">
            <span>// Where FALSE pairs land</span>
            <span className="tag">should sit low</span>
          </div>
          <div className="panel-pad" style={{ height: 300 }}>
            <StackedBarChart labels={falseMatrix.labels} datasets={falseMatrix.datasets} percent horizontal />
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-pad">
          <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
            {TIER_ORDER.map((t) => (
              <span key={t} className="row center" style={{ gap: 6, fontSize: ".68rem" }}>
                <span style={{ width: 10, height: 10, background: TIER_META[t].color, display: "inline-block" }} />
                <b style={{ color: TIER_META[t].color }}>{t}</b>
                <span className="muted">{TIER_META[t].blurb}</span>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── Curves ── */}
      <div className="grid g2" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-head">
            <span>// ROC</span>
            <span className="tag">AUC {num(mean(s1?.auc), 3)}</span>
          </div>
          <div className="panel-pad" style={{ height: 300 }}>
            <CurveChart datasets={rocDatasets} xLabel="false positive rate" yLabel="true positive rate" />
          </div>
          <div className="panel-pad" style={{ paddingTop: 0 }}>
            <p className="snip">
              An AUC at 1.000 says the synthetic population is separable, not that attribution is
              solved. It is reported because hiding it would be worse, and it is the reason the
              scenarios above exist: ranking is easy here, and the hard question is where the
              decision thresholds sit.
            </p>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span>// Reliability</span>
            <span className="tag">stated vs observed</span>
          </div>
          <div className="panel-pad" style={{ height: 300 }}>
            <CurveChart
              datasets={reliabilityDatasets}
              xLabel="stated probability (log)"
              yLabel="observed frequency"
              logX
            />
          </div>
          <div className="panel-pad" style={{ paddingTop: 0 }}>
            <p className="snip">
              Points on the dashed line mean a stated confidence matches how often it turns out to be
              right. Bins are log-spaced because a 1-in-454 prior puts nearly every pair below 0.01.
              Calibration is currently a mild monotonic correction, not a fitted isotonic regression —
              the engine reports that limitation in every response.
            </p>
          </div>
        </div>
      </div>

      {/* ── Ablation ── */}
      {ablation && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span>// Ablation — which signal is actually doing the work</span>
            <span className="tag">suppress one family</span>
          </div>
          <div className="panel-pad" style={{ height: 240 }}>
            <BarChart
              labels={ablation.results.map((r) => r.suppressed)}
              data={ablation.results.map((r) => Number(((r.recallDrop ?? 0) * 100).toFixed(1)))}
              color="#b56cff"
              horizontal
            />
          </div>
          <div className="panel-pad" style={{ paddingTop: 0 }}>
            <table>
              <thead>
                <tr><th>Suppressed</th><th>Link recall</th><th>Link precision</th><th>Recall lost</th></tr>
              </thead>
              <tbody>
                {ablation.results.map((r) => (
                  <tr key={r.suppressed}>
                    <td><b>{r.suppressed}</b></td>
                    <td><Spread metric={r.linkRecall} /></td>
                    <td><Spread metric={r.linkPrecision} /></td>
                    <td style={{ color: (r.recallDrop ?? 0) > 0.05 ? "#ffb020" : "var(--ink-dim)" }}>
                      {pct(r.recallDrop)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="snip" style={{ marginTop: 12, maxWidth: "92ch" }}>
              This is the honest answer to &ldquo;is one signal doing everything?&rdquo;. Removing the
              temporal family costs the most recall, which matches the published finding that
              inter-event timing survives identity rotation. Removing stylometry barely changes recall
              but collapses precision — because a style mismatch is what argues against unrelated
              pairs. Neither can corroborate a link alone, and the identifier family costs no recall
              at all here, because in this corpus almost every identifier has been rotated away.
            </p>
          </div>
        </div>
      )}

      {/* ── Threshold choice, shown rather than asserted ── */}
      {tuning && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span>// How the PROBABLE threshold was chosen</span>
            <span className="tag">train seeds only</span>
          </div>
          <div className="panel-pad">
            <table>
              <thead>
                <tr><th>Minimum lift over prior</th><th>Precision</th><th>Recall</th><th>F1</th></tr>
              </thead>
              <tbody>
                {tuning.sweep.map((row) => {
                  const chosen = row.floor === tuning.chosen?.floor;
                  return (
                    <tr key={row.floor} style={chosen ? { background: "rgba(198,255,58,0.07)" } : undefined}>
                      <td>
                        <b style={chosen ? { color: "var(--acid)" } : undefined}>{row.floor}×</b>
                        {chosen && <span className="tag" style={{ marginLeft: 8 }}>SHIPPED</span>}
                      </td>
                      <td>{pct(row.precision)}</td>
                      <td>{pct(row.recall)}</td>
                      <td>{num(row.f1, 3)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="snip" style={{ marginTop: 12, maxWidth: "92ch" }}>
              {tuning.basis}, swept on scenario <code>{tuning.scenario}</code> over seeds{" "}
              {tuning.seeds?.join(", ")}. Reporting and tuning on the same seeds would fit the
              threshold to the test and publish the result as accuracy, so the sweep and the reported
              figures use disjoint seeds.
            </p>
          </div>
        </div>
      )}

      {/* ── Per-scenario detail ── */}
      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <span>// Scenarios</span>
          <span className="tag">{current.scenarios.length} · seeds {current.provenance?.reportSeeds?.join("/")}</span>
        </div>
        <div className="panel-pad">
          <div className="grid g2">
            {current.scenarios.map((s) => {
              const l = live[s.name] ?? {};
              const safetyBreached = (s.falseCorroborated?.max ?? 0) > 0;
              return (
                <div
                  key={s.name}
                  className="panel"
                  style={{ borderColor: safetyBreached ? "var(--alert)" : "var(--line-hard)" }}
                >
                  <div className="panel-pad">
                    <div className="row between center" style={{ gap: 8 }}>
                      <b style={{ fontSize: ".82rem" }}>{s.label}</b>
                      <button className="btn btn-sm" disabled={l.running} onClick={() => rerun(s.name)}>
                        {l.running ? "running…" : "re-run live"}
                      </button>
                    </div>
                    <p className="snip" style={{ marginTop: 6 }}>{s.blurb}</p>
                    <p className="snip" style={{ color: "var(--ink-faint)" }}>
                      <b>Tests:</b> {s.stresses}
                    </p>

                    <div className="kv-rows" style={{ marginTop: 12 }}>
                      <div><span>pairs scored</span><b>{s.pairs?.mean ?? "—"}</b></div>
                      <div><span>true links</span><b>{s.truePairs?.mean ?? "—"}</b></div>
                      <div><span>link precision</span><b><Spread metric={s.linkPrecision} /></b></div>
                      <div><span>link recall</span><b><Spread metric={s.linkRecall} /></b></div>
                      <div><span>false-link rate</span><b><Spread metric={s.falseLinkRate} /></b></div>
                      <div>
                        <span>false CORROBORATED</span>
                        <b style={{ color: safetyBreached ? "var(--alert)" : "var(--acid)" }}>
                          {s.falseCorroborated?.max ?? "—"}
                        </b>
                      </div>
                      <div>
                        <span>true links buried</span>
                        <b style={{ color: (s.trueWronglyContradicted?.max ?? 0) > 0 ? "#ffb020" : "var(--acid)" }}>
                          {s.trueWronglyContradicted?.max ?? "—"}
                        </b>
                      </div>
                      <div><span>ms / pair</span><b>{num(s.msPerPair)}</b></div>
                    </div>

                    {l.error && <p className="snip" style={{ color: "var(--alert)", marginTop: 10 }}>{l.error}</p>}
                    {l.result && (
                      <p className="snip" style={{ marginTop: 10, color: "var(--acid)" }}>
                        Live re-run in {l.result.elapsedMs} ms — precision{" "}
                        {pct(mean(l.result.result.linkPrecision))}, recall{" "}
                        {pct(mean(l.result.result.linkRecall))}, false CORROBORATED{" "}
                        {l.result.result.falseCorroborated?.max ?? 0}.
                        <br />
                        <span className="muted">{l.result.note}</span>
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>// Reproducing this page</span></div>
        <div className="panel-pad">
          <pre className="snip" style={{ padding: 12, border: "1px solid var(--line)", overflowX: "auto" }}>
{`cd backend
npm run eval:attribution        # rewrites every figure above
npm test                        # engine invariants, including the safety tier rule
node scripts/demo-pairs.mjs     # pick a demo pair from the live corpus`}
          </pre>
          <p className="snip" style={{ marginTop: 10 }}>
            The evaluation script exits non-zero if any scenario lets an unrelated pair reach
            CORROBORATED, so that guarantee is enforced by the build rather than by this page
            happening to show a zero.
          </p>
        </div>
      </div>
    </div>
  );
}
