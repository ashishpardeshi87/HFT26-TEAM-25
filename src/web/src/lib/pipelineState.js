// ── Pipeline state reducer ──────────────────────────────────────────────────
//
// Turns the investigation's raw log stream into per-stage status and counts for
// the pipeline canvas.
//
// Kept as plain JS, separate from the PipelineFlow component, for two reasons:
// it is pure logic with no React dependency, and it is the part that can silently
// be WRONG — if the backend's log format drifts, the canvas would keep rendering
// confidently incorrect stage states. Isolating it makes it directly testable
// (scripts/test-pipeline-parse.mjs asserts it against real captured output).

export const PHASES = [
  { id: "breach",  n: 1, label: "Breach Attribution", sub: "HIBP · XposedOrNot" },
  { id: "secrets", n: 2, label: "Leaked Secrets",     sub: "GitHub · Pastes" },
  { id: "infra",   n: 3, label: "Infrastructure",     sub: "DNS · TLS · Ports" },
  { id: "brand",   n: 4, label: "Brand Abuse",        sub: "Typosquat DNS" },
  { id: "darkweb", n: 5, label: "Dark Web Exposure",  sub: "Ahmia · IntelX" },
];

// Strip the "[hh:mm:ss xm] LEVEL " prefix osint.js writes.
const body = (line) => String(line).replace(/^\[[^\]]*\]\s*\w*\s*/, "");

export function derive(logs = [], { status, findings = [], pathStats, risk } = {}) {
  const state = {
    seed: "idle", classifier: "idle", correlate: "idle", report: "idle",
    counts: {}, skips: {}, sources: {},
  };
  for (const p of PHASES) state[p.id] = "idle";

  let current = null;
  let sawCorrelate = false;
  let sawComplete = false;

  for (const raw of logs) {
    const t = body(raw);

    if (/^DARKGUARD INCIDENT-RESPONSE INVESTIGATION/i.test(t)) { state.seed = "done"; continue; }

    // Phase header: "[3/5] INFRASTRUCTURE FOOTPRINT"
    const ph = t.match(/^\[(\d)\/5\]/);
    if (ph) {
      const idx = Number(ph[1]) - 1;
      // Anything before the newly-started phase has finished.
      for (let i = 0; i < idx; i++) if (state[PHASES[i].id] === "running") state[PHASES[i].id] = "done";
      current = PHASES[idx]?.id ?? null;
      if (current) state[current] = "running";
      continue;
    }

    if (/^ATTACK PATH CORRELATION/i.test(t)) {
      for (const p of PHASES) if (state[p.id] === "running") state[p.id] = "done";
      state.classifier = "done";
      state.correlate = "running";
      sawCorrelate = true;
      continue;
    }

    if (/^INVESTIGATION COMPLETE/i.test(t)) { sawComplete = true; continue; }

    // Source result: "  GitHub — code, configs & secrets: 2 finding(s)."
    const res = t.match(/^\s*(.+?):\s*(\d+)\s+finding\(s\)/);
    if (res && current) {
      state.counts[current] = (state.counts[current] || 0) + Number(res[2]);
      (state.sources[current] ||= []).push({ label: res[1].trim(), n: Number(res[2]) });
      continue;
    }

    // Skipped source: "  Paste sites — PSBDMP: skipped (ENOTFOUND)."
    const sk = t.match(/^\s*(.+?):\s*skipped/);
    if (sk && current) {
      state.skips[current] = (state.skips[current] || 0) + 1;
      (state.sources[current] ||= []).push({ label: sk[1].trim(), n: null });
      continue;
    }

    // The perimeter scan reports a shaped summary rather than a finding count.
    const inf = t.match(/Resolved (\d+) IP\(s\), (\d+) subdomain\(s\), (\d+) open port\(s\)/);
    if (inf) {
      state.counts.infra = (state.counts.infra || 0) + Number(inf[3]);
      (state.sources.infra ||= []).push({
        label: `${inf[1]} IP · ${inf[2]} sub · ${inf[3]} port`,
        n: Number(inf[3]),
      });
    }
  }

  state.classifiedCount = findings.filter((f) => f.classifier).length;
  state.abstainedCount = findings.filter((f) => f.ai?.belowFloor).length;

  // ── Terminal states ──────────────────────────────────────────────────────
  if (status === "failed") {
    for (const k of ["seed", ...PHASES.map((p) => p.id), "classifier", "correlate", "report"]) {
      if (state[k] === "running") state[k] = "failed";
    }
    return state;
  }

  if (sawComplete || status === "completed") {
    for (const p of PHASES) if (state[p.id] !== "idle") state[p.id] = "done";
    state.seed = "done";
    state.classifier = "done";
    state.correlate = sawCorrelate ? "done" : "idle";
    state.report = "done";
    // Draw the eye to a correlation that actually produced chains.
    if (pathStats?.chainsEmitted > 0) state.correlate = "alert";
    if (typeof risk?.score === "number" && risk.score >= 40) state.report = "alert";
  } else if (status === "running") {
    // The classifier runs inside the source phases, so it is live whenever a
    // text-bearing source is live.
    if (PHASES.some((p) => state[p.id] === "running")) state.classifier = "running";
  }

  // A phase that ran, produced nothing, and skipped every source is "skipped",
  // not "done" — the distinction matters when judging coverage.
  for (const p of PHASES) {
    if (state[p.id] === "done" && !state.counts[p.id] && state.skips[p.id]) state[p.id] = "skipped";
  }

  return state;
}
