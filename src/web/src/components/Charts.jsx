import { Chart as ChartJS, ArcElement, BarElement, LineElement, PointElement, CategoryScale, LinearScale, LogarithmicScale, Tooltip, Legend, Filler } from "chart.js";
import { Doughnut, Bar, Line } from "react-chartjs-2";

// LogarithmicScale is needed by the reliability diagram: an open-set prior of
// 1 in 454 puts nearly every posterior below 0.01, and a linear axis collapses
// the whole distribution onto the left edge.
ChartJS.register(ArcElement, BarElement, LineElement, PointElement, CategoryScale, LinearScale, LogarithmicScale, Tooltip, Legend, Filler);

const GRID = "rgba(255,255,255,0.06)";
const TICK = "#8d8d85";
const FONT = { family: "JetBrains Mono", size: 10 };

export function DoughnutChart({ labels = [], data = [], colors = [], showLegend = false }) {
  return (
    <Doughnut
      data={{ labels, datasets: [{ data, backgroundColor: colors, borderColor: "#0a0a0b", borderWidth: 2 }] }}
      options={{
        cutout: "68%",
        plugins: {
          legend: { display: showLegend, position: "bottom", labels: { color: TICK, boxWidth: 9, font: FONT } },
        },
      }}
    />
  );
}

export function BarChart({ labels = [], data = [], color = "#c6ff3a", horizontal = false }) {
  return (
    <Bar
      data={{ labels, datasets: [{ data, backgroundColor: color, borderRadius: 0 }] }}
      options={{
        indexAxis: horizontal ? "y" : "x",
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: TICK, font: FONT }, grid: { color: GRID } },
          y: { ticks: { color: TICK, font: FONT, precision: 0 }, grid: { color: GRID } },
        },
      }}
    />
  );
}

export const SEV_COLORS = {
  critical: "#ff453a", high: "#ffb020", medium: "#4cc9f0", low: "#3ddc97", info: "#8d8d85",
};

export function LineChart({ labels = [], data = [], color = "#c6ff3a" }) {
  return (
    <Line
      data={{
        labels,
        datasets: [{
          data, borderColor: color, backgroundColor: "rgba(198,255,58,0.12)",
          fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2,
        }],
      }}
      options={{
        animation: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: TICK, font: FONT, maxTicksLimit: 6 }, grid: { display: false } },
          y: { ticks: { color: TICK, font: FONT, precision: 0 }, grid: { color: GRID }, beginAtZero: true },
        },
      }}
    />
  );
}

// ── Multi-series variants ───────────────────────────────────────────────────
//
// The three charts above each take ONE series, which is right for the exposure
// views where a single count is the whole story. The evaluation views compare
// series against each other — true pairs against false pairs, an ROC against
// the no-skill diagonal, stated confidence against observed frequency — and a
// comparison drawn as separate charts is not a comparison.

/**
 * Stacked bars. Used for the tier matrix: how true pairs and false pairs
 * distribute across the five verdicts, per scenario.
 *
 * `datasets` is [{ label, data, color }].
 */
export function StackedBarChart({ labels = [], datasets = [], horizontal = false, percent = false }) {
  return (
    <Bar
      data={{
        labels,
        datasets: datasets.map((d) => ({
          label: d.label,
          data: d.data,
          backgroundColor: d.color,
          borderRadius: 0,
          borderWidth: 0,
        })),
      }}
      options={{
        maintainAspectRatio: false,
        indexAxis: horizontal ? "y" : "x",
        plugins: {
          legend: { display: true, position: "bottom", labels: { color: TICK, boxWidth: 9, font: FONT } },
          tooltip: {
            callbacks: {
              label: (c) => `${c.dataset.label}: ${percent ? `${(c.parsed[horizontal ? "x" : "y"] * 100).toFixed(1)}%` : c.formattedValue}`,
            },
          },
        },
        scales: {
          x: {
            stacked: true,
            ticks: { color: TICK, font: FONT },
            grid: { color: GRID },
            ...(percent && horizontal ? { max: 1 } : {}),
          },
          y: {
            stacked: true,
            ticks: { color: TICK, font: FONT },
            grid: { color: GRID },
            ...(percent && !horizontal ? { max: 1 } : {}),
          },
        },
      }}
    />
  );
}

/**
 * Lines over a numeric x axis, for curves whose x values are measurements rather
 * than categories (ROC, reliability). A category scale would space the points
 * evenly and silently distort both.
 *
 * `datasets` is [{ label, points: [{x, y}], color, dashed }].
 */
export function CurveChart({
  datasets = [],
  xLabel = "",
  yLabel = "",
  xMax = 1,
  yMax = 1,
  logX = false,
}) {
  return (
    <Line
      data={{
        datasets: datasets.map((d) => ({
          label: d.label,
          data: d.points,
          borderColor: d.color,
          backgroundColor: "transparent",
          borderDash: d.dashed ? [4, 4] : [],
          borderWidth: d.dashed ? 1 : 2,
          pointRadius: d.points.length <= 24 ? 2.5 : 0,
          pointBackgroundColor: d.color,
          tension: 0,
          fill: false,
        })),
      }}
      options={{
        maintainAspectRatio: false,
        parsing: false,          // data is already {x, y}
        animation: false,
        plugins: {
          legend: { display: true, position: "bottom", labels: { color: TICK, boxWidth: 9, font: FONT } },
          tooltip: {
            callbacks: {
              label: (c) => `${c.dataset.label}  x ${Number(c.parsed.x).toPrecision(3)}  y ${Number(c.parsed.y).toPrecision(3)}`,
            },
          },
        },
        scales: {
          x: {
            type: logX ? "logarithmic" : "linear",
            min: logX ? undefined : 0,
            max: xMax,
            title: { display: !!xLabel, text: xLabel, color: TICK, font: FONT },
            ticks: { color: TICK, font: FONT },
            grid: { color: GRID },
          },
          y: {
            type: "linear",
            min: 0,
            max: yMax,
            title: { display: !!yLabel, text: yLabel, color: TICK, font: FONT },
            ticks: { color: TICK, font: FONT },
            grid: { color: GRID },
          },
        },
      }}
    />
  );
}
