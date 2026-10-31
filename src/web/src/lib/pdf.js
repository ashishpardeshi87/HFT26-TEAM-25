import { jsPDF } from "jspdf";
import { autoTable } from "jspdf-autotable";

const INK = [20, 20, 22];
const ACID = [150, 190, 30];
const ALERT = [200, 50, 45];
const MUTE = [120, 120, 115];

const SEV_RGB = {
  critical: [255, 69, 58], high: [255, 176, 32], medium: [76, 201, 240], low: [61, 220, 151], info: [141, 141, 133],
};

const fmt = (d) => { try { return new Date(d + "Z").toLocaleString(); } catch { return d; } };
const countBy = (arr, k) => arr.reduce((a, x) => { const v = x[k] || "other"; a[v] = (a[v] || 0) + 1; return a; }, {});

// Build a detailed PDF threat report. `images` = [{ title, dataUrl }].
export function generateScanReport(scan, images = []) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;
  let y = 0;

  // ---- Header band ----
  doc.setFillColor(10, 10, 11);
  doc.rect(0, 0, W, 92, "F");
  doc.setFillColor(...ACID);
  doc.rect(M, 30, 12, 12, "F");
  doc.setTextColor(237, 237, 234);
  doc.setFont("courier", "bold");
  doc.setFontSize(20);
  doc.text("DARKGUARD", M + 22, 42);
  doc.setFontSize(9);
  doc.setTextColor(150, 190, 30);
  doc.text("DARK WEB THREAT INTELLIGENCE REPORT", M + 22, 58);
  doc.setTextColor(160, 160, 155);
  doc.setFontSize(8);
  doc.text(`GENERATED ${new Date().toLocaleString()}`, W - M, 42, { align: "right" });
  doc.text(`SCAN ${scan.id?.slice(0, 8) || "—"}`, W - M, 56, { align: "right" });
  y = 120;

  // ---- Target + classification ----
  const findings = scan.findings || [];
  const sev = countBy(findings, "severity");
  const risk = scan.risk_score ?? 0;
  const classification = risk >= 70 ? "CRITICAL" : risk >= 40 ? "ELEVATED" : risk > 0 ? "MODERATE" : "CLEAR";

  doc.setTextColor(...INK);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text("Target:", M, y);
  doc.setFont("courier", "normal");
  doc.text(String(scan.target_url || scan.email || scan.query || "—"), M + 56, y);
  y += 22;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(...MUTE);
  doc.text(`Scanned: ${fmt(scan.created_at)}   ·   Status: ${scan.status}   ·   Engines: ${(scan.engines || []).join(", ") || "—"}`, M, y);
  y += 26;

  // ---- Risk banner ----
  const rc = risk >= 40 ? ALERT : ACID;
  doc.setFillColor(...rc);
  doc.rect(M, y, W - M * 2, 56, "F");
  doc.setTextColor(0, 0, 0);
  doc.setFont("courier", "bold");
  doc.setFontSize(30);
  doc.text(String(risk), M + 16, y + 38);
  doc.setFontSize(11);
  doc.text("/100 RISK", M + 70, y + 38);
  doc.setFontSize(14);
  doc.text(`THREAT LEVEL: ${classification}`, W - M - 16, y + 34, { align: "right" });
  y += 78;

  // ---- Executive summary ----
  section(doc, "EXECUTIVE SUMMARY", M, y); y += 18;
  const stats = scan.stats || {};
  const summaryLines = [
    `This report consolidates findings from breach databases, paste sites, public code`,
    `repositories, public forums and the Tor dark web. A total of ${findings.length} finding(s) were`,
    `identified across ${Object.keys(countBy(findings, "engine")).length} source(s). Severity breakdown: ` +
      `${sev.critical || 0} critical, ${sev.high || 0} high, ${sev.medium || 0} medium, ${sev.low || 0} low.`,
    `Intel sources returned ${stats.intel ?? "—"} item(s); the dark web crawl examined ${stats.crawled ?? "—"} live link(s)` +
      ` and ${stats.blocked ?? 0} item(s) were dropped by the safety filter.`,
  ];
  doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(60, 60, 60);
  summaryLines.forEach((l) => { doc.text(l, M, y); y += 15; });
  y += 10;

  // ---- Scope & methodology ----
  section(doc, "SCOPE & METHODOLOGY", M, y); y += 16;
  const method = [
    `DarkGuard performed a parallel multi-source sweep against the target identifier. Breach`,
    `databases (Have I Been Pwned, XposedOrNot) were queried for known credential exposure;`,
    `public code (GitHub), paste sites and forums were searched for leaked references; and the`,
    `Tor network was crawled via OnionSearch discovery for live .onion exposure. All results were`,
    `de-duplicated, classified by category and scored by severity. Illegal content was dropped`,
    `at source by the safety filter and is excluded from this report.`,
  ];
  doc.setFontSize(9.5); doc.setTextColor(70, 70, 70);
  method.forEach((l) => { doc.text(l, M, y); y += 13; });
  y += 12;

  // ---- Source coverage table ----
  const bySource = countBy(findings, "engine");
  if (Object.keys(bySource).length) {
    section(doc, "SOURCE COVERAGE", M, y); y += 8;
    autoTable(doc, {
      startY: y,
      head: [["SOURCE", "FINDINGS", "TYPE"]],
      body: Object.entries(bySource).map(([s, n]) => [s, String(n), /tor|onion|ahmia|phobos|deeplink|tordex/i.test(s) ? "Dark web" : "Surface / breach DB"]),
      styles: { font: "helvetica", fontSize: 8.5, cellPadding: 5 },
      headStyles: { fillColor: [10, 10, 11], textColor: [198, 255, 58], fontStyle: "bold" },
      margin: { left: M, right: M },
    });
    y = doc.lastAutoTable.finalY + 22;
  }

  // ---- Charts ----
  if (images.length) {
    section(doc, "VISUAL ANALYSIS", M, y); y += 14;
    const imgW = (W - M * 2 - 16) / 2;
    let x = M;
    for (const img of images.slice(0, 2)) {
      try { doc.addImage(img.dataUrl, "PNG", x, y, imgW, imgW * 0.7); } catch { /* skip */ }
      x += imgW + 16;
    }
    y += imgW * 0.7 + 20;
  }

  // ---- Findings table ----
  if (y > 680) { doc.addPage(); y = 50; }
  section(doc, "DETAILED FINDINGS", M, y); y += 8;
  autoTable(doc, {
    startY: y,
    head: [["SEVERITY", "CATEGORY", "DETAIL", "SOURCE"]],
    body: findings.map((f) => [
      (f.severity || "info").toUpperCase(),
      f.category || "—",
      `${f.title || "—"}\n${f.snippet || ""}${f.onion_url ? `\n${f.onion_url}` : ""}`,
      f.engine || "—",
    ]),
    styles: { font: "helvetica", fontSize: 8, cellPadding: 5, textColor: [40, 40, 40], lineColor: [220, 220, 220] },
    headStyles: { fillColor: [10, 10, 11], textColor: [198, 255, 58], fontStyle: "bold", fontSize: 8 },
    columnStyles: { 0: { cellWidth: 64 }, 1: { cellWidth: 70 }, 3: { cellWidth: 80 } },
    didParseCell: (data) => {
      if (data.section === "body" && data.column.index === 0) {
        const c = SEV_RGB[(findings[data.row.index]?.severity) || "info"] || MUTE;
        data.cell.styles.textColor = c; data.cell.styles.fontStyle = "bold";
      }
    },
    margin: { left: M, right: M },
  });
  y = doc.lastAutoTable.finalY + 24;

  // ---- Recommendations ----
  if (y > 700) { doc.addPage(); y = 50; }
  section(doc, "RECOMMENDATIONS", M, y); y += 18;
  const recs = buildRecommendations(sev, scan);
  doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(50, 50, 50);
  recs.forEach((r) => {
    doc.setTextColor(...ACID); doc.text(">", M, y);
    doc.setTextColor(50, 50, 50);
    const lines = doc.splitTextToSize(r, W - M * 2 - 16);
    doc.text(lines, M + 14, y); y += 14 * lines.length + 4;
  });

  // ---- Footer on every page ----
  const pages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setDrawColor(220, 220, 220); doc.line(M, 808, W - M, 808);
    doc.setFont("courier", "normal"); doc.setFontSize(7); doc.setTextColor(...MUTE);
    doc.text("DARKGUARD // CONFIDENTIAL — Authorized monitoring only", M, 820);
    doc.text(`Page ${i} / ${pages}`, W - M, 820, { align: "right" });
  }

  doc.save(`darkguard-report-${(scan.target_url || scan.query || "scan").replace(/[^a-z0-9]/gi, "_")}.pdf`);
}

function section(doc, title, x, y) {
  doc.setFillColor(...ACID); doc.rect(x, y - 9, 4, 12, "F");
  doc.setFont("courier", "bold"); doc.setFontSize(11); doc.setTextColor(20, 20, 22);
  doc.text(title, x + 12, y);
}

function buildRecommendations(sev, scan) {
  const r = [];
  if (sev.critical) r.push("CRITICAL: Force-reset credentials for all exposed accounts immediately and enable MFA. Assume passwords in these breaches are compromised.");
  if (scan.email) r.push("Notify the affected user and monitor the email for targeted phishing following these exposures.");
  if (sev.high) r.push("Review high-severity breaches and rotate any shared or reused secrets across systems.");
  r.push("Enroll affected domains and emails in continuous monitoring to detect new exposures as they surface.");
  r.push("Search internal systems and code repositories for reuse of any leaked credentials or API keys.");
  if (!sev.critical && !sev.high) r.push("No critical exposure detected. Maintain continuous monitoring and periodic re-scans.");
  return r;
}
