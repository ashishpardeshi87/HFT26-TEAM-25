import { jsPDF } from "jspdf";
import { autoTable } from "jspdf-autotable";

const ACID = [150, 190, 30];
const ALERT = [200, 50, 45];
const INK = [20, 20, 22];
const MUTE = [120, 120, 115];
const SEV_RGB = { critical: [255, 69, 58], high: [255, 176, 32], medium: [76, 201, 240], low: [61, 220, 151], info: [141, 141, 133] };

// Build a branded PDF from a DarkGuard OSINT investigation object.
export function generateOsintReport(inv) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;
  let y = 0;

  const target = inv.target?.domain || inv.target?.email || inv.target?.keyword || "—";
  const risk = inv.risk?.score ?? inv.risk_score ?? 0;
  const level = inv.risk?.level ?? inv.risk_level ?? "—";
  const findings = inv.findings || [];

  // Header band
  doc.setFillColor(10, 10, 11); doc.rect(0, 0, W, 92, "F");
  doc.setFillColor(...ACID); doc.rect(M, 30, 12, 12, "F");
  doc.setTextColor(237, 237, 234); doc.setFont("courier", "bold"); doc.setFontSize(20);
  doc.text("DARKGUARD", M + 22, 42);
  doc.setFontSize(9); doc.setTextColor(150, 190, 30);
  doc.text("OSINT INCIDENT-RESPONSE INVESTIGATION", M + 22, 58);
  doc.setTextColor(160, 160, 155); doc.setFontSize(8);
  doc.text(`GENERATED ${new Date().toLocaleString()}`, W - M, 42, { align: "right" });
  doc.text(`ID ${(inv.id || "—").slice(0, 8)}`, W - M, 56, { align: "right" });
  y = 120;

  doc.setTextColor(...INK); doc.setFont("helvetica", "bold"); doc.setFontSize(16);
  doc.text("Target:", M, y);
  doc.setFont("courier", "normal"); doc.text(String(target), M + 56, y); y += 26;

  // Risk banner
  const rc = risk >= 40 ? ALERT : ACID;
  doc.setFillColor(...rc); doc.rect(M, y, W - M * 2, 54, "F");
  doc.setTextColor(0, 0, 0); doc.setFont("courier", "bold"); doc.setFontSize(28);
  doc.text(String(risk), M + 16, y + 36);
  doc.setFontSize(11); doc.text("/100 RISK", M + 64, y + 36);
  doc.setFontSize(14); doc.text(`THREAT LEVEL: ${level}`, W - M - 16, y + 33, { align: "right" });
  y += 76;

  section(doc, "FINDINGS", M, y); y += 6;
  autoTable(doc, {
    startY: y,
    head: [["SEVERITY", "CATEGORY", "DETAIL", "SOURCE"]],
    body: findings.map((f) => [(f.severity || "info").toUpperCase(), (f.category || "—").replace(/_/g, " "), `${f.title || "—"}\n${f.snippet || ""}`, f.engine || "—"]),
    styles: { font: "helvetica", fontSize: 8, cellPadding: 4, textColor: [40, 40, 40] },
    headStyles: { fillColor: [10, 10, 11], textColor: [198, 255, 58], fontStyle: "bold" },
    columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 80 }, 3: { cellWidth: 70 } },
    didParseCell: (d) => { if (d.section === "body" && d.column.index === 0) { d.cell.styles.textColor = SEV_RGB[(findings[d.row.index]?.severity) || "info"] || MUTE; d.cell.styles.fontStyle = "bold"; } },
    margin: { left: M, right: M },
  });
  y = doc.lastAutoTable.finalY + 22;

  if (inv.attack?.length) {
    if (y > 660) { doc.addPage(); y = 50; }
    section(doc, "MITRE ATT&CK", M, y); y += 6;
    autoTable(doc, {
      startY: y,
      head: [["TECHNIQUE", "NAME", "TACTIC"]],
      body: inv.attack.map((a) => [a.id, a.name, a.tactic]),
      styles: { font: "helvetica", fontSize: 8.5, cellPadding: 4 },
      headStyles: { fillColor: [10, 10, 11], textColor: [181, 108, 255], fontStyle: "bold" },
      margin: { left: M, right: M },
    });
    y = doc.lastAutoTable.finalY + 22;
  }

  if (inv.recommendations?.length) {
    if (y > 680) { doc.addPage(); y = 50; }
    section(doc, "PRIORITIZED REMEDIATION", M, y); y += 16;
    doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(50, 50, 50);
    for (const r of inv.recommendations) {
      doc.setTextColor(...ACID); doc.text(r.priority || ">", M, y);
      doc.setTextColor(50, 50, 50);
      const lines = doc.splitTextToSize(r.text || String(r), W - M * 2 - 30);
      doc.text(lines, M + 30, y); y += 14 * lines.length + 4;
      if (y > 770) { doc.addPage(); y = 50; }
    }
  }

  const pages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i); doc.setDrawColor(220, 220, 220); doc.line(M, 808, W - M, 808);
    doc.setFont("courier", "normal"); doc.setFontSize(7); doc.setTextColor(...MUTE);
    doc.text("DARKGUARD // CONFIDENTIAL — authorized monitoring only · darkguard.csbc.co.in", M, 820);
    doc.text(`Page ${i}/${pages}`, W - M, 820, { align: "right" });
  }

  doc.save(`darkguard-osint-${String(target).replace(/[^a-z0-9]/gi, "_")}.pdf`);
}

function section(doc, title, x, y) {
  doc.setFillColor(...ACID); doc.rect(x, y - 9, 4, 12, "F");
  doc.setFont("courier", "bold"); doc.setFontSize(11); doc.setTextColor(20, 20, 22);
  doc.text(title, x + 12, y);
}
