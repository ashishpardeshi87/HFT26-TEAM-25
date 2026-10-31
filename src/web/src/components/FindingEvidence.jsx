// ── Finding evidence badges ─────────────────────────────────────────────────
//
// One place that answers "why does this finding say what it says", for every
// finding type. Previously this logic was duplicated between the OSINT table and
// ScanResults, and typosquat evidence was collected but never rendered at all.
//
// Three kinds of evidence, rendered in the order a reader cares about:
//   1. How the verdict was reached  — model score, abstention, or regex fallback
//   2. Why a lookalike was graded   — MX, HTTP, redirect, parking, portfolio
//   3. What was extracted           — IOC counts from a crawled page
//
// Counts, never values: credential pairs, card numbers and payment keys are
// integers here because scraper/app/extract.py never stores the underlying
// strings. Retaining them would make this database a target in its own right.

function Badge({ label, title, color = "var(--info)", dim }) {
  return (
    <span
      className={`aibadge ${dim ? "abstained" : ""}`}
      title={title}
      style={dim ? undefined : { borderColor: color, color }}
    >
      {label}
    </span>
  );
}

// How the classifier reached this verdict.
function ClassifierBadge({ finding: f }) {
  if (f.ai) {
    const t =
      `all-MiniLM-L6-v2 · best match "${f.ai.topCategory}" at cosine ${f.ai.topScore} ` +
      `(abstain floor ${f.ai.floor})` +
      (f.ai.belowFloor ? " — below floor, so this was NOT treated as an exposure" : "") +
      (f.regexOpinion ? ` · regex baseline would have said "${f.regexOpinion.category}"` : "");
    return f.ai.belowFloor
      ? <Badge label={`model abstained ${f.ai.topScore}`} title={t} dim />
      : <Badge label={`model ${f.ai.topScore}`} title={t} />;
  }
  if (f.classifier === "regex-fallback") {
    return <Badge label="regex fallback" title="Model unavailable — the regex cascade produced this verdict" dim />;
  }
  return null;
}

// Why a lookalike domain was graded the way it was.
function TyposquatEvidence({ ev }) {
  if (!ev) return null;
  const out = [];

  if (ev.defensiveRegistration) {
    out.push(["defensive registration", `Redirects to ${ev.redirectsTo} — the brand owner protecting its own namespace, not a threat`, "var(--ok)"]);
  }
  if (ev.brandInTitle) {
    out.push([`brand in title`, `Page title: "${ev.pageTitle}" — presenting itself AS your brand, which is impersonation rather than typo traffic`, "var(--alert)"]);
  }
  if (ev.mx?.length) {
    out.push([`MX ×${ev.mx.length}`, `Accepts mail via ${ev.mx.join(", ")} — mistyped addresses reach this operator, enabling BEC and password-reset interception`, "var(--alert)"]);
  } else if (ev.mx) {
    out.push(["no MX", "Accepts no mail — cannot be used for mail-based attacks in its current state", "var(--ink-dim)"]);
  }
  if (ev.httpStatus) {
    out.push([`HTTP ${ev.httpStatus}`, "Serves a live response over HTTP", ev.httpStatus < 400 ? "var(--warn)" : "var(--ink-dim)"]);
  } else if (ev.httpStatus === null && ev.ips) {
    out.push(["no HTTP", "Resolves in DNS but serves nothing — registered and dormant, weaponizable later", "var(--ink-dim)"]);
  }
  if (ev.redirectsTo && !ev.defensiveRegistration) {
    out.push([`→ ${ev.redirectsTo}`, "Redirects elsewhere — follow this to see who benefits from the traffic", "var(--info)"]);
  }
  if (ev.parkedPage) {
    out.push(["parked", "Serves a parking or for-sale page — registered for resale or typo traffic. Worth acquiring, not escalating", "var(--ink-dim)"]);
  }
  if (ev.sharedIpWithOtherLookalikes) {
    out.push(["portfolio IP", "Shares an identical IP set with other lookalikes in this scan — a squatter's portfolio pattern rather than a campaign aimed at you", "var(--ink-dim)"]);
  }
  // Namespace-saturation note carries counts instead of per-domain evidence.
  if (ev.candidatesTested) {
    out.push([
      `${ev.resolved}/${ev.candidatesTested} registered`,
      `${Math.round(ev.hitRate * 100)}% of generated permutations already resolve — for a well-known brand this is the background rate of squatting, not evidence of targeting`,
      "var(--ink-dim)",
    ]);
  }

  return out.map(([label, title, color]) => <Badge key={label} label={label} title={title} color={color} />);
}

// Indicators extracted from a crawled dark-web page.
function IocEvidence({ iocs, hits }) {
  if (!iocs && !hits?.length) return null;
  const out = [];
  if (hits?.length) out.push([`target named: ${hits.join(", ")}`, "The target's own identifiers appear on the page — this is not a generic listing", "var(--alert)"]);
  if (iocs?.payment_keys) out.push([`${iocs.payment_keys} payment key`, "Live gateway credential — spendable authority over a merchant account. Count only; the value is never stored", "var(--alert)"]);
  if (iocs?.credential_pairs) out.push([`${iocs.credential_pairs} cred pairs`, "Count only — the credentials themselves are never stored", "var(--alert)"]);
  if (iocs?.card_numbers) out.push([`${iocs.card_numbers} card-like`, "Count only — the numbers themselves are never stored", "var(--alert)"]);
  if (iocs?.secrets?.length) out.push([`${iocs.secrets.length} secret`, "API keys or private-key blocks detected", "var(--warn)"]);
  const wallets = (iocs?.btc?.length || 0) + (iocs?.eth?.length || 0) + (iocs?.xmr?.length || 0);
  if (wallets) out.push([`${wallets} wallet`, "Crypto addresses — the payment rail for a listing", "var(--warn)"]);
  if (iocs?.emails?.length) out.push([`${iocs.emails.length} email`, "Extracted addresses", "var(--info)"]);
  if (iocs?.pgp_keys) out.push([`${iocs.pgp_keys} pgp`, "PGP key blocks — vendor identity", "var(--ink-dim)"]);
  return out.map(([label, title, color]) => <Badge key={label} label={label} title={title} color={color} />);
}

export default function FindingEvidence({ finding }) {
  if (!finding) return null;
  const isTypo = finding.category === "typosquat";
  return (
    <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 5, marginLeft: 6, verticalAlign: "middle" }}>
      <ClassifierBadge finding={finding} />
      {isTypo && <TyposquatEvidence ev={finding.evidence} />}
      <IocEvidence iocs={finding.iocs} hits={finding.target_hits} />
    </span>
  );
}
