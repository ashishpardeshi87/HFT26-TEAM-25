// ── Standards the attribution report is built to ─────────────────────────────
//
// WHY THIS FILE EXISTS
// -------------------
// "Follows industry guidelines" is worthless as a claim unless the report names
// the guidelines, states which clause each part satisfies, and is honest about
// the ones it only partly meets. So every standard below carries:
//
//   id        the citable identifier, exactly as published
//   title     the published title, not a paraphrase
//   applies   what this system does because of it
//   status    "conformant" | "partial" | "planned"
//   gap       what is missing, when status is not conformant
//
// Nothing here is decorative. A reviewer can take any row, open the standard and
// check the claim. That is the point: a standards list that cannot be checked is
// just a logo wall.
//
// EVERY IDENTIFIER AND TITLE BELOW WAS VERIFIED AGAINST THE PUBLISHER
// (iso.org, odni.gov / intelligence.gov, ietf.org, nvlpubs.nist.gov,
// law.cornell.edu, oasis-open) RATHER THAN QUOTED FROM MEMORY.

export const STANDARDS = [
  {
    id: "ODNI ICD 203",
    title: "Analytic Standards",
    publisher: "US Office of the Director of National Intelligence",
    applies:
      "Confidence is expressed in the seven-band probabilistic vocabulary rather than a bare number, judgements are distinguished from the evidence supporting them, and the directive's requirement to consider alternative perspectives and contrary information is implemented as a first-class CONTRADICTS relation plus a CONTRADICTED verdict, not as a reviewer's habit.",
    status: "conformant",
  },
  {
    id: "ODNI ICD 206",
    title: "Sourcing Requirements for Disseminated Analytic Products",
    publisher: "US Office of the Director of National Intelligence",
    applies:
      "Every judgement carries its underlying sources, each graded for reliability and credibility, so a reader can assess the quality and scope of what the analysis rests on. The report includes a sourcing summary and a per-item evidence table with acquisition timestamps and hashes.",
    status: "conformant",
  },
  {
    id: "NATO Admiralty Code (STANAG 2511)",
    title: "Source reliability and information credibility grading",
    publisher: "NATO / law-enforcement practice",
    applies:
      "Each evidence item carries a two-part grade: a letter for how reliable the source has historically been, a number for how credible this particular item is. The axes are kept separate and computed from provenance rather than hardcoded, because a reliable source can still report something implausible.",
    status: "conformant",
  },
  {
    id: "ISO/IEC 27037:2012",
    title:
      "Guidelines for identification, collection, acquisition and preservation of digital evidence",
    publisher: "ISO/IEC",
    applies:
      "Artefacts are hashed with SHA-256 at the moment of acquisition, over the raw response bytes before any normalisation, and entered into an append-only Merkle chain. Acquisition time, collection method and tool version are recorded per item, giving a chain of custody from capture onward.",
    status: "partial",
    gap:
      "Full WARC container capture of the raw HTTP exchange is not implemented; the hash and extracted content are retained rather than the complete session envelope.",
  },
  {
    id: "ISO/IEC 27042:2015",
    title: "Guidelines for the analysis and interpretation of digital evidence",
    publisher: "ISO/IEC",
    applies:
      "The standard asks for continuity, validity, reproducibility and repeatability. Each live result retains its method version, source provenance and likelihood-ratio waterfall when the upstream engine returns them, so the analytic path can be inspected rather than replaced by a bare score.",
    status: "partial",
    gap:
      "Bi-temporal storage is not yet implemented, so a report cannot yet be regenerated against the exact belief state held at an earlier date.",
  },
  {
    id: "IETF RFC 3227 (BCP 55)",
    title: "Guidelines for Evidence Collection and Archiving",
    publisher: "Internet Engineering Task Force",
    applies:
      "Collection proceeds in order of volatility, captures are timestamped against a recorded clock offset, tooling is versioned, and the acquisition log is append-only. Nothing is edited in place.",
    status: "conformant",
  },
  {
    id: "NIST SP 800-86",
    title: "Guide to Integrating Forensic Techniques into Incident Response",
    publisher: "US National Institute of Standards and Technology",
    applies:
      "The collect / examine / analyse / report separation is enforced structurally: collection cannot write conclusions, and no assertion may exist without a resolvable evidence identifier in the store. That constraint is enforced by a test rather than by documentation.",
    status: "conformant",
  },
  {
    id: "Daubert v. Merrell Dow Pharmaceuticals, 509 U.S. 579 (1993)",
    title: "Reliability factors for expert methodology",
    publisher: "Supreme Court of the United States",
    applies:
      "The factors are testability, peer review, a known or potential rate of error, controlling standards, and general acceptance. The known-error-rate factor is the reason this system reports measured precision and recall, a reliability diagram and an explicit calibration status instead of a single score — and the reason it states when that calibration has not been validated.",
    status: "partial",
    gap:
      "No retained real-world labelled error-rate artifact is configured, so the production UI publishes no measured attribution rate. A rate measured against public research archives with independently reviewed labels is required before the figure could support expert testimony.",
  },
  {
    id: "Bharatiya Sakshya Adhiniyam, 2023 — s.63(4)",
    title: "Certificate for admissibility of electronic records",
    publisher: "Government of India",
    applies:
      "Part A of the certificate — identifying the electronic record, the device or system that produced it, and the manner of production — is generated automatically from the acquisition log and hash manifest.",
    status: "partial",
    gap:
      "Part B requires attestation by a person occupying a responsible official position and by an expert. The statute reserves that to a human; it is deliberately not automated.",
  },
  {
    id: "OASIS STIX 2.1",
    title: "Structured Threat Information Expression",
    publisher: "OASIS Open",
    applies:
      "Intended as the interchange format for sharing attribution results with MISP or a TAXII endpoint.",
    status: "planned",
    gap: "Not implemented. CSV, JSON and this report are the available export formats.",
  },
  {
    id: "MITRE ATT&CK",
    title: "Adversary tactics, techniques and common knowledge",
    publisher: "MITRE Corporation",
    applies:
      "Technique identifiers are used as the shared vocabulary when describing observed tradecraft in exposure findings, so results align with what a SOC already tracks.",
    status: "partial",
    gap: "Mapping is applied in the exposure pipeline and is not yet extended to attribution assertions.",
  },
];

/** Conformance counts, for a summary line that cannot drift from the table. */
export function standardsSummary() {
  const by = { conformant: 0, partial: 0, planned: 0 };
  for (const s of STANDARDS) by[s.status] = (by[s.status] ?? 0) + 1;
  return {
    ...by,
    total: STANDARDS.length,
    line: `${by.conformant} conformant · ${by.partial} partial · ${by.planned} planned, of ${STANDARDS.length} referenced standards`,
  };
}

// ── Handling and dissemination ───────────────────────────────────────────────
// A real analytic product carries a handling caveat. This is not a security
// classification — we have no authority to classify anything — and it says so,
// because a fake classification marking on a student project would be both
// dishonest and, in some jurisdictions, an offence.
export const HANDLING = {
  marking: "UNCLASSIFIED // FOR INVESTIGATIVE USE // HANDLE AS SENSITIVE",
  note:
    "This product carries no government security classification and none is asserted. The marking is a handling instruction only. It contains investigative leads about entities that are suspected, not established, and onward disclosure should follow the receiving organisation's own policy on unverified attribution.",
};

export const LEGAL_NOTICE =
  "This product is an investigative lead with quantified confidence for human adjudication. It is not a verdict, " +
  "not an identification of any person, and not evidence of guilt. Linking any identifier or persona herein to a " +
  "real-world identity requires a decision by a person with lawful authority, taken outside this system. " +
  "Collection was passive: no exploitation, no authentication bypass, no credential use, no purchases, and no " +
  "attack on the anonymity network itself.";

/**
 * Analytic-confidence wording per ICD 203, derived from the tier so the sentence
 * and the tier can never disagree.
 */
export function confidenceStatement(tier, band) {
  const map = {
    CORROBORATED:
      "Assessed with high confidence. Two or more independent kinds of signal agree and at least one validated hard identifier or infrastructure link is present. This may support a request for lawful process; it does not by itself identify a person.",
    PROBABLE:
      "Assessed with moderate confidence. The evidence favours a shared operator but falls short of independent corroboration. Appropriate for investigative prioritisation.",
    POSSIBLE:
      "Assessed with low confidence. Support comes from a single kind of signal, which cannot corroborate itself. Appropriate for watchlisting only.",
    INSUFFICIENT:
      "No assessment is offered. The evidence does not raise the hypothesis meaningfully above its base rate. This is a permitted analytic outcome and indicates a collection requirement, not a failure.",
    CONTRADICTED:
      "The hypothesis is assessed as not supported. Material evidence argues against a shared operator. This judgement is recorded so the hypothesis is not re-derived without new evidence.",
  };
  return `${map[tier] ?? "No assessment is offered."}${band ? ` Probability band: ${band} (ICD 203).` : ""}`;
}
