import { useState } from "react";

// ── Guide ───────────────────────────────────────────────────────────────────
// Explains what each part of the system does and why it is built that way,
// including the parts that do not work well. Written for someone who has not
// read the design document.

const SECTIONS = [
  {
    id: "problem",
    title: "What problem this solves",
    body: [
      ["The short version", "A threat actor on a Tor hidden service can throw away an identity far more cheaply than an investigator can rebuild a case. When a marketplace is seized, vendors scatter and reappear under new names, and the investigative record restarts from zero. That asymmetry — not encryption — is what makes dark web attribution hard."],
      ["What we do not try to do", "We do not try to name people. A system that outputs an identity cannot be checked, so it is useless in proceedings. We output an evidence set, a probability, a standard confidence band, and the specific evidence that disagrees. That can be interrogated, reproduced, and refuted."],
      ["Two products in one dashboard", "The exposure side (Scans, Findings, Watchtower, OSINT) monitors an organisation's own exposure. The attribution side (Attribution Console) links dark web personas to a single actor. They share collection and safety machinery but answer different questions."],
    ],
  },
  {
    id: "signals",
    title: "The six signals, and what each is worth",
    body: [
      ["Identifier", "PGP fingerprints, cryptocurrency addresses, contact handles. The strongest single signal when it survives, and the only kind that can lift a verdict to CORROBORATED. But identifiers are rotated deliberately, and they can be forged — a vendor may publish a rival's key. So a match is evidence of a link, never proof of identity."],
      ["Infrastructure", "Misconfigured hidden services leak their real origin: status endpoints, TLS certificates, service banners. High precision when it lands, but published work recovers the origin of roughly 5% of services. Expect nothing most of the time; that is the honest base rate, not a defect."],
      ["Temporal", "When someone is awake. We build a histogram of gaps between their events and a 24-hour activity profile, then compare them. This is the signal we trust most under adversarial pressure, because prose can be rewritten but a fabricated sleep cycle cannot be sustained for months without either automation (which looks detectably regular) or real discipline."],
      ["Stylometric", "How someone writes. Strong on clean text, but it degrades toward chance under deliberate obfuscation, which language models have made cheap. It can never establish identity alone."],
      ["Operational", "How someone sells — listing templates, price notation, category mix, product photography. Individually weak, and correlated with writing style, so the fusion stage discounts whichever of the two is weaker."],
      ["Relational", "Who vouches for whom. Useful context and corroboration, rarely decisive."],
    ],
  },
  {
    id: "fusion",
    title: "How the confidence number is produced",
    body: [
      ["Why not a weighted score", "A formula like 0.3 × style + 0.4 × wallet has three fatal problems: the weights cannot be defended when challenged, the output is not a real probability, and evidence pointing the other way has nowhere to go."],
      ["What we do instead", "Each signal reports a likelihood ratio — how much more likely this evidence is if the personas ARE the same actor than if they are not. Ratios add. Evidence against contributes a negative number. Because the comparison is against a coincidence rate, rare evidence automatically counts for more than common evidence, with no weights to tune."],
      ["Starting from the base rate", "Most pairs of personas are unrelated. In our reference pool, about 1 in 450 is a true match, and the calculation starts from that. This is why an absolute probability of 6% can still be a strong lead: it is roughly 26 times the base rate. The console shows that lift next to the probability, because the lift is often the more meaningful number."],
      ["The dependence correction", "Adding correlated ratios as if independent inflates confidence, and aggregate accuracy figures will not reveal it. Writing style correlates with topic; wallet overlap correlates with market membership. So within each correlated group, the strongest signal keeps full weight and the rest are discounted. The waterfall marks discounted rows."],
      ["Calibration, and what we do not claim", "A confidence figure is only reportable once 80% means right-80%-of-the-time. Our fusion already starts from the true base rate, so it is not over-confident the way a balanced-class model is; the correction applied here is a mild one. We have not fitted it on a held-out set, and the console says so rather than claiming an accuracy we did not measure."],
    ],
  },
  {
    id: "reading",
    title: "Reading a verdict",
    body: [
      ["The words are borrowed on purpose", "Confidence is expressed in the ODNI ICD 203 seven-band scale — from 'almost no chance' to 'almost certain'. An analyst already knows what 'likely' means in an intelligence product. Nobody knows what 'score 0.72' means."],
      ["Every source is graded twice", "Each piece of evidence carries an Admiralty grade: a letter for how reliable that source has been historically, and a number for how credible this particular item is. They are kept separate because a reliable source can still report something implausible."],
      ["The tier tells you what you may do", "CORROBORATED may support a request for lawful process, and requires two independent kinds of signal plus one validated hard identifier or infrastructure link. PROBABLE means investigate. POSSIBLE means watchlist only. INSUFFICIENT means collect more — it is a permitted answer, not a failure. CONTRADICTED is recorded so a rejected idea is not quietly re-derived later."],
      ["'Not observable' is not 'disagreed'", "If a persona has four posts, the temporal signal cannot be computed. That is completely different from the temporal signal disagreeing. We record which, and show the reason, because collapsing the two misleads the reader and makes the fused number uninterpretable."],
    ],
  },
  {
    id: "evidence",
    title: "Why the evidence chain matters",
    body: [
      ["No claim without evidence", "A rule cannot fire unless every item it depends on is present, and every output cites those items by id. This is enforced by a test, not by documentation. There is no free-text prompt in this path and nothing that can invent a citation."],
      ["Hashed at the moment of capture", "SHA-256 is computed over the raw bytes before any processing, and each record is appended to a hash chain, so later alteration is detectable. This cannot be added afterwards — the hashes have to exist from the moment of capture, which is why it sits at the foundation."],
      ["Admissibility", "Because hashes exist from acquisition, the system can pre-fill Part A of the certificate that Indian law requires for electronic records — hash values, timestamps, tool version, collection method. Part B is a human expert's signature and is deliberately not machine-generated."],
      ["Bi-temporal records", "Every claim carries two timelines: when it was true in the world, and when we came to believe it. That second axis is what lets a report filed as evidence be regenerated exactly, months later, from the belief state it was written from — rather than explaining why the system now says something different."],
    ],
  },
  {
    id: "visuals",
    title: "Why the graphics are shaped the way they are",
    body: [
      ["The attribution view encodes the arithmetic", "Evidence accumulates along a log-odds axis: each signal displaces the marker by exactly its likelihood ratio, right for one shared operator, left for two different people. Bar length is the contribution, so reading the track left to right is reading the calculation. An earlier version orbited six plates around a 'fusion core' — it animated well and encoded nothing, and the symmetry it implied was wrong, since two signals are hard and four are behavioural."],
      ["Zero is drawn, not just stated", "A signal that was observed and contributed nothing appears as a hollow tick with no width. Evidence against travels backwards. Calibration is hatched and drawn separately so the post-fusion adjustment is never folded into the total."],
      ["3D only where the question is qualitative", "The live marketplace crawl uses a moving canvas because the question there is 'is this alive and how far along', which motion answers at a glance. Nothing quantitative is encoded in it."],
      ["2D for evidence chains", "The evidence path is deliberately flat. Following a chain is a reading task, and in three dimensions nodes hide behind each other, depth is ambiguous, and you end up rotating the scene instead of reading it. We would rather the analyst trace the chain than admire the topology."],
    ],
  },
  {
    id: "limits",
    title: "What this cannot do",
    body: [
      ["It cannot de-anonymize a careful operator", "It finds the ones who make mistakes, continuously and at scale. Published origin-recovery rates are around 5%."],
      ["It cannot follow Monero", "This is the single largest structural gap in the financial signal, and it is not solvable from the outside."],
      ["It cannot enter closed communities", "Running covert personas inside invite-only forums is a human activity under lawful authority. We declare it out of scope rather than pretend to automate it."],
      ["It cannot prove authorship from writing alone", "Stylometry degrades under obfuscation. It contributes; it never decides."],
      ["It cannot produce a verdict", "The output is an investigative lead with a stated confidence. A human with lawful authority adjudicates, and that step is enforced as a workflow state rather than described as a policy."],
      ["Our numbers are from a synthetic corpus", "Actor identity there is exact by construction, so the mathematics is real but the population is not. Real evaluation against public darknet-market research archives is the declared next step, and until then nothing here is a prediction of real-world performance."],
    ],
  },
  {
    id: "safety",
    title: "Boundaries enforced in code",
    body: [
      ["No exploitation", "No vulnerability exploitation, no authentication bypass, no credential use, no purchases, no interaction with vendors. Collection is passive retrieval of what a service already serves to any anonymous client."],
      ["No attacks on Tor", "No traffic confirmation, guard discovery or relay flooding. Those degrade anonymity for every user of the network, including the journalists and abuse survivors it exists to protect."],
      ["Zero retention of child abuse material", "Enforced by a deterministic rule, including the URL, and checked before the page is ever requested. A probabilistic model must never be the arbiter of that decision, so it is not one."],
      ["Credentials counted, never stored", "Passwords, card numbers and payment keys are recorded as counts. Keeping the values would make this database a more attractive target than the actors it tracks."],
      ["Right of rebuttal", "Because contradicting evidence and the full evidence path are preserved, a wrong conclusion can be examined and refuted rather than merely disputed. That is the strongest protection the design offers someone wrongly implicated."],
    ],
  },
];

export default function Guide() {
  const [open, setOpen] = useState("problem");

  return (
    <div>
      <div className="page-title">
        <div>
          <div className="eyebrow">// Reference</div>
          <h1 className="display">How DarkGuard Works</h1>
          <p>
            What each part does, why it is built that way, and where it falls short. No prior knowledge assumed.
          </p>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head"><span>// Contents</span><span className="tag">{SECTIONS.length} sections</span></div>
        <div className="panel-pad">
          <div className="chips">
            {SECTIONS.map((s) => (
              <button
                key={s.id}
                className="chip"
                onClick={() => setOpen(s.id)}
                style={{
                  cursor: "pointer",
                  borderColor: open === s.id ? "var(--acid)" : "var(--line-hard)",
                  color: open === s.id ? "var(--acid)" : "var(--ink-dim)",
                  background: "transparent",
                }}
              >
                {s.title}
              </button>
            ))}
          </div>
        </div>
      </div>

      {SECTIONS.map((s) => (
        <div key={s.id} className="panel" style={{ marginTop: 16, borderColor: open === s.id ? "var(--line-hard)" : "var(--line)" }}>
          <div
            className="panel-head clickable"
            onClick={() => setOpen(open === s.id ? null : s.id)}
            style={{ cursor: "pointer" }}
          >
            <span>// {s.title}</span>
            <span className="tag">{open === s.id ? "−" : "+"}</span>
          </div>
          {open === s.id && (
            <div className="panel-pad">
              {s.body.map(([heading, text], i) => (
                <div key={i} style={{ padding: "10px 0", borderBottom: i < s.body.length - 1 ? "1px dashed var(--line)" : "none" }}>
                  <div className="mono-label" style={{ color: "var(--acid)", marginBottom: 5 }}>{heading}</div>
                  <p style={{ fontSize: ".88rem", lineHeight: 1.68, margin: 0 }}>{text}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      <div className="banner" style={{ marginTop: 16, borderColor: "var(--info)", background: "rgba(76,201,240,.06)", color: "var(--info)" }}>
        <span>// Authorized, defensive use only. Assess assets you own or are permitted to assess.</span>
      </div>
    </div>
  );
}
