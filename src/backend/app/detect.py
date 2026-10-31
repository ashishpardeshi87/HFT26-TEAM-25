"""Sensitive-data detection (PS requirement 3): regex signatures, Shannon entropy,
and PII with real validation (Aadhaar via Verhoeff, cards via Luhn).

Everything runs locally. Matches are masked before they leave this process.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import secrets

from .models import Finding

# Keyed-hash fingerprint: redact the secret locally but keep HMAC(org_key, secret) so a
# file read can be proven to match a later payload leak WITHOUT storing the secret.
_ORG_KEY = os.getenv("ORG_HMAC_KEY", "").encode() or secrets.token_bytes(32)

# Optional deployment-unique canary. No predictable test credential ships in
# production; set SENTINEL_CANARY from the local secrets store when desired.
CANARY = os.getenv("SENTINEL_CANARY", "").strip()


def fingerprint(value: str) -> str:
    norm = re.sub(r"\s+", "", value or "").encode()
    return hmac.new(_ORG_KEY, norm, hashlib.sha256).hexdigest()[:16]

# ---------------------------------------------------------------- secrets
# (label, compiled regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("OpenAI API Key", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"), "critical"),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "critical"),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub PAT", re.compile(r"github_pat_[A-Za-z0-9_]{60,}"), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "high"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("Generic Secret Assignment", re.compile(
        r"(?i)(?:password|passwd|secret|api[_-]?key|token|bearer)\s*[:=]\s*['\"]?([^\s'\"]{8,})"), "high"),
]

# ---------------------------------------------------------------- PII
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_IN_RE = re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)(\d{4})\s?(\d{4})\s?(\d{4})(?!\s?\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

# Verhoeff tables (used by the UIDAI Aadhaar checksum)
_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]


def _verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def _luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _mask(s: str, keep: int = 4) -> str:
    s = s.strip()
    if len(s) <= keep:
        return "\u2588" * len(s)
    return s[:keep] + "\u2588" * min(8, max(3, len(s) - keep))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.type, f.label, f.match_masked)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def redact_for_storage(text: str) -> str:
    """Remove raw secrets and regulated numeric identifiers before evidence is
    stored. Detection runs first; this is the storage-boundary redaction."""
    if not text:
        return ""
    out = text
    for _, rx, _ in SECRET_PATTERNS:
        out = rx.sub(lambda m: _mask(m.group(0)), out)
    out = CARD_RE.sub(lambda m: "████-████-████-" + re.sub(r"\D", "", m.group(0))[-4:]
                      if _luhn_ok(m.group(0)) else m.group(0), out)
    out = AADHAAR_RE.sub(lambda m: "XXXX-XXXX-" + (m.group(1) + m.group(2) + m.group(3))[-4:]
                         if _verhoeff_ok(m.group(1) + m.group(2) + m.group(3)) else m.group(0), out)
    out = PAN_RE.sub(lambda m: m.group(0)[:3] + "███" + m.group(0)[-1], out)
    out = PHONE_IN_RE.sub(lambda m: "██████" + m.group(0)[-4:], out)
    return out


def scan(text: str) -> list[Finding]:
    """Scan one outgoing payload and return masked findings."""
    if not text:
        return []
    findings: list[Finding] = []

    # canary token — confirmed exfiltration, ground truth
    if CANARY and CANARY in text:
        findings.append(Finding(type="canary", label="Canary Token — CONFIRMED EXFILTRATION",
                                severity="critical", confidence=1.0,
                                match_masked=CANARY[:8] + "\u2588\u2588\u2588", fingerprint=fingerprint(CANARY)))

    # secrets
    for label, rx, sev in SECRET_PATTERNS:
        for m in rx.finditer(text):
            if CANARY and m.group(0) in CANARY:
                continue  # already reported as a canary token
            findings.append(Finding(type="secret", label=label, severity=sev,
                                     confidence=0.95, match_masked=_mask(m.group(0)),
                                     fingerprint=fingerprint(m.group(0))))

    # credit cards (validated) FIRST, so we can exclude their digits from Aadhaar
    card_spans: list[tuple[int, int]] = []
    for m in CARD_RE.finditer(text):
        if _luhn_ok(m.group(0)):
            card_spans.append((m.start(), m.end()))
            digits = re.sub(r"\D", "", m.group(0))
            findings.append(Finding(type="pii", label="Credit Card", severity="critical",
                                    confidence=0.92, match_masked="\u2588\u2588\u2588\u2588 " + digits[-4:]))

    def _in_card(a: int, b: int) -> bool:
        return any(a < ce and cs < b for cs, ce in card_spans)

    # PII — Aadhaar (validated, not part of a card number)
    for m in AADHAAR_RE.finditer(text):
        if _in_card(m.start(), m.end()):
            continue
        raw = m.group(1) + m.group(2) + m.group(3)
        if _verhoeff_ok(raw):
            findings.append(Finding(type="pii", label="Aadhaar", severity="high",
                                    confidence=0.97, match_masked="XXXX-XXXX-" + raw[-4:]))
    # PAN
    for m in PAN_RE.finditer(text):
        findings.append(Finding(type="pii", label="PAN", severity="high",
                                confidence=0.9, match_masked=m.group(0)[:3] + "\u2588\u2588\u2588" + m.group(0)[-1]))
    # email / phone
    for m in EMAIL_RE.finditer(text):
        e = m.group(0)
        findings.append(Finding(type="pii", label="Email", severity="medium", confidence=0.85,
                                match_masked=e[0] + "\u2588\u2588\u2588@" + e.split("@")[-1]))
    for m in PHONE_IN_RE.finditer(text):
        p = m.group(0)
        findings.append(Finding(type="pii", label="Phone (IN)", severity="medium",
                                confidence=0.8, match_masked="\u2588\u2588\u2588\u2588\u2588\u2588" + p[-4:]))

    # entropy — catch secrets that match no signature
    known = {f.match_masked[:4] for f in findings}
    for tok in re.findall(r"[A-Za-z0-9+/_=-]{20,}", text):
        if tok[:4] in known:
            continue
        if shannon_entropy(tok) >= 4.0:
            findings.append(Finding(type="entropy", label="High-Entropy Secret", severity="high",
                                    confidence=0.6, match_masked=_mask(tok)))

    return _dedup(findings)
