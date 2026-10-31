"""Exposure engine (DarkGuard-style surface-web sweep) — REAL data, no mock.

Mirrors DarkGuard's `/scans` API shape so the ported Exposure panel works
unchanged: POST creates a scan (queued), a background task runs the real sweep
and streams a process log, GET polls status until completed.

Data sources (all keyless, no account required):
  • XposedOrNot  — email breach analytics (breaches, exposed data classes, risk)
                   https://api.xposedornot.com/v1/breach-analytics?email=
  • crt.sh       — certificate-transparency logs -> subdomain / shadow-infra
                   discovery for a domain, and brand-substring search for a keyword
                   https://crt.sh/?q=<q>&output=json

Everything runs server-side; nothing about the target is persisted beyond the
in-memory scan record for the life of the process.
"""
from __future__ import annotations

import asyncio
import re
import secrets
from datetime import datetime, timezone

import httpx

# ---- in-memory scan store (self-hosted, single-tenant) --------------------
SCANS: dict[str, dict] = {}
_ORDER: list[str] = []          # scan ids, newest first

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
URL_RE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.I)

_UA = {"User-Agent": "SENTINEL-APEX/1.0 (+exposure-scanner)"}


def _now() -> str:
    # Naive UTC ISO string; the frontend appends "Z" before parsing.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def detect_kind(value: str) -> str:
    v = value.strip()
    if EMAIL_RE.match(v):
        return "email"
    if URL_RE.match(v):
        return "website"
    return "keyword"


def bare_domain(value: str) -> str:
    v = value.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split("?")[0]
    return v.strip(".")


# ---- public API (mirrors DarkGuard) ---------------------------------------

def create_scan(body: dict) -> dict:
    """Create a scan record (status=queued) and schedule the real sweep."""
    email = (body.get("email") or "").strip()
    target_url = (body.get("targetUrl") or "").strip()
    query = (body.get("query") or "").strip()
    engines = body.get("engines") or []

    raw = email or target_url or query
    if not raw:
        return {"error": "email, targetUrl or query required"}
    kind = "email" if email else "website" if target_url else "keyword"
    # If the caller used `query` but it's actually an email/domain, reclassify.
    if kind == "keyword":
        kind = detect_kind(raw)

    sid = "scan_" + secrets.token_hex(5)
    scan = {
        "id": sid,
        "session_id": str(body.get("session_id") or ""),
        "status": "queued",
        "kind": kind,
        "target_url": bare_domain(raw) if kind == "website" else "",
        "query": raw,
        "engines": engines,
        "created_at": _now(),
        "risk_score": 0,
        "findings": [],
        "stats": {"kept": 0, "intel": 0, "crawled": 0, "blocked": 0},
        "logs": [f"[queued] target accepted — classified as {kind}"],
        "summary": "",
        "keywords": [],
        "error": "",
    }
    SCANS[sid] = scan
    _ORDER.insert(0, sid)
    asyncio.create_task(_run(sid))
    return {"scan": {"id": sid, "status": "queued"}}


def list_scans(session_id: str = "") -> dict:
    out = []
    for sid in _ORDER:
        s = SCANS.get(sid)
        if not s or (session_id and s.get("session_id") != session_id):
            continue
        out.append({
            "id": s["id"], "status": s["status"], "kind": s["kind"],
            "target_url": s["target_url"], "query": s["query"],
            "risk_score": s["risk_score"], "stats": s["stats"],
            "created_at": s["created_at"], "summary": s["summary"],
        })
    return {"scans": out}


def get_scan(sid: str, session_id: str = "") -> dict:
    s = SCANS.get(sid)
    if not s or (session_id and s.get("session_id") != session_id):
        return {"error": "scan not found"}
    return {"scan": s}


# ---- runner ----------------------------------------------------------------

async def _run(sid: str) -> None:
    s = SCANS.get(sid)
    if not s:
        return
    s["status"] = "running"
    log = s["logs"].append
    try:
        async with httpx.AsyncClient(timeout=35.0, headers=_UA, follow_redirects=True) as client:
            if s["kind"] == "email":
                await _scan_email(client, s, log)
            elif s["kind"] == "website":
                await _scan_domain(client, s, log)
            else:
                await _scan_keyword(client, s, log)
        s["stats"]["kept"] = len(s["findings"])
        s["status"] = "completed"
        log("[✓] sweep complete")
    except Exception as e:  # never crash the server on a bad upstream
        s["status"] = "failed"
        s["error"] = str(e)
        log(f"[ERROR] sweep failed — {e}")


# ---- email: XposedOrNot breach analytics ----------------------------------

def _sev_for_classes(classes: str) -> str:
    c = classes.lower()
    if any(k in c for k in ("password", "credit card", "bank", "cvv", "payment", "security question")):
        return "critical"
    if any(k in c for k in ("phone", "physical address", "date of birth", "government",
                             "social security", "passport", "partial credit", "historical password",
                             "security pin", "tax")):
        return "high"
    if any(k in c for k in ("email", "username", "name", "geographic", "ip address", "job", "employer")):
        return "medium"
    return "low"


async def _scan_email(client: httpx.AsyncClient, s: dict, log) -> None:
    email = s["query"]
    log(f"[intel] querying XposedOrNot breach analytics for {email}")
    r = await client.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email})
    if r.status_code == 404:
        log("[✓] no breaches found for this address — clean")
        s["risk_score"] = 0
        s["summary"] = "No known breaches. Good news."
        s["stats"]["intel"] = 0
        return
    r.raise_for_status()
    data = r.json()

    metrics = data.get("BreachMetrics") or {}
    # XposedOrNot wraps risk in a single-element list: [{"risk_label","risk_score"}].
    risk_raw = metrics.get("risk")
    if isinstance(risk_raw, list):
        risk_raw = risk_raw[0] if risk_raw else {}
    risk = risk_raw or {}
    risk_score = int(risk.get("risk_score") or 0)
    risk_label = risk.get("risk_label") or ""

    details = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
    pastes = (data.get("PastesSummary") or {}).get("cnt") or 0
    log(f"[intel] XposedOrNot returned {len(details)} breach record(s) · risk {risk_score}/100 {risk_label}")
    await asyncio.sleep(0.3)

    all_classes: list[str] = []
    for b in details:
        classes = b.get("xposed_data") or ""
        for cl in classes.split(";"):
            cl = cl.strip()
            if cl and cl not in all_classes:
                all_classes.append(cl)
        sev = _sev_for_classes(classes)
        verified = (b.get("verified") == "Yes")
        records = b.get("xposed_records") or 0
        name = b.get("breach") or "Unknown"
        s["findings"].append({
            "severity": sev,
            "confidence": "high" if verified else "med",
            "category": (b.get("industry") or "breach").lower(),
            "title": f"{name} · {b.get('xposed_date') or '—'} · {records:,} records",
            "snippet": (b.get("details") or "").strip()[:280]
                       + (f"  ·  Exposed: {classes}" if classes else ""),
            "engine": "xposedornot",
            "onion_url": "",
        })

    log(f"[intel] {len(all_classes)} distinct data class(es) exposed across breaches")
    # Order findings by severity for the table.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    s["findings"].sort(key=lambda f: order.get(f["severity"], 9))

    s["risk_score"] = risk_score
    s["stats"] = {"kept": len(s["findings"]), "intel": len(details),
                  "crawled": int(pastes), "blocked": 0}
    s["keywords"] = all_classes[:14]
    crit_high = sum(1 for f in s["findings"] if f["severity"] in ("critical", "high"))
    s["summary"] = (f"{len(details)} breach(es) · {crit_high} critical/high · "
                    f"risk {risk_score}/100 {risk_label}".strip())


# ---- domain: crt.sh subdomain / shadow-infra discovery --------------------

# Labels that make a discovered host notable. Ordered by how much they raise severity.
_HIGH = ("admin", "internal", "intranet", "vpn", "db", "database", "sql", "jenkins",
         "git", "gitlab", "staging", "stage", "dev", "test", "uat", "qa", "backup",
         "phpmyadmin", "grafana", "kibana", "jira", "confluence", "sonar", "nexus",
         "vault", "ldap", "s3", "minio")
_MED = ("api", "mail", "smtp", "imap", "remote", "portal", "dashboard", "monitor",
        "ci", "cd", "registry", "proxy", "gateway", "sso", "auth", "ftp", "ssh",
        "rdp", "citrix", "owa", "webmail", "status")
# AI shadow-IT markers — the whole point of the problem statement.
_AI = ("ollama", "llm", "vllm", "mlflow", "genai", "copilot", "openai", "llama",
       "gpt", "chatbot", "langchain", "ai", "ml")


def _labels(host: str) -> list[str]:
    return [p for p in host.lower().split(".") if p]


def _classify_host(host: str, root: str) -> tuple[str, str] | None:
    """Return (severity, category) if the host is notable, else None."""
    labels = _labels(host)
    sub = labels[:-len(_labels(root))] if host.endswith(root) else labels
    tokens = set(sub)
    # AI infra first — this is the shadow-IT signal we most want surfaced.
    if any(t in _AI and t not in ("ai", "ml") for t in tokens) or \
       any(t in ("ai", "ml") for t in tokens if t in sub[:1]):
        return "high", "ai-infra"
    if tokens & set(_HIGH):
        return "high", "shadow-infra"
    if tokens & set(_MED):
        return "medium", "exposed-service"
    return None


async def _scan_domain(client: httpx.AsyncClient, s: dict, log) -> None:
    domain = bare_domain(s["query"])
    s["target_url"] = domain
    log(f"[recon] querying crt.sh certificate transparency for {domain}")
    r = await client.get("https://crt.sh/", params={"q": domain, "output": "json"})
    r.raise_for_status()
    try:
        rows = r.json()
    except Exception:
        rows = []
    log(f"[recon] crt.sh returned {len(rows)} certificate row(s)")
    await asyncio.sleep(0.3)

    names: set[str] = set()
    recent: list[str] = []
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None)
    for row in rows:
        for nm in str(row.get("name_value") or "").split("\n"):
            nm = nm.strip().lower().lstrip("*.")
            if nm and nm.endswith(domain):
                names.add(nm)
        nb = row.get("not_before") or ""
        try:
            d = datetime.strptime(nb[:19], "%Y-%m-%dT%H:%M:%S")
            if (cutoff - d).days <= 30:
                cn = str(row.get("common_name") or "").strip().lower().lstrip("*.")
                if cn and cn not in recent:
                    recent.append(cn)
        except Exception:
            pass

    names.discard(domain)
    log(f"[recon] {len(names)} unique subdomain(s) resolved from CT logs")

    cats: list[str] = []
    notable = 0
    for host in sorted(names):
        hit = _classify_host(host, domain)
        if not hit:
            continue
        sev, cat = hit
        if cat not in cats:
            cats.append(cat)
        notable += 1
        s["findings"].append({
            "severity": sev,
            "confidence": "high",
            "category": cat,
            "title": host,
            "snippet": {
                "ai-infra": "Hostname suggests self-hosted AI / LLM infrastructure exposed in public CT logs — classic shadow-IT.",
                "shadow-infra": "Non-production or internal-tier hostname published in CT logs — attack surface that likely shouldn't be internet-visible.",
                "exposed-service": "Service endpoint discoverable from certificate transparency.",
            }.get(cat, "Discovered via certificate transparency."),
            "engine": "crt.sh",
            "onion_url": "",
        })
        if notable >= 60:
            log("[recon] • notable-host cap reached (60) — remaining hosts summarised")
            break

    # One info finding for freshly issued certs (change signal).
    if recent:
        s["findings"].append({
            "severity": "info", "confidence": "med", "category": "cert-activity",
            "title": f"{len(recent)} certificate(s) issued in the last 30 days",
            "snippet": "Recent CT issuance: " + ", ".join(recent[:8])
                       + (" …" if len(recent) > 8 else ""),
            "engine": "crt.sh", "onion_url": "",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    s["findings"].sort(key=lambda f: order.get(f["severity"], 9))

    unique = len(names)
    risk = min(100, 8 + notable * 6 + min(35, unique // 12))
    if any(f["category"] == "ai-infra" for f in s["findings"]):
        risk = min(100, risk + 12)
    s["risk_score"] = risk
    s["stats"] = {"kept": len(s["findings"]), "intel": unique,
                  "crawled": len(rows), "blocked": 0}
    s["keywords"] = cats
    s["summary"] = (f"{unique} subdomains · {notable} notable host(s) · "
                    f"risk {risk}/100")
    if not s["findings"]:
        log("[✓] no notable hosts — surface looks tidy")


# ---- keyword: crt.sh brand-substring search -------------------------------

async def _scan_keyword(client: httpx.AsyncClient, s: dict, log) -> None:
    kw = s["query"].strip()
    log(f"[recon] searching crt.sh certificate transparency for brand '{kw}'")
    # ILIKE substring match across all logged certificate names.
    r = await client.get("https://crt.sh/", params={"q": f"%{kw}%", "output": "json"})
    r.raise_for_status()
    try:
        rows = r.json()
    except Exception:
        rows = []
    log(f"[recon] crt.sh returned {len(rows)} certificate row(s) mentioning '{kw}'")
    await asyncio.sleep(0.3)

    domains: dict[str, str] = {}   # domain -> first-seen issuer
    for row in rows:
        for nm in str(row.get("name_value") or "").split("\n"):
            nm = nm.strip().lower().lstrip("*.")
            if nm and kw.lower() in nm and nm not in domains:
                domains[nm] = str(row.get("issuer_name") or "")
    log(f"[recon] {len(domains)} distinct hostname(s) contain '{kw}'")

    kwl = kw.lower()
    for host, issuer in sorted(domains.items())[:40]:
        # A host where the brand is a subdomain of someone else's domain, or a
        # lookalike apex, is the interesting case (possible impersonation).
        apex = ".".join(host.split(".")[-2:])
        brand_is_apex = host.split(".")[0] == kwl or apex.startswith(kwl)
        sev = "low" if brand_is_apex else "medium"
        s["findings"].append({
            "severity": sev,
            "confidence": "med",
            "category": "brand-mention" if brand_is_apex else "possible-impersonation",
            "title": host,
            "snippet": f"Certificate issued by {issuer[:80]}"
                       + ("" if brand_is_apex else " — brand appears inside an unrelated domain."),
            "engine": "crt.sh",
            "onion_url": "",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    s["findings"].sort(key=lambda f: order.get(f["severity"], 9))

    impers = sum(1 for f in s["findings"] if f["category"] == "possible-impersonation")
    risk = min(100, impers * 9 + min(30, len(domains) // 3))
    s["risk_score"] = risk
    s["stats"] = {"kept": len(s["findings"]), "intel": len(domains),
                  "crawled": len(rows), "blocked": 0}
    s["keywords"] = [kw]
    s["summary"] = (f"{len(domains)} hostname(s) mention '{kw}' · "
                    f"{impers} possible impersonation(s) · risk {risk}/100")
    if not s["findings"]:
        log("[✓] no certificate-transparency mentions found")
