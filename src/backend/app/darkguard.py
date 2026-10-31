"""Real DarkGuard server-to-server bridge.

No fabricated fallback exists. When DarkGuard is unconfigured, unreachable, or a
scan fails, callers receive that state and zero intelligence. Completed findings
carry scan IDs and source provenance.

Authentication options (server-side only):
  * DARKGUARD_TOKEN — an approved short-lived/local-session JWT; or
  * DARKGUARD_EMAIL + DARKGUARD_PASSWORD — exchanged at /auth/login and cached
    in memory. Credentials are never returned to the browser or logged.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
import re
import time
from typing import Any, Iterable
from urllib.parse import unquote

import httpx

_TOKEN_CACHE: dict[str, Any] = {"token": None, "at": 0.0}
_TOKEN_LOCK = asyncio.Lock()
MAX_INDICATORS = 6
MAX_UI_RESPONSE_BYTES = 20 * 1024 * 1024
_UI_REQUEST_TIMEOUT = 200.0
_UI_MAX_AFTER = 1_000_000
_UUID_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_LIVE_JOB_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z\d+.-]*:", re.IGNORECASE)
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_INVALID_PERCENT_RE = re.compile(r"%(?![0-9a-f]{2})", re.IGNORECASE)


@dataclass(frozen=True)
class UIResponse:
    status_code: int
    content: bytes
    media_type: str


class UIRequestError(Exception):
    """A caller-safe DarkGuard UI bridge failure."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


_UI_STATIC_OPERATIONS: dict[tuple[str, str], str] = {
    ("GET", "/scans"): "application/json",
    ("GET", "/export/findings.csv"): "text/csv",
    ("GET", "/export/json"): "application/json",
    ("GET", "/monitors"): "application/json",
    ("GET", "/assets"): "application/json",
    ("GET", "/tor/ip"): "application/json",
    ("GET", "/osint/model"): "application/json",
    ("GET", "/osint/history"): "application/json",
    ("GET", "/hunt/readiness"): "application/json",
    ("GET", "/attribution/evaluation"): "application/json",
    ("GET", "/attribution/status"): "application/json",
    ("GET", "/attribution/live/services"): "application/json",
    ("POST", "/monitors"): "application/json",
    ("POST", "/assets"): "application/json",
    ("POST", "/tor/newnym"): "application/json",
    ("POST", "/tor/search"): "application/json",
    ("POST", "/tor/open"): "application/json",
    ("POST", "/osint/investigate"): "application/json",
    ("POST", "/attribution/evaluation/run"): "application/json",
    ("POST", "/attribution/live/start"): "application/json",
    ("POST", "/attribution/categorise"): "application/json",
}


def _bounded_indicators(indicators: list[str]) -> list[str]:
    return list(dict.fromkeys(str(i).strip() for i in indicators if str(i).strip()))[:MAX_INDICATORS]


def _base() -> str:
    return os.getenv("DARKGUARD_API_BASE", "").strip().rstrip("/")


def enabled() -> bool:
    return os.getenv("DARKGUARD_ENABLED", "false").lower() == "true" and bool(_base())


def configured() -> dict:
    direct = bool(os.getenv("DARKGUARD_TOKEN", "").strip())
    login = bool(os.getenv("DARKGUARD_EMAIL", "").strip() and os.getenv("DARKGUARD_PASSWORD", "").strip())
    return {
        "enabled": enabled(),
        "configured": enabled() and (direct or login),
        "base": _base() if enabled() else None,
        "auth": "token" if direct else "service-login" if login else "missing",
        "mode": "live-only",
        "synthetic_fallback": False,
    }


def _cached_service_token() -> str:
    token = _TOKEN_CACHE.get("token")
    if token and time.time() - float(_TOKEN_CACHE.get("at") or 0.0) < 45 * 60:
        return str(token)
    return ""


async def _token(client: httpx.AsyncClient) -> str:
    direct = os.getenv("DARKGUARD_TOKEN", "").strip()
    if direct:
        return direct
    email = os.getenv("DARKGUARD_EMAIL", "").strip()
    password = os.getenv("DARKGUARD_PASSWORD", "").strip()
    if not email or not password:
        raise RuntimeError("DarkGuard authentication is not configured")
    cached = _cached_service_token()
    if cached:
        return cached

    # A cache miss is checked again under the lock. This prevents a burst of UI
    # requests from exchanging the same service credentials concurrently.
    async with _TOKEN_LOCK:
        cached = _cached_service_token()
        if cached:
            return cached
        client.cookies.clear()
        r = await client.post(f"{_base()}/auth/login", json={"email": email, "password": password})
        client.cookies.clear()
        r.raise_for_status()
        token = (r.json() or {}).get("token")
        if not token:
            raise RuntimeError("DarkGuard login returned no token")
        _TOKEN_CACHE.update(token=token, at=time.time())
        return str(token)


async def _invalidate_service_token(token: str) -> None:
    async with _TOKEN_LOCK:
        # Do not erase a token another request has already refreshed.
        if _TOKEN_CACHE.get("token") == token:
            _TOKEN_CACHE.update(token=None, at=0.0)


async def _authenticated_response(client: httpx.AsyncClient, method: str, path: str, *,
                                  body: dict | None = None, params: dict | None = None,
                                  stream: bool = False) -> httpx.Response:
    async def send(token: str) -> httpx.Response:
        client.cookies.clear()
        kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": f"{_base()}{path}",
            "params": params,
            "headers": {"Authorization": f"Bearer {token}"},
        }
        if body is not None:
            kwargs["json"] = body
        req = client.build_request(**kwargs)
        return await client.send(req, stream=stream, follow_redirects=False)

    token = await _token(client)
    response = await send(token)
    if response.status_code == 401 and not os.getenv("DARKGUARD_TOKEN", "").strip():
        await response.aclose()
        client.cookies.clear()
        await _invalidate_service_token(token)
        token = await _token(client)
        response = await send(token)
    return response


async def request(method: str, path: str, *, body: dict | None = None,
                  params: dict | None = None, timeout: float = 70.0) -> dict:
    if not configured()["configured"]:
        raise RuntimeError("DarkGuard live integration is not configured")
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                 headers={"User-Agent": "SENTINEL-APEX-Bridge/1.0"}) as client:
        r = await _authenticated_response(client, method, path, body=body, params=params)
        r.raise_for_status()
        return r.json()


def _ui_error(status_code: int, detail: str) -> UIRequestError:
    return UIRequestError(status_code, detail)


def _validate_ui_path(path: str, raw_path: str | bytes | None) -> None:
    if not isinstance(path, str) or not path or len(path) > 512:
        raise _ui_error(400, "Invalid DarkGuard UI path.")

    candidates: list[str] = [path]
    if raw_path is not None:
        if isinstance(raw_path, bytes):
            try:
                candidates.append(raw_path.decode("ascii"))
            except UnicodeDecodeError as exc:
                raise _ui_error(400, "Invalid DarkGuard UI path encoding.") from exc
        elif isinstance(raw_path, str):
            candidates.append(raw_path)
        else:
            raise _ui_error(400, "Invalid DarkGuard UI path encoding.")

    for candidate in candidates:
        if not candidate or len(candidate) > 512:
            raise _ui_error(400, "Invalid DarkGuard UI path.")
        current = candidate
        for _ in range(6):
            if (_CONTROL_CHARACTER_RE.search(current) or "\\" in current or "?" in current
                    or "#" in current or ".." in current):
                raise _ui_error(400, "Unsafe DarkGuard UI path rejected.")
            if (not current.startswith("/") or current.startswith("//")
                    or _URL_SCHEME_RE.match(current) or "://" in current):
                raise _ui_error(400, "Absolute DarkGuard UI URLs are not allowed.")
            if any(segment == "." for segment in current.split("/")):
                raise _ui_error(400, "DarkGuard UI path traversal is not allowed.")
            if _INVALID_PERCENT_RE.search(current) or _ENCODED_SEPARATOR_RE.search(current):
                raise _ui_error(400, "Encoded DarkGuard UI path separators are not allowed.")
            try:
                decoded = unquote(current, errors="strict")
            except UnicodeDecodeError as exc:
                raise _ui_error(400, "Invalid DarkGuard UI path encoding.") from exc
            if decoded == current:
                break
            current = decoded
        else:
            raise _ui_error(400, "Excessively encoded DarkGuard UI path rejected.")


def _query_items(params: dict | Iterable[tuple[str, Any]] | None) -> list[tuple[str, str]]:
    if params is None:
        return []
    source = params.items() if isinstance(params, dict) else params
    items: list[tuple[str, str]] = []
    try:
        for key, value in source:
            items.append((str(key), str(value)))
    except (TypeError, ValueError) as exc:
        raise _ui_error(400, "Invalid DarkGuard UI query parameters.") from exc
    if len({key for key, _ in items}) != len(items):
        raise _ui_error(400, "Duplicate DarkGuard UI query parameters are not allowed.")
    return items


def _validate_uuid_id(value: str) -> None:
    if not _UUID_ID_RE.fullmatch(value):
        raise _ui_error(400, "Invalid DarkGuard resource ID.")


def _ui_operation(method: str, path: str,
                  params: dict | Iterable[tuple[str, Any]] | None) -> tuple[str, dict[str, Any]]:
    media_type = _UI_STATIC_OPERATIONS.get((method, path))
    query_mode: str | None = None

    match = re.fullmatch(r"/scans/([^/]+)", path)
    if match:
        _validate_uuid_id(match.group(1))
        if method == "GET":
            media_type = "application/json"
    match = re.fullmatch(r"/monitors/([^/]+)", path)
    if match:
        _validate_uuid_id(match.group(1))
        if method == "GET":
            media_type = "application/json"
            query_mode = "refresh"
        elif method == "DELETE":
            media_type = "application/json"
    match = re.fullmatch(r"/osint/jobs/([^/]+)", path)
    if match:
        _validate_uuid_id(match.group(1))
        if method == "GET":
            media_type = "application/json"
    match = re.fullmatch(r"/osint/investigations/([^/]+)", path)
    if match:
        _validate_uuid_id(match.group(1))
        if method == "GET":
            media_type = "application/json"
    match = re.fullmatch(r"/osint/investigations/([^/]+)/export\.json", path)
    if match:
        _validate_uuid_id(match.group(1))
        if method == "GET":
            media_type = "application/json"
    match = re.fullmatch(r"/attribution/live/job/([^/]+)", path)
    if match:
        if not _LIVE_JOB_ID_RE.fullmatch(match.group(1)):
            raise _ui_error(400, "Invalid DarkGuard live job ID.")
        if method == "GET":
            media_type = "application/json"
            query_mode = "after"

    if media_type is None:
        raise _ui_error(404, "DarkGuard UI operation is not allowed.")

    items = _query_items(params)
    if not query_mode:
        if items:
            raise _ui_error(400, "Query parameters are not allowed for this DarkGuard UI operation.")
        return media_type, {}
    if any(key != query_mode for key, _ in items):
        raise _ui_error(400, "Unknown DarkGuard UI query parameter.")
    if not items:
        return media_type, {}

    value = items[0][1]
    if query_mode == "refresh":
        if value not in {"true", "false"}:
            raise _ui_error(400, "refresh must be true or false.")
        return media_type, {"refresh": value}
    if not re.fullmatch(r"[0-9]{1,7}", value):
        raise _ui_error(400, "after must be a bounded non-negative integer.")
    after = int(value)
    if after > _UI_MAX_AFTER:
        raise _ui_error(400, f"after must be between 0 and {_UI_MAX_AFTER}.")
    return media_type, {"after": after}


async def _bounded_response_content(response: httpx.Response) -> bytes:
    declared = response.headers.get("content-length")
    if declared:
        try:
            if int(declared) > MAX_UI_RESPONSE_BYTES:
                raise _ui_error(502, "DarkGuard response exceeds the 20 MiB limit.")
        except ValueError:
            pass
    content = bytearray()
    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
        if len(content) + len(chunk) > MAX_UI_RESPONSE_BYTES:
            raise _ui_error(502, "DarkGuard response exceeds the 20 MiB limit.")
        content.extend(chunk)
    return bytes(content)


def _valid_json(content: bytes) -> bool:
    try:
        json.loads(content.decode("utf-8-sig"))
        return True
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False


async def ui_request(method: str, path: str, *, body: dict | None = None,
                     params: dict | Iterable[tuple[str, Any]] | None = None,
                     raw_path: str | bytes | None = None,
                     timeout: float = _UI_REQUEST_TIMEOUT) -> UIResponse:
    """Call one explicitly allowlisted DarkGuard UI operation.

    The browser cannot choose an upstream origin, headers, redirects, cookies,
    or response media type. The FastAPI route applies Sentinel authentication
    and evidence eligibility before calling this transport boundary.
    """
    normalized_method = str(method or "").upper()
    if normalized_method not in {"GET", "POST", "DELETE"}:
        raise _ui_error(405, "DarkGuard UI method is not allowed.")
    _validate_ui_path(path, raw_path)
    media_type, safe_params = _ui_operation(normalized_method, path, params)
    if body is not None and not isinstance(body, dict):
        raise _ui_error(400, "DarkGuard UI request body must be a JSON object.")
    if normalized_method != "POST" and body is not None:
        raise _ui_error(400, "A request body is not allowed for this DarkGuard UI operation.")
    if not configured()["configured"]:
        raise _ui_error(503, "DarkGuard live integration is not configured.")

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "SENTINEL-APEX-Bridge/1.0"},
        ) as client:
            response = await _authenticated_response(
                client, normalized_method, path, body=body,
                params=safe_params or None, stream=True,
            )
            try:
                status_code = response.status_code
                if 300 <= status_code < 400:
                    raise _ui_error(502, "DarkGuard redirect was blocked.")
                if status_code in {401, 407}:
                    raise _ui_error(502, "DarkGuard service authentication failed.")
                if status_code >= 500 or status_code < 200:
                    raise _ui_error(502, "DarkGuard upstream service failed.")
                content = await _bounded_response_content(response)
            finally:
                await response.aclose()
    except UIRequestError:
        raise
    except httpx.TimeoutException as exc:
        raise _ui_error(504, "DarkGuard request timed out.") from exc
    except httpx.RequestError as exc:
        raise _ui_error(502, "DarkGuard is unreachable.") from exc
    except (httpx.HTTPStatusError, RuntimeError, json.JSONDecodeError, ValueError) as exc:
        raise _ui_error(502, "DarkGuard service authentication failed.") from exc

    if 400 <= status_code < 500:
        if not _valid_json(content):
            content = json.dumps({"detail": f"DarkGuard returned HTTP {status_code}"}).encode("utf-8")
        return UIResponse(status_code=status_code, content=content, media_type="application/json")
    if status_code in {204, 205} and not content:
        return UIResponse(status_code=status_code, content=b"", media_type="application/json")
    if media_type == "application/json" and not _valid_json(content):
        raise _ui_error(502, "DarkGuard returned an invalid JSON response.")
    if media_type == "text/csv":
        try:
            content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise _ui_error(502, "DarkGuard returned an invalid CSV response.") from exc
        if b"\x00" in content:
            raise _ui_error(502, "DarkGuard returned an invalid CSV response.")
    return UIResponse(status_code=status_code, content=content, media_type=media_type)


async def readiness() -> dict:
    cfg = configured()
    if not cfg["configured"]:
        return {**cfg, "reachable": False, "status": "unconfigured",
                "error": "Set DARKGUARD_API_BASE and a server-side token or service login."}
    try:
        # This authenticated live endpoint checks both DarkGuard and its scraper.
        data = await request("GET", "/attribution/live/services", timeout=75)
        count = len(data.get("services") or [])
        note = data.get("note")
        scraper_url = os.getenv("DARKGUARD_SCRAPER_HEALTH_URL", "").strip()
        scraper = None
        if scraper_url:
            try:
                async with httpx.AsyncClient(timeout=12, follow_redirects=False) as hc:
                    hr = await hc.get(scraper_url); hr.raise_for_status(); scraper = hr.json()
            except Exception as exc:
                scraper = {"status": "unavailable", "error": _safe_error(exc)}
        tor_ready = bool((scraper or {}).get("tor", {}).get("reachable")) if scraper is not None else None
        status = "ready" if count > 0 and tor_ready is True else "degraded"
        if tor_ready is False:
            note = f"{note or ''} Tor is not reachable; live fingerprints will fail until the SOCKS daemon is ready.".strip()
        elif tor_ready is None:
            note = f"{note or ''} Tor readiness is not independently configured; set DARKGUARD_SCRAPER_HEALTH_URL.".strip()
        return {**cfg, "reachable": True, "status": status,
                "live_services": count, "scraper": scraper, "tor_ready": tor_ready,
                "note": note or ("No services returned by the scraper." if count == 0 else None)}
    except Exception as exc:
        return {**cfg, "reachable": False, "status": "unavailable", "error": _safe_error(exc)}


async def lookup(indicators: list[str]) -> dict | None:
    """Create and poll real DarkGuard scans for non-sensitive indicators."""
    clean = _bounded_indicators(indicators)
    if not clean:
        return None
    cfg = configured()
    if not cfg["configured"]:
        return {"status": "unconfigured", "live": False, "exposure_score": None,
                "sources": [], "results": [], "personas": [],
                "error": "DarkGuard live integration is not configured.", "provenance": cfg}

    scan_ids: list[str] = []
    completed: list[dict] = []
    errors: list[str] = []
    try:
        for indicator in clean:
            try:
                created = await request("POST", "/scans", body={"query": indicator}, timeout=30)
                scan = created.get("scan") or {}
                sid = scan.get("id")
                if not sid:
                    errors.append(f"{indicator}: DarkGuard returned no scan id")
                    continue
                scan_ids.append(sid)
            except Exception as exc:
                errors.append(f"{indicator}: {_safe_error(exc)}")

        timeout_s = max(15, min(600, int(os.getenv("DARKGUARD_SCAN_TIMEOUT", "180"))))
        deadline = time.time() + timeout_s
        pending = set(scan_ids)
        while pending and time.time() < deadline:
            for sid in list(pending):
                try:
                    data = await request("GET", f"/scans/{sid}", timeout=30)
                    scan = data.get("scan") or {}
                    state = scan.get("status")
                    if state == "completed":
                        completed.append(scan); pending.remove(sid)
                    elif state == "failed":
                        errors.append(f"{sid}: {scan.get('error') or 'scan failed'}"); pending.remove(sid)
                except Exception as exc:
                    errors.append(f"{sid}: {_safe_error(exc)}"); pending.remove(sid)
            if pending:
                await asyncio.sleep(2)
        for sid in pending:
            errors.append(f"{sid}: timed out waiting for DarkGuard scan completion")
    except Exception as exc:
        return {"status": "failed", "live": False, "exposure_score": None,
                "sources": [], "results": [], "personas": [], "error": _safe_error(exc),
                "provenance": {**cfg, "scan_ids": scan_ids}}

    results = []
    sources = set()
    scores = []
    personas = []
    for scan in completed:
        if scan.get("risk_score") is not None:
            scores.append(int(scan["risk_score"]))
        for f in scan.get("findings") or []:
            source = f.get("engine") or f.get("source") or "darkguard"
            sources.add(source)
            row = {
                "scan_id": scan.get("id"), "query": scan.get("query"),
                "severity": f.get("severity"), "confidence": f.get("confidence"),
                "category": f.get("category"), "title": f.get("title"),
                "snippet": f.get("snippet"), "url": f.get("onion_url") or f.get("url"),
                "source": source,
            }
            results.append(row)
            if f.get("persona") and isinstance(f["persona"], dict):
                personas.append({**f["persona"], "scan_id": scan.get("id"), "source": source})

    status = "completed" if completed and not errors else "partial" if completed else "failed"
    return {
        "status": status,
        "live": bool(completed),
        "exposure_score": max(scores) if scores else None,
        "sources": sorted(sources),
        "results": results,
        "personas": personas,
        "error": "; ".join(errors) if errors else None,
        "provenance": {
            "provider": "DarkGuard", "mode": "live", "scan_ids": scan_ids,
            "completed_scan_ids": [s.get("id") for s in completed],
            "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "api_base": _base(), "synthetic": False,
        },
    }


async def hunt(indicators: list[str]) -> dict:
    """Start and poll DarkGuard's authenticated marketplace hunts.

    The same six-indicator bound used by ``lookup`` applies here. Every link and
    event in the return value came from the live upstream response.
    """
    clean = _bounded_indicators(indicators)
    cfg = configured()
    if not clean:
        return {"status": "no_indicators", "live": False, "job_ids": [],
                "jobs": [], "events": [], "hits": [], "errors": []}
    if not cfg["configured"]:
        return {"status": "unconfigured", "live": False, "job_ids": [],
                "jobs": [], "events": [], "hits": [],
                "errors": ["DarkGuard live integration is not configured."],
                "provenance": cfg}

    jobs: dict[str, dict] = {}
    errors: list[str] = []
    for indicator in clean:
        try:
            created = await request("POST", "/hunt", body={"query": indicator, "engines": []}, timeout=30)
            job_id = created.get("jobId") or created.get("job_id")
            if not job_id:
                errors.append(f"{indicator}: DarkGuard returned no hunt job id")
                continue
            jobs[str(job_id)] = {
                "job_id": str(job_id), "query": indicator, "status": "running",
                "last_seq": 0, "events": [], "hits": [], "markets": [],
                "stage": None, "stats": {}, "error": None,
            }
        except Exception as exc:
            errors.append(f"{indicator}: {_safe_error(exc)}")

    timeout_s = max(15, min(600, int(os.getenv("DARKGUARD_SCAN_TIMEOUT", "180"))))
    deadline = time.time() + timeout_s
    pending = set(jobs)
    while pending and time.time() < deadline:
        for job_id in list(pending):
            job = jobs[job_id]
            try:
                data = await request(
                    "GET", f"/hunt/{job_id}", params={"after": job["last_seq"]}, timeout=30
                )
                returned_events = data.get("events") or []
                for event in returned_events:
                    if isinstance(event, dict):
                        job["events"].append({"job_id": job_id, "query": job["query"], **event})
                job["last_seq"] = int(data.get("lastSeq") or job["last_seq"])
                job["status"] = str(data.get("status") or job["status"])
                job["stage"] = data.get("stage")
                job["hits"] = data.get("hits") or []
                job["markets"] = data.get("markets") or []
                job["stats"] = data.get("stats") or {}
                job["error"] = data.get("error")
                if job["status"] in ("completed", "failed"):
                    pending.remove(job_id)
                    if job["error"]:
                        errors.append(f"{job_id}: {job['error']}")
            except Exception as exc:
                errors.append(f"{job_id}: {_safe_error(exc)}")
                job["status"] = "failed"
                job["error"] = _safe_error(exc)
                pending.remove(job_id)
        if pending:
            await asyncio.sleep(2)

    for job_id in pending:
        jobs[job_id]["status"] = "timed_out"
        jobs[job_id]["error"] = "timed out waiting for DarkGuard hunt completion"
        errors.append(f"{job_id}: timed out waiting for DarkGuard hunt completion")

    values = list(jobs.values())
    events = [event for job in values for event in job["events"]]
    hits = [
        {"job_id": job["job_id"], "query": job["query"], **hit}
        for job in values for hit in job["hits"] if isinstance(hit, dict)
    ]
    completed = [job for job in values if job["status"] == "completed"]
    status = "completed" if values and len(completed) == len(values) and not errors \
        else "partial" if completed else "failed"
    return {
        "status": status,
        "live": bool(values and (events or completed)),
        "job_ids": list(jobs),
        "jobs": values,
        "events": events,
        "hits": hits,
        "errors": errors,
        "provenance": {
            "provider": "DarkGuard", "mode": "live", "endpoint": "/hunt",
            "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "api_base": _base(), "synthetic": False,
            "indicator_limit": MAX_INDICATORS, "indicators": clean,
        },
    }


async def attribution(method: str, suffix: str, body: dict | None = None,
                      params: dict | None = None) -> dict:
    """Proxy a live-only DarkGuard attribution operation."""
    allowed = {
        "status", "live/services", "live/start", "live/compare", "categorise",
    }
    if suffix.startswith("live/job/"):
        pass
    elif suffix not in allowed:
        raise ValueError("Unsupported DarkGuard attribution operation")
    return await request(method, "/attribution/" + suffix, body=body, params=params)


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"DarkGuard returned HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "DarkGuard request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "DarkGuard is unreachable"
    return str(exc)[:240] or type(exc).__name__
