"""Tor Finder — direct proxy to the DarkGuard scraper microservice.

This mirrors darkguard.in/backend/src/services/scraper.js: the browser's onion
search / open / identity-rotation calls are forwarded verbatim to the scraper's
``/tor/*`` endpoints using the shared scraper bearer token.

It is deliberately independent of the DarkGuard web backend AND of
external-intervention eligibility, so the onion browser works whenever Tor
(SOCKS 127.0.0.1:9050) and the scraper (127.0.0.1:9000) are running — exactly
like darkguard.in. Response bodies are returned to the caller unchanged so the
frontend contract (``ip``/``reachable``; ``ok``/``old_ip``/``new_ip``/``changed``;
``query``/``count``/``links[{engine,name,url}]``; ``ok``/``title``/``text``/
``onion_links``/``blocked``/``error``) is identical to DarkGuard's.
"""
from __future__ import annotations

import os
from typing import Any

import httpx


def _base() -> str:
    return os.getenv("DARKGUARD_SCRAPER_URL", "http://127.0.0.1:9000").strip().rstrip("/")


def _token() -> str:
    return os.getenv("DARKGUARD_SCRAPER_TOKEN", "dev-scraper-token").strip()


def configured() -> dict:
    return {"scraper_url": _base(), "token_set": bool(_token())}


class TorFinderError(Exception):
    """A caller-safe Tor Finder proxy failure."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


async def _call(method: str, path: str, *, body: dict | None = None, timeout: float) -> Any:
    url = _base() + path
    headers = {
        "Authorization": f"Bearer {_token()}",
        "User-Agent": "SENTINEL-APEX-TorFinder/1.0",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, headers=headers) as client:
            r = await client.request(method.upper(), url, json=body)
    except httpx.TimeoutException as exc:
        raise TorFinderError(504, "The Tor scraper timed out.") from exc
    except httpx.RequestError as exc:
        raise TorFinderError(
            502,
            "The Tor scraper is unreachable. Start the DarkGuard scraper on :9000 and Tor on :9050.",
        ) from exc
    if r.status_code in (401, 403):
        raise TorFinderError(502, "The Tor scraper rejected the token; set DARKGUARD_SCRAPER_TOKEN to match the scraper.")
    if r.status_code >= 500 or r.status_code < 200:
        raise TorFinderError(502, f"The Tor scraper returned HTTP {r.status_code}.")
    try:
        return r.json()
    except ValueError as exc:
        raise TorFinderError(502, "The Tor scraper returned a non-JSON response.") from exc


async def ip() -> dict:
    """Current Tor exit IP + reachability. {"ip": str|None, "reachable": bool}."""
    return await _call("GET", "/tor/ip", timeout=40.0)


async def newnym() -> dict:
    """Request a new Tor circuit (SIGNAL NEWNYM) and report the IP change."""
    return await _call("POST", "/tor/newnym", timeout=75.0)


async def search(query: str, engines: list[str] | None, limit: int | None) -> dict:
    """Discover .onion links for a single keyword over Tor."""
    body = {"query": query, "engines": engines or ["ahmia", "tor66"], "limit": int(limit or 2)}
    return await _call("POST", "/tor/search", body=body, timeout=320.0)


async def open_url(url: str) -> dict:
    """Fetch and sanitize a single .onion page over Tor."""
    return await _call("POST", "/tor/open", body={"url": url}, timeout=185.0)
