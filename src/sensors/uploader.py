"""Upload an authorized HAR/JSON/JSONL log into a verified monitoring session.

Required environment from Setup:
  SENTINEL_SESSION_ID, SENTINEL_GATEWAY_TOKEN
Run: python src/sensors/uploader.py <file.har|file.jsonl>
"""
from __future__ import annotations

import os
import sys

import httpx

BACKEND = os.getenv("SENTINEL_BACKEND", "http://127.0.0.1:8000").rstrip("/")
SESSION_ID = os.getenv("SENTINEL_SESSION_ID", "").strip()
TOKEN = os.getenv("SENTINEL_GATEWAY_TOKEN", "").strip()


def main(path: str) -> None:
    if not SESSION_ID or not TOKEN:
        raise SystemExit("Run Setup first, then set SENTINEL_SESSION_ID and SENTINEL_GATEWAY_TOKEN.")
    with open(path, "rb") as f:
        files = {"file": (os.path.basename(path), f.read())}
    r = httpx.post(
        f"{BACKEND}/api/ingest/upload", files=files,
        headers={"X-Sentinel-Session": SESSION_ID, "X-Sentinel-Token": TOKEN}, timeout=60,
    )
    r.raise_for_status()
    print(f"[uploader] {path} -> {r.json()}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python uploader.py <file.har|file.json|file.jsonl>")
        raise SystemExit(1)
    main(sys.argv[1])
