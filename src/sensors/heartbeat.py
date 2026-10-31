"""Send one benign heartbeat to the public sample API."""

import json
import os
from pathlib import Path

import httpx

BASE_URL = os.getenv("SENTINEL_SAMPLE_URL", "http://127.0.0.1:8000").rstrip("/")
SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "heartbeat.json"


def main() -> None:
    payload = json.loads(SAMPLE.read_text(encoding="utf-8"))
    response = httpx.post(f"{BASE_URL}/sample/heartbeat", json=payload, timeout=5)
    response.raise_for_status()
    print(response.json())


if __name__ == "__main__":
    main()
