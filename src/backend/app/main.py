"""SENTINEL APEX API bootstrap."""

from fastapi import FastAPI

app = FastAPI(
    title="SENTINEL APEX",
    description="AI security monitoring prototype",
    version="0.1.0",
)


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Return process readiness without exposing configuration details."""
    return {"status": "ok", "service": "sentinel-apex"}
