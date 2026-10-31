"""SENTINEL Agent — process↔network sensor (PS requirement 1).

Passively polls local established connections with psutil, attributes each to its
owning process, and emits an event when the destination looks like an AI provider
(local LLM by port, or a cloud provider by best-effort reverse DNS). No packets are
decrypted; this reads only connection metadata the OS already exposes.

Run:  python src/sensors/process_sensor.py
"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app import providers  # noqa: E402  (reuse the provider catalog)
from sensors.common import configured, heartbeat, send_event  # noqa: E402

HOSTNAME = socket.gethostname()
_seen: dict[tuple, float] = {}
_dns: dict[str, str] = {}


def _rdns(ip: str) -> str:
    if ip in _dns:
        return _dns[ip]
    try:
        socket.setdefaulttimeout(0.4)
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ""
    _dns[ip] = host
    return host


def poll_once() -> int:
    emitted = 0
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        print(f"[process_sensor] need elevation? {e}")
        return 0

    now = time.time()
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        rip, rport = c.raddr.ip, c.raddr.port
        host = _rdns(rip) if rport not in providers.LOCAL_LLM_PORTS else "127.0.0.1"
        cls = providers.classify(host=host, ip=rip, port=rport)
        if cls["provider"] == "unknown":
            continue

        key = (c.pid, rip, rport)
        if now - _seen.get(key, 0) < 30:
            continue
        _seen[key] = now

        pname, cmd = "unknown", ""
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                pname = p.name()
                cmd = " ".join(p.cmdline()[:6])
            except Exception:
                pass

        send_event({
            "source": "process", "host": HOSTNAME, "event_type": "ai_provider_connection",
            "process": {"name": pname, "pid": c.pid or 0, "cmdline": cmd},
            "destination": {"host": host, "ip": rip, "port": rport},
            "meta": {"agent_id": pname, "sensor": "psutil-process-network-v1"},
        })
        print(f"[process_sensor] {pname} (pid {c.pid}) -> {cls['provider']} [{host or rip}:{rport}]")
        emitted += 1
    return emitted


def main() -> None:
    if not configured():
        raise SystemExit("Run Setup first, then export SENTINEL_SESSION_ID and SENTINEL_GATEWAY_TOKEN.")
    print(f"[process_sensor] watching {HOSTNAME} — authenticated session telemetry. Ctrl+C to stop.")
    last_heartbeat = 0.0
    while True:
        if time.time() - last_heartbeat >= 15:
            heartbeat(); last_heartbeat = time.time()
        poll_once()
        time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[process_sensor] stopped.")
