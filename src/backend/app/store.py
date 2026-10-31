"""Durable, tamper-evident local Evidence Store with async pub/sub.

Events are redacted before they reach this module. Each append is chained to the
previous SHA-256 hash and written as JSONL. Incidents are snapshotted separately.
Optional off-box checkpointing anchors the chain head outside the monitored host.
A local hash chain detects accidental/low-privilege tampering; it is not claimed
to survive an attacker with full control unless remote anchoring is configured.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from collections import deque
from pathlib import Path

import httpx

from .models import Event, Incident


class Store:
    def __init__(self, maxlen: int = 500) -> None:
        self.events: deque[Event] = deque(maxlen=maxlen)
        self.incidents: dict[str, Incident] = {}
        self._order: deque[str] = deque(maxlen=maxlen)
        self._subs: set[asyncio.Queue] = set()
        self._lock = threading.RLock()
        self._records: deque[dict] = deque(maxlen=maxlen)
        self._head = "0" * 64
        self._count = 0
        self._last_anchor_count = 0
        default_dir = Path(__file__).resolve().parents[1] / ".sentinel"
        self._dir = Path(os.getenv("SENTINEL_DATA_DIR") or str(default_dir)).expanduser().resolve()
        self._events_path = self._dir / "evidence.jsonl"
        self._incidents_path = self._dir / "incidents.json"
        self._sign_key = os.getenv("SENTINEL_EVIDENCE_HMAC_KEY", "").encode()
        self._load()

    def _canonical(self, value: dict) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _load(self) -> None:
        try:
            lines = self._events_path.read_text(encoding="utf-8").splitlines()
            for line in lines[-self.events.maxlen:]:
                rec = json.loads(line)
                self._records.append(rec)
                self.events.appendleft(Event.model_validate(rec["event"]))
                self._head = rec["hash"]
                self._count = max(self._count, int(rec.get("seq", 0)))
        except FileNotFoundError:
            pass
        except Exception:
            # Keep the evidence file untouched and expose integrity failure.
            self._head = "load-error"
        try:
            raw = json.loads(self._incidents_path.read_text(encoding="utf-8"))
            for item in raw:
                inc = Incident.model_validate(item)
                self.incidents[inc.incident_id] = inc
                self._order.append(inc.incident_id)
        except FileNotFoundError:
            pass
        except Exception:
            self.incidents.clear(); self._order.clear()

    # ---- writes
    def add_event(self, ev: Event) -> None:
        with self._lock:
            event = json.loads(ev.model_dump_json())
            base = {"seq": self._count + 1, "previous_hash": self._head,
                    "acquired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "event": event}
            digest = hashlib.sha256(self._canonical(base)).hexdigest()
            rec = {**base, "hash": digest}
            if self._sign_key:
                rec["hmac_sha256"] = hmac.new(self._sign_key, digest.encode(), hashlib.sha256).hexdigest()
            self._dir.mkdir(parents=True, exist_ok=True)
            with self._events_path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._head = digest
            self._count += 1
            self._records.append(rec)
            self.events.appendleft(ev)

    def upsert_incident(self, inc: Incident) -> None:
        with self._lock:
            if inc.incident_id not in self.incidents:
                self._order.appendleft(inc.incident_id)
            self.incidents[inc.incident_id] = inc
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp = self._incidents_path.with_suffix(".tmp")
            ordered = [json.loads(self.incidents[i].model_dump_json()) for i in self._order if i in self.incidents]
            tmp.write_text(json.dumps(ordered, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self._incidents_path)

    # ---- reads
    def recent_events(self, n: int = 50, session_id: str = "") -> list[Event]:
        values = list(self.events)
        if session_id:
            values = [e for e in values if e.session_id == session_id]
        return values[:n]

    def recent_incidents(self, n: int = 50, session_id: str = "") -> list[Incident]:
        values = [self.incidents[i] for i in list(self._order) if i in self.incidents]
        if session_id:
            values = [i for i in values if i.signals.get("session_id") == session_id]
        return values[:n]

    def get_incident(self, iid: str) -> Incident | None:
        return self.incidents.get(iid)

    def events_by_ids(self, ids: list[str]) -> list[Event]:
        by_id = {e.id: e for e in self.events}
        return [by_id[i] for i in ids if i in by_id]

    def read_session_evidence(self, session_id: str = "") -> dict:
        """Read and verify the complete evidence.jsonl chain under the store lock.

        This is the report/classification path. It intentionally does not use the
        bounded UI deque, and it returns only redacted Event records.
        """
        with self._lock:
            selected_records: list[dict] = []
            selected_events: list[Event] = []
            previous = "0" * 64
            checked = 0
            error = None
            try:
                with self._events_path.open("r", encoding="utf-8") as fh:
                    for line_number, line in enumerate(fh, start=1):
                        if not line.strip():
                            continue
                        try:
                            rec = json.loads(line)
                            if int(rec.get("seq", 0)) != checked + 1:
                                raise ValueError("non-contiguous sequence")
                            if rec.get("previous_hash") != previous:
                                raise ValueError("previous-hash mismatch")
                            base = {k: rec[k] for k in ("seq", "previous_hash", "acquired_at", "event")}
                            expected = hashlib.sha256(self._canonical(base)).hexdigest()
                            if not hmac.compare_digest(expected, str(rec.get("hash", ""))):
                                raise ValueError("record hash mismatch")
                            if self._sign_key:
                                signature = hmac.new(self._sign_key, expected.encode(), hashlib.sha256).hexdigest()
                                if not hmac.compare_digest(signature, str(rec.get("hmac_sha256", ""))):
                                    raise ValueError("record HMAC mismatch")
                            event = Event.model_validate(rec["event"])
                        except Exception as exc:
                            error = f"line {line_number}: {exc}"
                            break
                        checked += 1
                        previous = expected
                        if not session_id or event.session_id == session_id:
                            selected_records.append(rec)
                            selected_events.append(event)
            except FileNotFoundError:
                pass
            except Exception as exc:
                error = str(exc)

            integrity = {
                "ok": error is None and self._head != "load-error",
                "checked": checked,
                "head": previous,
                "records_total": checked,
                "session_records": len(selected_records),
                "hmac_enabled": bool(self._sign_key),
                "error": error,
                "scope": "complete evidence.jsonl chain",
            }
            return {"records": selected_records, "events": selected_events, "integrity": integrity}

    def events_by_ids_durable(self, ids: list[str], session_id: str = "") -> list[Event]:
        wanted = set(ids)
        evidence = self.read_session_evidence(session_id)
        by_id = {event.id: event for event in evidence["events"] if event.id in wanted}
        return [by_id[event_id] for event_id in ids if event_id in by_id]

    def session_incidents(self, session_id: str) -> list[Incident]:
        with self._lock:
            values = [
                incident for incident in self.incidents.values()
                if incident.signals.get("session_id") == session_id
            ]
        return sorted(values, key=lambda incident: incident.opened)

    def save_session_report(self, session_id: str, report: dict) -> dict:
        """Atomically persist the terminal report snapshot outside mutable state.json."""
        with self._lock:
            reports_dir = self._dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            name = hashlib.sha256(session_id.encode("utf-8")).hexdigest() + ".json"
            path = reports_dir / name
            tmp = path.with_suffix(".tmp")
            raw = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
            with tmp.open("w", encoding="utf-8", newline="\n") as fh:
                fh.write(raw)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            return {
                "stored": True,
                "report_hash": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "path": str(path),
            }

    def load_session_report(self, session_id: str) -> dict | None:
        with self._lock:
            name = hashlib.sha256(session_id.encode("utf-8")).hexdigest() + ".json"
            path = self._dir / "reports" / name
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                return value if isinstance(value, dict) else None
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                return None

    def stats(self, session_id: str = "") -> dict:
        incs = self.recent_incidents(self.events.maxlen, session_id)
        events = self.recent_events(self.events.maxlen, session_id)
        providers: dict[str, int] = {}
        approved = unapproved = 0
        for ev in events:
            p = ev.destination.provider
            if p and p != "unknown":
                providers[p] = providers.get(p, 0) + 1
            if ev.destination.approval == "approved": approved += 1
            elif ev.destination.approval == "unapproved": unapproved += 1
        findings = sum(len(e.findings) for e in events)
        risky = sum(1 for e in events if e.behavior)
        top = max((i.score for i in incs), default=0)
        by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in incs:
            by_level[i.level] = by_level.get(i.level, 0) + 1
        return {
            "risk_score": min(100, top), "events": len(events), "incidents": len(incs),
            "by_level": by_level, "providers": providers, "approved": approved,
            "unapproved": unapproved, "sensitive_findings": findings, "data_leaks": findings,
            "risky_agents": risky, "score_note": "illustrative supporting signal; explicit policy drives enforcement",
        }

    # ---- integrity
    def verify_chain(self) -> dict:
        """Verify the complete durable chain, not only the bounded UI cache."""
        return self.read_session_evidence()["integrity"]

    def integrity_status(self) -> dict:
        remote = bool(os.getenv("SENTINEL_ANCHOR_URL"))
        return {**self.verify_chain(),
                "remote_anchor_configured": remote,
                "limit": ("Off-box checkpoints configured." if remote else
                          "Local chain only: an attacker with full host control may rewrite it. Configure SENTINEL_ANCHOR_URL and keep its key off-host.")}

    async def anchor_if_due(self) -> None:
        url = os.getenv("SENTINEL_ANCHOR_URL", "").strip()
        every = max(1, int(os.getenv("SENTINEL_ANCHOR_EVERY", "25")))
        if not url or self._count - self._last_anchor_count < every:
            return
        token = os.getenv("SENTINEL_ANCHOR_TOKEN", "").strip()
        payload = {"chain_head": self._head, "records": self._count,
                   "checkpointed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
                r = await client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"} if token else {})
                r.raise_for_status()
                self._last_anchor_count = self._count
        except Exception:
            # Monitoring continues but integrity status stays local/unanchored.
            pass

    # ---- pub/sub
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100); self._subs.add(q); return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    async def publish(self, message: dict) -> None:
        for q in list(self._subs):
            try: q.put_nowait(message)
            except asyncio.QueueFull: pass


store = Store()
