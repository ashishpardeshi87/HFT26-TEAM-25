"""Clear polluted agent state (reground/quarantine/denials) from failed demo
runs while PRESERVING the monitoring session + gateway token. Also clears old
incidents/evidence so the next run produces a single clean external incident."""
import json, os

base = os.path.join(os.path.dirname(__file__), ".sentinel")
sp = os.path.join(base, "state.json")

d = json.load(open(sp, encoding="utf-8"))
for sid, sess in (d.get("sessions") or {}).items():
    for aid, st in (sess.get("agent_state") or {}).items():
        st["reground_required"] = False
        st["reground_context"] = None
        st["last_reground_ack"] = None
        st["quarantined"] = False
        st["quarantine"] = None
        st["capability_epoch"] = 1
        st["history"] = []
    sess["quarantined_agents"] = {}
    sess["denial_counts"] = {}
d["wordlists"] = {}
d["investigations"] = {}
d["approvals"] = {}

json.dump(d, open(sp, "w", encoding="utf-8"), indent=2)

for f in ("state.json.bak", "evidence.jsonl", "incidents.json"):
    try:
        os.remove(os.path.join(base, f))
    except FileNotFoundError:
        pass

print("RESET OK: agent state cleared, incidents/evidence removed, session preserved")
for sid, sess in (d.get("sessions") or {}).items():
    print("  session", sid, "status", sess.get("status"), "agents", list((sess.get("agent_state") or {}).keys()))
