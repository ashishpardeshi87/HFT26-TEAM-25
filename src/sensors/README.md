# Public Sensor Sample

`heartbeat.py` sends one benign, non-persistent heartbeat from `samples/heartbeat.json` to the public sample API.

```powershell
python -m pip install -r requirements.txt
python heartbeat.py
```

The production monitoring sensor and security event schema are intentionally outside this public sample slice.
