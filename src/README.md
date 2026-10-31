# Public Prototype Slice

This source tree is a runnable, sanitized vertical slice used to verify repository structure and local service wiring.

```text
src/
├── backend/   FastAPI health + non-persistent sample heartbeat
├── web/       React/Vite status page and heartbeat form
└── sensors/   One-shot heartbeat client
```

## Run

```powershell
# terminal 1
cd src\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# terminal 2
cd src\web
npm install
npm run dev

# optional one-shot client
cd src\sensors
python -m pip install -r requirements.txt
python heartbeat.py
```

Open `http://127.0.0.1:4173`.

The heartbeat is acknowledged but not stored. This public slice does not contain production monitoring, security-policy, detection, investigation, or integration logic.
