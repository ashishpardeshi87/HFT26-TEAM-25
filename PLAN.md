# 🛡️ SENTINEL APEX — Build Plan & Playbook

*CBIT Hacktoberfest '26 · AI Security & Data Privacy · Team "The Nice Guys"*

Operational companion to [README.md](./README.md): scope tiers, the hour-by-hour timeline, who builds what, the demo script, and what breaks at a venue.

> ⚠️ **You have ~20 hours of build time, not 24.** Coding starts 30 Oct 7:00 PM. Submissions open 31 Oct 2:00 PM and **hard code-freeze is 3:00 PM**. Plan to submit by **2:30 PM** with a recorded video already in hand.

> 🎯 **The one thing that wins this:** a live demo where three separate signals fuse into *one* correlated incident with a 0–100 score and an AI explanation. Everything below serves that moment.

---

## 1. Scope tiers — build in this order, never out of order

Finish each tier end-to-end (source → engine → correlation → dashboard) before starting the next. A thin slice that demos beats a wide slice that doesn't.

### 🟢 MVP — must exist for the demo (target: done by ~hour 14, i.e. 9 AM)
1. **Telemetry Collection + Process sensor → backend → live dashboard feed.** One real signal flowing end to end is the single most important milestone.
2. **AI Provider Fingerprinting → Shadow AI Detection** + `providers.yaml` (cloud hosts + local ports, approved/unapproved tag).
3. **Secret / PII Detection** (regex + Shannon entropy; Presidio + **Aadhaar/PAN**).
4. **Uploader** path (HAR / PCAP / JSONL) — the demo-safe fallback that needs no admin and no live internet.
5. **Risk Correlation Engine** — group events by process/host/time window into one incident. *This is the differentiator; do not skip it.*
6. **Threat Scoring** (0–100) + **Dashboard**: Overview, Data Leakage, live incident feed, masked evidence.
7. **Featherless Copilot** on an incident (explanation + one-line remediation).
8. **One agent-behavior detection**: an AI-agent process spawning a shell **or** reading `.env`.

### 🟡 Stretch — the "wow", if MVP is solid (hours 14–18)
9. **Browser extension** capturing a ChatGPT/Claude prompt *before encryption*.
10. **Packet sensor**: scapy reading a full plaintext prompt sent to local **Ollama** on :11434.
11. **DarkGuard external-exposure panel** (Threat Intelligence tab).
12. **Copilot Q&A** over recorded evidence ("which apps are unapproved?", "explain this incident").

### 🔴 Moonshot — only if you're ahead (hours 18–20)
13. Live block/warn toast, PDF compliance report export, policy-allowlist editor.

**Rule:** at every tier boundary, commit, deploy, confirm the demo still runs. If a stretch item isn't working by **11:00 AM**, cut it and polish the MVP.

> **Scope & provenance note:** the **autonomous pentest engine stays out** (README §10 Future Vision only) — too off-topic and risky for the time. **DarkGuard goes in** as `src/darkguard/`, clearly marked as the team's pre-existing, attributed open-source component (its own LICENSE + a "prior work" note in the README). The hackathon-built work is the SENTINEL APEX platform around it: telemetry agent, detection engines, the Risk Correlation Engine, scoring, copilot, dashboard, and all integration code. Keep that line crisp so a judge sees what's new vs. reused.

---

## 2. Team roles

Team of **4**. Swap to match each person's actual strengths.

| Dev | Owns | Primary files |
|---|---|---|
| **Vishnu Varma — Backend & detection** | FastAPI, event/incident schema, WebSocket, secret + PII engines, scoring, SQLite | `src/backend/**` |
| **Saifullah Pathan — Sensors / local agent** | Process sensor, packet sensor, agent sensor, uploader, provider catalog | `src/sensors/**`, `data/providers.yaml` |
| **Shruti Sadgir — Frontend** | React Command Center, charts, incident feed, risk gauge, evidence drawer | `src/dashboard/**` |
| **Ashish Pardeshi (Lead) — Correlation, AI, DarkGuard & demo** | **Risk Correlation Engine**, Featherless copilot, DarkGuard integration, browser extension, deploy, video + pitch | `src/backend/engines/correlate.py`, `copilot/**`, `src/darkguard/**`, `src/extension/**` |

**The contract that unblocks parallel work:** freeze the **event + incident schema** (README §4) in the first 30 minutes. Once Vishnu publishes it with a `POST /events` endpoint and `samples/requests.jsonl`, Saifullah emits events, Shruti renders them, Ashish builds correlation — nobody waits.

---

## 3. Hour-by-hour timeline

### Before 7:00 PM — pre-flight (during opening / PS lock-in)
- [ ] All laptops: **Python 3.11**, **Node 18+**, **Git**, **Npcap** (tick *loopback* + *WinPcap-compatible*), **Ollama** (`ollama pull llama3.2:1b`).
- [ ] Pre-download the spaCy model (`python -m spacy download en_core_web_lg`, ~500 MB) — not on venue Wi-Fi at hour 10.
- [ ] **Featherless API key** working (ask organizers about the $300 partner credits); one successful call confirmed.
- [ ] Repo cloned; `.gitignore`, `LICENSE` (MIT), README + PLAN committed. **Every member pushes one commit now.**
- [ ] Mobile hotspot ready as Wi-Fi backup.

### 7:00–8:00 PM — scaffold + the schema contract
- A: FastAPI skeleton, `schemas.py` (event + incident), `POST /events`, `GET /ws`, SQLite init. Publish the schema.
- B: `providers.yaml` from README; `sensors/common` event-client that POSTs to the backend.
- C: Vite + React + Tailwind skeleton; connect to `/ws`; render a raw event list.
- D: Confirm Featherless + DarkGuard calls with `curl`; stub `correlate.py`, `copilot/featherless.py`, `bridge/darkguard.py`.
- ✅ **8 PM: a hand-posted event appears live in the dashboard.**

### 8:00 PM–12:00 AM — MVP core
- B: Process sensor (psutil → PID → remote host:port → provider) and the Uploader (HAR first).
- A: Secret detector (signatures + entropy) + PII detector (Presidio + Aadhaar/PAN); emit findings on events.
- D: **Correlation engine** joining events into incidents; scoring; first Featherless explanation.
- C: Overview tab (risk gauge, usage-by-provider), incident feed with severity colours + masked evidence drawer.
- ✅ **12 AM: upload `sample.har` → secrets + PII detected → correlated into one incident → scored → AI explanation shown.**

### 12:00–1:00 AM — Ice-Breaker 1
Eat, **commit and push**, redeploy, confirm the demo runs on a second machine.

### 1:00–6:00 AM — stretch features
- D: Browser extension end to end (type in ChatGPT → event → incident); DarkGuard exposure panel.
- B: Packet sensor on loopback reading an Ollama prompt; agent-behavior sensor (shell spawn / `.env` read / dangerous flag).
- A: Harden correlation (dedupe, time windows), per-app rollup, `GET /incidents`, `GET /stats`.
- C: Agent-behaviour tab, DarkGuard panel UI, copilot chat box, empty/error states.
- ✅ **6 AM: at least one stretch feature fully demoable.**

### 6:00–8:00 AM — morning sprint
Freeze feature edges. Fix the top 3 demo-breaking bugs. Seed a clean dataset with `scripts/seed_demo.py`.

### 8:00–9:00 AM — Ice-Breaker 2
Breakfast. **Record the backup demo video now** while everything works.

### 9:00 AM–12:00 PM — polish + README
- Finalize setup steps; a judge must be able to `pip install -r requirements.txt` and run it.
- UI pass: colours, logo, risk gauge, the "95 → 60" score-drop animation.
- Deploy dashboard → Vercel, backend → Render/Railway. Confirm the public link.

### 12:00–2:00 PM — freeze, rehearse, submit
- **Stop writing features at 12:30 PM.** Bug-fixes only.
- Rehearse the 3-minute demo **twice**, out loud, on the clock.
- **Submit by 2:30 PM**: repo, README, live link, video. Don't wait for 3:00 PM.

### 2:00–3:00 PM — presentations
Lead with the problem and the live correlated incident, not the architecture diagram.

---

## 4. The 3-minute demo script

The spine is the correlation moment. Judges score *code quality, technical execution, innovation* — show all three fast.

1. **(0:00–0:30) Hook.** "~40% of what employees paste into AI tools is sensitive; shadow AI was in 43% of 2026 breaches; security sees none of it. Meet SENTINEL APEX." Dashboard open, risk score green ~95, zero incidents.
2. **(0:30–1:15) Live leak → local AI.** Send a prompt with a fake AWS key + Aadhaar number to local Ollama. A **critical** incident appears instantly, naming the process and the masked secret. "No SSL decryption — we read it at the process and packet layer."
3. **(1:15–1:55) Browser trick → cloud.** Paste a fake customer list into ChatGPT in the browser. The extension flags the PII **before the browser encrypted it.** "That's how we beat Encrypted Client Hello — we catch the prompt, not the packet."
4. **(1:55–2:25) The correlation payoff.** Run a toy agent that executes `Get-Content .env`, then opens a connection. SENTINEL APEX **fuses the shadow-AI connection + the secret + the agent's file read into ONE incident**, score jumps to 91. "This is the s1ngularity pattern — and instead of three disconnected alerts, it's one investigation."
5. **(2:25–2:55) Closer.** Open the incident → DarkGuard panel shows the leaked domain is *already* on a breach DB; the Featherless copilot explains the risk and the fix in plain English. "Left of boom, right of boom, one incident, one score, one explanation."

Backup: if live capture fails on venue Wi-Fi, switch to the **Uploader** path (`sample.har`) — same pipeline, same incident. Keep the pre-recorded video as the ultimate fallback.

---

## 5. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Npcap / admin blocked on venue machine | Medium | Process sensor (psutil) + Uploader need **no** admin. Packet sensor is stretch, not core. |
| Encrypted Client Hello hides SNI | Medium | That's *why* we have the browser extension + process-layer mapping. Lead with those. |
| spaCy / Presidio download mid-event | High if not pre-done | **Pre-download in pre-flight.** Regex-only PII fallback flag. |
| Featherless credits / rate limit | Medium | Cache results; `temperature:0`; fall back to a local Ollama judge. Copilot is enrichment, never the detector. |
| DarkGuard API needs a token | Medium | Enrichment only; MVP stands alone. It uses Firebase bearer tokens — confirm early; if blocked, keep the panel behind a flag with a captioned "live API" note. |
| Correlation looks like "just grouping" | Medium | Show the score math and the AI explanation; make the join criteria (process+host+window) visible in the incident. |
| Live capture flaky on stage | Medium | Uploader path + pre-recorded video. One failed packet must not sink the pitch. |
| Scope creep (pentest/dark-web pull) | **High** | §1 tier rules + the out-of-scope note. If a stretch item isn't up by 11 AM, cut it. |
| Only some members commit | Medium | Everyone commits in pre-flight and at every milestone. It's graded. |

---

## 6. Pre-flight checklist (print this)

**Bring:** original college IDs, admit pass QR, laptops + chargers, **Ethernet adapter**, extension board/power strip, mobile hotspot.

**Each laptop:**
- [ ] Python 3.11 + pip, Node 18+, Git
- [ ] Npcap installed (loopback + WinPcap-compatible)
- [ ] Ollama + a small model pulled
- [ ] spaCy `en_core_web_lg` pre-downloaded
- [ ] Repo cloned, editor ready, one commit pushed
- [ ] Featherless key tested, DarkGuard reachable

---

## 7. Open questions (answer these and I'll scaffold the repo)

1. **Team size + each person's strengths** (Python? React? security? DevOps?) — to lock the role split.
2. **DarkGuard API token / keyless scan endpoint?** Decides whether the exposure panel is a live call or a flagged mock.
3. **Primary demo OS** — all Windows or mixed? (Affects packet sensor + file paths.)
4. **Live deploy or video-first?** Recommendation: deploy the dashboard for the "live link" box, but make the **video** the primary proof since sensors are local.

Say the word and I'll scaffold the repo (FastAPI skeleton, event/incident schema, `providers.yaml`, correlation stub, dashboard shell, sample files) so you code at 7:00 PM instead of configuring.
