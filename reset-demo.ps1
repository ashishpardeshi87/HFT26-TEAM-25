# FAST demo reset (run on the MONITOR laptop between runs for the judges).
# Clears the agent/incident/taint state and restarts ONLY the SENTINEL backend.
# Tor, the DarkGuard scraper, DarkGuard API, and the web UI keep running, so this
# takes ~5 seconds (no Tor re-bootstrap). The monitoring session + gateway token
# are preserved, so Laptop 2 keeps the same session id / token.
$ErrorActionPreference = 'SilentlyContinue'
$backend = 'd:\CBIT Hacktoberfest\sentinel-apex\src\backend'

Write-Host '[1/3] Stopping the SENTINEL backend...' -ForegroundColor Yellow
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq 'cmd.exe' -and $_.CommandLine -match 'title SENTINEL-API' } |
  ForEach-Object { & taskkill /PID $_.ProcessId /T /F 2>$null | Out-Null }
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty OwningProcess -Unique |
  ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Write-Host '[2/3] Clearing agent + incident state (session preserved)...' -ForegroundColor Yellow
& "$backend\.venv\Scripts\python.exe" "$backend\reset_agent_state.py"

Write-Host '[3/3] Restarting the backend (LAN) in a visible window...' -ForegroundColor Green
Start-Process cmd -ArgumentList '/k title SENTINEL-API & .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env' -WorkingDirectory $backend

Write-Host ''
Write-Host 'Reset complete. Wait ~5 seconds, hard-refresh the Monitor browser (Ctrl+Shift+R),' -ForegroundColor Cyan
Write-Host 'then re-run the agent on Laptop 2.' -ForegroundColor Cyan
