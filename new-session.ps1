# Wipe ALL runtime state and restart only the backend, so you can create a
# brand-new monitoring session (use when the previous session was ENDED).
# Tor, the DarkGuard scraper/API, and the web UI keep running.
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

Write-Host '[2/3] Wiping runtime state (sessions, evidence, incidents)...' -ForegroundColor Yellow
Remove-Item -Force `
  "$backend\.sentinel\state.json", `
  "$backend\.sentinel\state.json.bak", `
  "$backend\.sentinel\evidence.jsonl", `
  "$backend\.sentinel\incidents.json" -ErrorAction SilentlyContinue

Write-Host '[3/3] Restarting the backend (clean, no session)...' -ForegroundColor Green
Start-Process cmd -ArgumentList '/k title SENTINEL-API & .venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env' -WorkingDirectory $backend

Write-Host ''
Write-Host 'Backend is clean. Now do a fresh Setup in the browser (see the steps).' -ForegroundColor Cyan
