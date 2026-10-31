# Terminate this workspace's existing stack (including orphaned launch windows),
# then relaunch every service in its own VISIBLE, titled terminal window.
#
# Local only:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\start-stack-visible.ps1
# Four-laptop LAN demo:
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\start-stack-visible.ps1 -Lan
#
# Windows: TOR, DARKGUARD-SCRAPER, DARKGUARD-API, SENTINEL-API, SENTINEL-WEB
param([switch]$Lan)
$ErrorActionPreference = 'SilentlyContinue'
$dg = 'd:\CBIT Hacktoberfest\darkguard\darkguard.in'
$sa = 'd:\CBIT Hacktoberfest\sentinel-apex'
$bind = if ($Lan) { '0.0.0.0' } else { '127.0.0.1' }

Write-Host '[1/2] Terminating old stack processes and launch windows ...' -ForegroundColor Yellow
# Close prior /k windows as process trees. Killing only their listening child can
# leave a backend process alive long enough to rewrite stale state during reset.
$launchers = Get-CimInstance Win32_Process | Where-Object {
  $_.Name -eq 'cmd.exe' -and $_.CommandLine -match 'title (TOR|DARKGUARD-SCRAPER|DARKGUARD-API|SENTINEL-API|SENTINEL-WEB)'
}
foreach ($process in $launchers) {
  & taskkill.exe /PID $process.ProcessId /T /F 2>$null | Out-Null
}

foreach ($port in 8000, 4173, 8080, 9000, 9050, 9051, 8765, 9090) {
  Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
}
Start-Sleep -Seconds 2

Write-Host "[2/2] Launching services (SENTINEL bind $bind) ..." -ForegroundColor Green
Start-Process cmd -ArgumentList "/k title TOR & tor\tor.exe -f torrc.local" -WorkingDirectory "$dg\tools\tor"
Start-Process cmd -ArgumentList "/k title DARKGUARD-SCRAPER & .venv\Scripts\python.exe run.py" -WorkingDirectory "$dg\scraper"
Start-Process cmd -ArgumentList "/k title DARKGUARD-API & npm start" -WorkingDirectory "$dg\backend"
Start-Process cmd -ArgumentList "/k title SENTINEL-API & .venv\Scripts\python.exe -m uvicorn app.main:app --host $bind --port 8000 --env-file .env" -WorkingDirectory "$sa\src\backend"
# The browser stays local to the monitoring laptop. Only the authenticated
# SENTINEL API is exposed to the private LAN for the agent harness.
Start-Process cmd -ArgumentList "/k title SENTINEL-WEB & npm run dev" -WorkingDirectory "$sa\src\web"

Write-Host ''
if ($Lan) {
  $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress
  Write-Host "LAN mode. Monitoring laptop IPv4 candidate(s): $($ips -join ', ')" -ForegroundColor Cyan
  Write-Host 'Open locally: http://127.0.0.1:4173/app' -ForegroundColor Cyan
  Write-Host 'Agent backend: http://<MONITOR-IP>:8000' -ForegroundColor Cyan
} else {
  Write-Host 'Open http://127.0.0.1:4173/app once SENTINEL-WEB is ready.' -ForegroundColor Cyan
}
Write-Host 'Tor needs ~15-60s to bootstrap before Tor Finder shows an exit IP.' -ForegroundColor DarkYellow
