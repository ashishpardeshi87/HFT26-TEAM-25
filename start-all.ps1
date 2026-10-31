# SENTINEL APEX — launch the local integrated stack in separate windows.
# Usage: .\start-all.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$workspace = Split-Path $root -Parent
$backend = Join-Path $root 'src\backend'
$frontend = Join-Path $root 'src\web'
$darkguardBackend = Join-Path $workspace 'darkguard\darkguard.in\backend'
$darkguardScraper = Join-Path $workspace 'darkguard\darkguard.in\scraper'

function Test-ListeningPort([int]$Port) {
  return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

if (-not (Test-Path (Join-Path $backend '.venv'))) {
  Write-Host '[setup] creating SENTINEL backend venv + installing deps...' -ForegroundColor Cyan
  Push-Location $backend
  python -m venv .venv
  .\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
  Pop-Location
}
if (-not (Test-Path (Join-Path $frontend 'node_modules'))) {
  Write-Host '[setup] installing SENTINEL web deps...' -ForegroundColor Cyan
  Push-Location $frontend
  npm install
  Pop-Location
}

# Start the existing DarkGuard services when that sibling project is present.
if (Test-Path $darkguardBackend) {
  if (-not (Test-Path (Join-Path $darkguardBackend 'node_modules'))) {
    Write-Host '[setup] installing DarkGuard backend deps...' -ForegroundColor Cyan
    Push-Location $darkguardBackend
    npm ci
    Pop-Location
  }
  if (-not (Test-ListeningPort 8080)) {
    Write-Host '[run] DarkGuard API -> http://127.0.0.1:8080' -ForegroundColor Green
    Start-Process powershell -WorkingDirectory $darkguardBackend -ArgumentList @('-NoExit', '-Command', 'npm start')
  } else { Write-Host '[reuse] DarkGuard API already listening on :8080' -ForegroundColor DarkGreen }
}
if ((Test-Path $darkguardScraper) -and (Test-Path (Join-Path $darkguardScraper '.venv\Scripts\python.exe'))) {
  if (-not (Test-ListeningPort 9000)) {
    Write-Host '[run] DarkGuard scraper -> http://127.0.0.1:9000' -ForegroundColor Green
    Start-Process powershell -WorkingDirectory $darkguardScraper -ArgumentList @('-NoExit', '-Command', '.\.venv\Scripts\python.exe run.py')
  } else { Write-Host '[reuse] DarkGuard scraper already listening on :9000' -ForegroundColor DarkGreen }
}

$backendCommand = '.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000'
if (Test-Path (Join-Path $backend '.env')) { $backendCommand += ' --env-file .env' }
Write-Host '[run] SENTINEL API -> http://127.0.0.1:8000' -ForegroundColor Green
if (-not (Test-ListeningPort 8000)) {
  Start-Process powershell -WorkingDirectory $backend -ArgumentList @('-NoExit', '-Command', $backendCommand)
} else { Write-Host '[reuse] SENTINEL API already listening on :8000' -ForegroundColor DarkGreen }

Write-Host '[run] SENTINEL web -> http://127.0.0.1:4173' -ForegroundColor Green
if (-not (Test-ListeningPort 4173)) {
  Start-Process powershell -WorkingDirectory $frontend -ArgumentList @('-NoExit', '-Command', 'npm run dev')
} else { Write-Host '[reuse] SENTINEL web already listening on :4173' -ForegroundColor DarkGreen }

Write-Host ''
Write-Host 'Open http://127.0.0.1:4173/app — Setup is the first page.' -ForegroundColor Yellow
Write-Host 'DarkGuard auth stays in src\backend\.env. Tor must listen on 127.0.0.1:9050 for live onion fingerprints; otherwise readiness is DEGRADED.' -ForegroundColor DarkYellow
