# Serve a static folder on the LAN for the APEX external-intervention test.
# Used by BOTH the target laptop and the attacker laptop.
#
#   Target  : .\serve-site.ps1 -Path .\target-site   -Port 8080
#   Attacker: .\serve-site.ps1 -Path .\attacker-site -Port 9090
#
# Binds 0.0.0.0 so the monitoring/agent laptops can reach it over the LAN.
# Open the port in Windows Firewall if peers cannot connect.
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [int]$Port = 8080,
  [string]$Bind = "0.0.0.0"
)
$ErrorActionPreference = "Stop"
$full = (Resolve-Path $Path).Path
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue) }
if (-not $py) { throw "Python is required (python -m http.server)." }

$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
       Select-Object -First 1 -ExpandProperty IPAddress)
Write-Host "Serving $full" -ForegroundColor Green
Write-Host "  local    : http://$ip`:$Port/" -ForegroundColor Yellow
Write-Host "  bind     : $Bind`:$Port" -ForegroundColor DarkGray
& $py.Source -m http.server $Port --bind $Bind --directory $full
