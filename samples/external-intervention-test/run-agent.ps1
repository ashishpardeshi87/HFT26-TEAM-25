# Configure and launch the APEX test agent (AI-AGENT laptop).
# Fill in the four values from the monitoring laptop's Setup page, then run:
#   .\run-agent.ps1                 # full scenario (benign -> inject -> exfil)
#   .\run-agent.ps1 -Mode benign    # only the in-policy baseline
#   .\run-agent.ps1 -Mode attack    # only the injection + exfil
param(
  [ValidateSet("all", "benign", "attack")][string]$Mode = "all",
  [string]$Backend,
  [string]$SessionId,
  [string]$Token,
  [string]$AttackerNoticeUrl,
  [string]$TargetUrl,
  [string]$AgentId = "campus-copilot",
  [string]$AgentProcess = "campus-copilot"
)
$ErrorActionPreference = "Stop"

# ---- EDIT THESE (or pass as parameters) -----------------------------------
if (-not $Backend)           { $Backend           = "http://192.168.1.10:8000" }      # monitoring laptop
if (-not $SessionId)         { $SessionId         = "sess_PASTE_FROM_SETUP" }
if (-not $Token)             { $Token             = "sgw_PASTE_FROM_SETUP" }
if (-not $AttackerNoticeUrl) { $AttackerNoticeUrl = "http://192.168.1.40:9090/notice/" } # attacker laptop
if (-not $TargetUrl)         { $TargetUrl         = "http://192.168.1.20:8080" }      # target laptop
# ---------------------------------------------------------------------------

$env:SENTINEL_BACKEND       = $Backend
$env:SENTINEL_SESSION_ID    = $SessionId
$env:SENTINEL_GATEWAY_TOKEN = $Token
$env:ATTACKER_NOTICE_URL    = $AttackerNoticeUrl
$env:TARGET_URL             = $TargetUrl
$env:AGENT_ID               = $AgentId
$env:AGENT_PROCESS          = $AgentProcess

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
python (Join-Path $here "apex_agent.py") $Mode
