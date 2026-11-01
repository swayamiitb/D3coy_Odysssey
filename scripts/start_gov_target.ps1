# Start the fictional government-agency lab target (Lokseva Citizen Alert Portal, SIMULATED) on :8081, behind the
# Odyssey HTTP shield. A lab target the shield defends; a person or a separate red-team session attacks it on loopback
# and Odyssey detects, opens a case and reports. It is NOT a real government service and holds no real data.
# Usage:  powershell -ExecutionPolicy Bypass -File D:\DECOY\scripts\start_gov_target.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Test-Port($port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try { return $c.ConnectAsync('127.0.0.1', $port).Wait(500) -and $c.Connected } catch { return $false } finally { $c.Dispose() }
}

if (-not (Test-Port 8000)) { throw "The Odyssey API is not up on :8000 - run scripts\start_all.ps1 first." }
if (Test-Port 8081) { "  Lokseva target already running on :8081"; exit 0 }

Start-Process -WindowStyle Hidden -WorkingDirectory $root -FilePath "$root\.venv\Scripts\python.exe" `
    -ArgumentList '-m', 'uvicorn', 'target.gov_portal:app', '--host', '127.0.0.1', '--port', '8081' `
    -RedirectStandardOutput "$root\data\gov_portal.log" -RedirectStandardError "$root\data\gov_portal.err.log"

for ($i = 0; $i -lt 30; $i++) { if (Test-Port 8081) { "  Lokseva Citizen Alert Portal (SIM) ready on http://127.0.0.1:8081"; break }; Start-Sleep 1 }
if (-not (Test-Port 8081)) { throw "the target did not start (see data\gov_portal.err.log)" }
"  It registers with the shield as 'lokseva-alert-portal' (org GOV-01). Red-team it from Live -> Red-team the shield,"
"  or: Invoke-RestMethod -Method POST http://127.0.0.1:8000/api/redteam/run -Body '{""target"":""http://127.0.0.1:8081""}' -ContentType application/json"
