# One command to bring the whole system up (idempotent): Ollama (GPU, models on D:), API (:8000), dashboard (:5173).
# Usage:  powershell -ExecutionPolicy Bypass -File D:\DECOY\scripts\start_all.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root 'data'
$node = 'D:\tools\node-v26.13.0-win-x64\node.exe'

function Test-Port($port) {
    # A direct TCP connect is reliable; Get-NetTCPConnection intermittently returns nothing on this machine.
    $c = New-Object System.Net.Sockets.TcpClient
    try { return $c.ConnectAsync('127.0.0.1', $port).Wait(500) -and $c.Connected } catch { return $false } finally { $c.Dispose() }
}
function Wait-Port($port, $name, $seconds = 60) {
    for ($i = 0; $i -lt $seconds; $i++) { if (Test-Port $port) { "  $name ready on :$port"; return }; Start-Sleep 1 }
    throw "$name did not start on :$port (see logs in $logs)"
}

# 1. Ollama: the desktop app reads OLLAMA_* from the environment it is launched with
if (-not (Test-Port 11434)) {
    foreach ($n in 'OLLAMA_MODELS', 'OLLAMA_FLASH_ATTENTION', 'OLLAMA_KV_CACHE_TYPE', 'OLLAMA_KEEP_ALIVE') {
        $v = [Environment]::GetEnvironmentVariable($n, 'User'); if ($v) { Set-Item "env:$n" $v }
    }
    Start-Process "$env:LOCALAPPDATA\Programs\Ollama\ollama app.exe"
}
Wait-Port 11434 'Ollama'

# 2. API
if (-not (Test-Port 8000)) {
    Start-Process -WindowStyle Hidden -WorkingDirectory $root -FilePath "$root\.venv\Scripts\python.exe" `
        -ArgumentList '-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000' `
        -RedirectStandardOutput "$logs\api.log" -RedirectStandardError "$logs\api.err.log"
}
Wait-Port 8000 'API'

# 2b. Indic translation service (IndicTrans2, own Python 3.14 env)
if (-not (Test-Port 8010)) {
    $env:HF_HOME = 'D:\hf-cache'; $env:HF_HUB_OFFLINE = '1'
    Start-Process -WindowStyle Hidden -WorkingDirectory $root -FilePath "$root\.venv-mt\Scripts\python.exe" `
        -ArgumentList '-m', 'uvicorn', 'backend.mt_service:app', '--host', '127.0.0.1', '--port', '8010' `
        -RedirectStandardOutput "$logs\mt.log" -RedirectStandardError "$logs\mt.err.log"
}
Wait-Port 8010 'Translation'

# 3. Dashboard
if (-not (Test-Port 5173)) {
    Start-Process -WindowStyle Hidden -WorkingDirectory "$root\frontend" -FilePath $node `
        -ArgumentList 'node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '5173', '--strictPort' `
        -RedirectStandardOutput "$logs\web.log" -RedirectStandardError "$logs\web.err.log"
}
Wait-Port 5173 'Dashboard'

# 4. Warm the GPU model so the first AI call on stage is instant
try { Invoke-RestMethod -Method Post http://127.0.0.1:11434/api/generate -Body '{"model":"mist:8b","prompt":"ok","stream":false,"options":{"num_predict":1}}' -ContentType 'application/json' -TimeoutSec 120 | Out-Null; '  mist:8b loaded on GPU' } catch { "  warning: could not warm mist:8b ($_)" }

"Open http://127.0.0.1:5173/"
