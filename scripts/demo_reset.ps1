# Fresh demo state in about 5 minutes: rebuild data/ews.db from the offline snapshot (restarts the API, so every
# deadline clock starts now), then pre-compute what the demo touches and run the test bench once.
# Run it shortly before presenting: the CERT-In 6-hour clock on the incident starts at build time.
# Usage: powershell -ExecutionPolicy Bypass -File scripts\demo_reset.ps1
$root = Split-Path -Parent $PSScriptRoot
& powershell -ExecutionPolicy Bypass -File "$root\scripts\rebuild.ps1"
for ($i = 0; $i -lt 60; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 3).StatusCode -eq 200) { break } } catch { }
    Start-Sleep 2
}
& "$root\.venv\Scripts\python.exe" "$root\scripts\warm_cache.py"
"Demo state is fresh: open http://127.0.0.1:5173"
