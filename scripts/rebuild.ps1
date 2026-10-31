# Stop the API (it holds the SQLite file), rebuild data/ews.db from the offline snapshot, restart the API.
# Usage: powershell -File scripts\rebuild.ps1
$root = Split-Path -Parent $PSScriptRoot
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*uvicorn backend.app.main*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Push-Location $root
& .\.venv\Scripts\python.exe -m backend.app.pipeline
Start-Process -WindowStyle Hidden -FilePath .\.venv\Scripts\python.exe `
    -ArgumentList '-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000' `
    -RedirectStandardOutput data\api.log -RedirectStandardError data\api.err.log
Pop-Location
"API restarted on http://127.0.0.1:8000"
