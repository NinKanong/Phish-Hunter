$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
function Write-Usage { Write-Host 'Usage: powershell -ExecutionPolicy Bypass -File .\run.ps1' }
$python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { Write-Error 'Virtual environment not found. Run .\install.ps1 first.' }
& $python -m uvicorn phishhunter.asgi:app --host 127.0.0.1 --port 8000
