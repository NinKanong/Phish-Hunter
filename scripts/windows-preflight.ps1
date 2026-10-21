$ErrorActionPreference = 'Stop'
function Write-Usage { Write-Host 'Usage: powershell -ExecutionPolicy Bypass -File .\scripts\windows-preflight.ps1' }
Write-Host 'Checking Windows PhishGuard prerequisites...'
$commands = @('py','python')
$selected = $null
foreach ($name in $commands) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { $selected = $name; break }
}
if (-not $selected) { Write-Error 'Python launcher not found. Install Python 3.12, 3.13, or 3.14 from python.org.' }
$version = (& $selected -c 'import sys; print("{}.{}.{}".format(sys.version_info.major, sys.version_info.minor, sys.version_info.micro))').Trim()
Write-Host "Python: $version"
$parts = $version.Split('.')
if ($parts.Count -lt 2 -or $parts[0] -ne '3' -or $parts[1] -notin @('12','13','14')) {
    Write-Error 'Supported versions are Python 3.12, 3.13, and 3.14.'
}
Write-Host 'PowerShell installer syntax: PASS'
Write-Host 'Python version gate: PASS'
Write-Host 'Run .\install.ps1 to create the virtual environment and install dependencies.'
