$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Write-Usage {
    Write-Host 'Usage: powershell -ExecutionPolicy Bypass -File .\install.ps1'
}

function Get-PythonCandidate {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($candidate in @('-3.14', '-3.13', '-3.12')) {
            try {
                $output = (& py $candidate -V 2>&1 | Out-String).Trim()
                if ($output -match '^Python\s+(3\.(12|13|14)\.[0-9]+)') {
                    return @{ Command = 'py'; Args = @($candidate); Version = $Matches[1] }
                }
            } catch {
            }
        }
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        try {
            $output = (& python -V 2>&1 | Out-String).Trim()
            if ($output -match '^Python\s+(3\.(12|13|14)\.[0-9]+)') {
                return @{ Command = 'python'; Args = @(); Version = $Matches[1] }
            }
        } catch {
        }
    }
    return $null
}

Write-Host 'PhishGuard native Windows installer (no Docker, no Node).'

$pythonInfo = Get-PythonCandidate
if (-not $pythonInfo) {
    Write-Error 'Python 3.12, 3.13, or 3.14 is required. Install CPython from python.org and enable the Python launcher.'
}

$pythonCommand = $pythonInfo.Command
$pythonArgs = $pythonInfo.Args
Write-Host "Using Python $($pythonInfo.Version)"

& $pythonCommand @pythonArgs -m venv .venv
if ($LASTEXITCODE -ne 0) { Write-Error 'Python virtual environment creation failed.' }

$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) { Write-Error 'The virtual environment Python executable was not created.' }

& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { Write-Error 'pip upgrade failed.' }

Write-Host 'Installing Python dependencies from binary wheels only...'
& $venvPython -m pip install --only-binary=:all: -r requirements\dev.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error 'Dependency installation failed. No source compilation is attempted by this installer.'
}

& $venvPython -m pip check
if ($LASTEXITCODE -ne 0) { Write-Error 'pip check failed. Dependency metadata is inconsistent.' }

& $venvPython scripts\verify-dependencies.py --strict
if ($LASTEXITCODE -ne 0) { Write-Error 'Dependency verification failed.' }

if (-not (Test-Path -LiteralPath '.env')) {
    Copy-Item -LiteralPath '.env.example' -Destination '.env'
}

& $venvPython scripts\preflight.py
if ($LASTEXITCODE -ne 0) { Write-Error 'PhishGuard preflight checks failed.' }

& $venvPython -m phishhunter.seed
if ($LASTEXITCODE -ne 0) { Write-Error 'Database initialization failed.' }

Write-Host ''
Write-Host 'Install complete.'
Write-Host 'Create admin with: .\.venv\Scripts\python.exe bootstrap_admin.py --email admin@company.com --password <strong-password>'
Write-Host 'Start with: .\.venv\Scripts\python.exe run.py'
Write-Host 'Open: http://127.0.0.1:8000'
