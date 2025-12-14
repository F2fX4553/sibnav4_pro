<#
.SYNOPSIS
Secure Protocol CLI for Windows
Uses Python bindings.
#>

param(
    [string]$Command,
    [string]$Arg1
)

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$PythonPath = Join-Path $ProjectRoot "bindings\python"

$env:PYTHONPATH = "$PythonPath"

function Show-Help {
    Write-Host "Secure Protocol CLI (Windows)" -ForegroundColor Cyan
    Write-Host "Usage: .\secure-cli.ps1 [command] [args]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  init          Initialize configuration (mock)"
    Write-Host "  gen-key       Generate a new keypair"
    Write-Host "  encrypt       Encrypt a message (demo)"
    Write-Host "  help          Show this help"
}

if (-not $Command) {
    Show-Help
    exit
}

switch ($Command) {
    "init" {
        Write-Host "[INFO] Initializing configuration..." -ForegroundColor Blue
        # Create config if needed
        New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.secure-protocol" | Out-Null
        Write-Host "[SUCCESS] Initialized." -ForegroundColor Green
    }
    "gen-key" {
        python -c "import sys; sys.path.append(r'$PythonPath'); from secure_protocol import generate_keypair; import base64; pub, priv = generate_keypair(); print(f'Public: {base64.b64encode(pub).decode()}'); print(f'Private: {base64.b64encode(priv).decode()}')"
    }
    "encrypt" {
        if (-not $Arg1) {
            Write-Error "Usage: encrypt <message>"
            exit 1
        }
        # Demo encryption using a fresh session
        python -c "import sys; sys.path.append(r'$PythonPath'); from secure_protocol import SecureContext; ctx = SecureContext(); session = ctx.create_session(b'demo'); print(f'Encrypted: {session.encrypt(b'''$Arg1''')}')"
    }
    Default {
        Show-Help
    }
}
