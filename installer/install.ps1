# BigSleep ASM Agent — Windows Quick-Install Script
# Run as Administrator in PowerShell:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\installer\install.ps1

param(
    [string]$InstallDir = "C:\BigSleepASM",
    [string]$Port       = "9000",
    [switch]$NoService,
    [switch]$LiteMode
)

$ErrorActionPreference = "Stop"

function Write-Header($msg) {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor DarkGray
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor DarkGray
}

function Write-OK($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [XX] $msg" -ForegroundColor Red }

Write-Header "BigSleep ASM Agent Installer"

# ── 1. Check Python ───────────────────────────────────────────────────────────
Write-Host "`n  Checking Python..." -NoNewline
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Fail "Python not found. Install Python 3.11+ from python.org"
    exit 1
}
$pyVer = (python --version 2>&1).ToString().Split(" ")[1]
Write-OK "Python $pyVer"

# ── 2. Create install directory ───────────────────────────────────────────────
Write-Host "  Creating install directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
# Copy files (when running from extracted zip/folder)
$scriptDir = Split-Path -Parent $PSScriptRoot
Copy-Item -Recurse -Force "$scriptDir\*" $InstallDir
Write-OK "Files copied to $InstallDir"

# ── 3. Install Python dependencies ────────────────────────────────────────────
Write-Host "`n  Installing Python dependencies..."
Set-Location $InstallDir
python -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Fail "pip install failed"; exit 1 }
Write-OK "Dependencies installed"

# ── 4. Create data / config directories ──────────────────────────────────────
@("data", "config") | ForEach-Object {
    $d = Join-Path $InstallDir $_
    if (-not (Test-Path $d)) { New-Item -ItemType Directory $d | Out-Null }
}

# ── 5. Write lite-mode runtime config if requested ───────────────────────────
if ($LiteMode) {
    $rtConfig = @{
        mode             = "lite"
        proxy_enabled    = $false
        scan_interval_seconds = 300
    } | ConvertTo-Json
    $rtConfig | Set-Content (Join-Path $InstallDir "config\runtime.json")
    Write-OK "Lite mode configured"
}

# ── 6. Run first-run setup wizard ────────────────────────────────────────────
Write-Header "First-Run Setup"
Write-Host "  You will be prompted for a license key and admin password.`n"
Set-Location $InstallDir
python run.py setup

# ── 7. Windows Firewall — allow inbound on dashboard port ────────────────────
Write-Host "`n  Configuring Windows Firewall..."
$ruleName = "BigSleep-ASM-Dashboard-$Port"
$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existing) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Action Allow -Profile Private,Domain | Out-Null
    Write-OK "Firewall rule added (port $Port inbound)"
} else {
    Write-OK "Firewall rule already exists"
}

# ── 8. Optional: Register as Windows Service via NSSM ────────────────────────
if (-not $NoService) {
    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssm) {
        Write-Host "`n  Registering BigSleepASM as Windows service..."
        $pyExe = (Get-Command python).Source
        nssm install BigSleepASM $pyExe "$InstallDir\run.py"
        nssm set BigSleepASM AppDirectory $InstallDir
        nssm set BigSleepASM AppParameters "serve --port $Port"
        nssm set BigSleepASM DisplayName "BigSleep ASM Agent"
        nssm set BigSleepASM Description "AI Attack Surface Management with DLP"
        nssm set BigSleepASM Start SERVICE_AUTO_START
        nssm start BigSleepASM
        Write-OK "Windows service 'BigSleepASM' installed and started"
    } else {
        Write-Warn "NSSM not found — skipping service registration."
        Write-Host "  To install as a service later:"
        Write-Host "    choco install nssm"
        Write-Host "    nssm install BigSleepASM python `"$InstallDir\run.py`""
        Write-Host ""
        Write-Host "  Or start manually:"
        Write-Host "    cd $InstallDir && python run.py"
    }
}

# ── 9. Done ───────────────────────────────────────────────────────────────────
Write-Header "Installation Complete"
Write-Host "  Dashboard : http://localhost:$Port" -ForegroundColor White
Write-Host "  Start     : cd $InstallDir && python run.py" -ForegroundColor White
Write-Host "  Docs      : $InstallDir\README.md" -ForegroundColor White
Write-Host ""
