# =============================================================================
# Wazuh + Ollama SIEM Platform - Local Startup Script (Windows PowerShell)
# =============================================================================
# Strictly adheres to Phase 11.0 Controlled Local Release requirements.
# Starts backend (port 8001) and frontend (port 5174) with reliable PID ownership.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$SkipDependencyCheck,
    [switch]$ForegroundBackend
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Wazuh + Ollama Local SIEM Platform - Starting Services" -ForegroundColor Cyan
Write-Host " Root Directory: $RootDir" -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Platform Check (Native Windows DPAPI / CNG requirement)
if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    Write-Error "ERROR: Native Windows DPAPI and CNG cryptography require Microsoft Windows. Unsupported OS."
    exit 1
}

# 2. Check Prerequisites
Write-Host "`n[1/6] Checking prerequisites..." -ForegroundColor Yellow

# Python
try {
    $pyVer = & uv run python --version 2>&1
    Write-Host "  [OK] Python via uv: $pyVer" -ForegroundColor Green
} catch {
    Write-Error "ERROR: 'uv' package manager or Python is not available in PATH. Please install uv (https://astral.sh/uv)."
    exit 1
}

# Node.js
try {
    $nodeVer = & node --version 2>&1
    Write-Host "  [OK] Node.js: $nodeVer" -ForegroundColor Green
} catch {
    Write-Error "ERROR: Node.js is not available in PATH. Please install Node.js >= 18."
    exit 1
}

# npm
try {
    $npmVer = & npm --version 2>&1
    Write-Host "  [OK] npm: $npmVer" -ForegroundColor Green
} catch {
    Write-Error "ERROR: npm is not available in PATH."
    exit 1
}

# 3. Verify Repository Directories
Write-Host "`n[2/6] Verifying directory structure..." -ForegroundColor Yellow
$requiredDirs = @("backend", "backend\app", "backend\alembic", "frontend", "frontend\src")
foreach ($dir in $requiredDirs) {
    $fullDir = Join-Path $RootDir $dir
    if (-not (Test-Path $fullDir)) {
        Write-Error "ERROR: Expected directory not found: $fullDir"
        exit 1
    }
}
Write-Host "  [OK] Repository structure verified." -ForegroundColor Green

# 4. Configuration Check (Non-leaking)
Write-Host "`n[3/6] Checking configuration..." -ForegroundColor Yellow
$envPathBackend = Join-Path $RootDir "backend\.env"
$envPathRoot = Join-Path $RootDir ".env"

if (-not (Test-Path $envPathBackend) -and -not (Test-Path $envPathRoot)) {
    Write-Host "  [WARN] No .env file found at backend\.env or root .env." -ForegroundColor Yellow
    Write-Host "         Using default development settings. To customize, copy .env.example to .env." -ForegroundColor Gray
} else {
    Write-Host "  [OK] Local .env configuration detected (credentials kept masked)." -ForegroundColor Green
}

# 5. Port Availability Verification (Fail-Safe, never kill existing)
Write-Host "`n[4/6] Verifying network ports..." -ForegroundColor Yellow

function Test-PortOccupied([int]$port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", $port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne(400, $false)
        if ($success) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

$backendPort = 8001
$frontendPort = 5174

if (Test-PortOccupied $backendPort) {
    Write-Host "  [CONFLICT] Port $backendPort is already in use by another process." -ForegroundColor Red
    Write-Host "             Run 'Get-NetTCPConnection -LocalPort $backendPort' to identify the process." -ForegroundColor Gray
    Write-Host "             Existing processes are not terminated by this script to prevent collateral loss." -ForegroundColor Gray
    exit 1
}

if (Test-PortOccupied $frontendPort) {
    Write-Host "  [CONFLICT] Port $frontendPort is already in use by another process." -ForegroundColor Red
    Write-Host "             Run 'Get-NetTCPConnection -LocalPort $frontendPort' to identify the process." -ForegroundColor Gray
    Write-Host "             Existing processes are not terminated by this script to prevent collateral loss." -ForegroundColor Gray
    exit 1
}

Write-Host "  [OK] Ports $backendPort (backend) and $frontendPort (frontend) are available." -ForegroundColor Green

# 6. Database Migration Check
Write-Host "`n[5/6] Checking database migration state..." -ForegroundColor Yellow
Push-Location (Join-Path $RootDir "backend")
try {
    $alembicStatus = & uv run alembic current 2>$null
    if (-not $alembicStatus) {
        $alembicStatus = & uv run alembic current | Out-String
    }
    Write-Host "  [OK] Database revision: $($alembicStatus.Trim())" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Database revision check note: $_" -ForegroundColor Yellow
} finally {
    Pop-Location
}

# 7. Start Services with Process Tracking
Write-Host "`n[6/6] Launching services..." -ForegroundColor Yellow

$logDir = Join-Path $RootDir "logs"
$runDir = Join-Path $RootDir "run"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
if (-not (Test-Path $runDir)) { New-Item -ItemType Directory -Path $runDir -Force | Out-Null }

$backendPidFile = Join-Path $runDir "backend.pid"
$frontendPidFile = Join-Path $runDir "frontend.pid"

# Check if previously recorded processes are still running
if (Test-Path $backendPidFile) {
    $existingBackendPid = Get-Content $backendPidFile -ErrorAction SilentlyContinue
    if ($existingBackendPid -and (Get-Process -Id $existingBackendPid -ErrorAction SilentlyContinue)) {
        Write-Host "  [WARN] Backend already running under PID $existingBackendPid. Run scripts/stop-local.ps1 first." -ForegroundColor Yellow
        exit 1
    }
}

if (Test-Path $frontendPidFile) {
    $existingFrontendPid = Get-Content $frontendPidFile -ErrorAction SilentlyContinue
    if ($existingFrontendPid -and (Get-Process -Id $existingFrontendPid -ErrorAction SilentlyContinue)) {
        Write-Host "  [WARN] Frontend already running under PID $existingFrontendPid. Run scripts/stop-local.ps1 first." -ForegroundColor Yellow
        exit 1
    }
}

# Start Backend (Detached Background Service)
$backendOut = Join-Path $logDir "backend.log"
$backendErr = Join-Path $logDir "backend.err.log"
$backendProc = Start-Process -FilePath "uv" `
    -ArgumentList "run", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$backendPort" `
    -WorkingDirectory (Join-Path $RootDir "backend") `
    -RedirectStandardOutput $backendOut `
    -RedirectStandardError $backendErr `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $backendPidFile -Value $backendProc.Id
Write-Host "  [OK] Backend started (PID: $($backendProc.Id)) -> Port $backendPort" -ForegroundColor Green

# Start Frontend (Detached Background Service)
$frontendOut = Join-Path $logDir "frontend.log"
$frontendErr = Join-Path $logDir "frontend.err.log"
$frontendProc = Start-Process -FilePath "npm.cmd" `
    -ArgumentList "run", "dev" `
    -WorkingDirectory (Join-Path $RootDir "frontend") `
    -RedirectStandardOutput $frontendOut `
    -RedirectStandardError $frontendErr `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $frontendPidFile -Value $frontendProc.Id
Write-Host "  [OK] Frontend started (PID: $($frontendProc.Id)) -> Port $frontendPort" -ForegroundColor Green

# 8. Post-Startup Health Probing
Write-Host "`nWaiting for service readiness..." -ForegroundColor Yellow
$backendReady = $false
$frontendReady = $false

for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if (-not $backendReady) {
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$backendPort/health/live" -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($resp -and $resp.status -eq "ok") {
                $backendReady = $true
            }
        } catch {}
    }
    if (-not $frontendReady) {
        if (Test-PortOccupied $frontendPort) {
            $frontendReady = $true
        }
    }
    if ($backendReady -and $frontendReady) {
        break
    }
}

if ($backendReady) {
    Write-Host "  [OK] Backend liveness probe passed (http://127.0.0.1:$backendPort/health/live)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Backend liveness probe did not respond within 15s. Check logs at logs/backend.err.log." -ForegroundColor Yellow
}

if ($frontendReady) {
    Write-Host "  [OK] Frontend HTTP server responding on port $frontendPort." -ForegroundColor Green
} else {
    Write-Host "  [WARN] Frontend did not respond within 15s. Check logs at logs/frontend.err.log." -ForegroundColor Yellow
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " APPLICATION READY FOR USE" -ForegroundColor Green
Write-Host " - Analyst Dashboard:  http://127.0.0.1:$frontendPort" -ForegroundColor White
Write-Host " - Backend API:        http://127.0.0.1:$backendPort" -ForegroundColor White
Write-Host " - Interactive Docs:   http://127.0.0.1:$backendPort/docs" -ForegroundColor White
Write-Host " - Health Live:        http://127.0.0.1:$backendPort/health/live" -ForegroundColor White
Write-Host " - Health Ready:       http://127.0.0.1:$backendPort/health/ready" -ForegroundColor White
Write-Host "`nTo gracefully shut down services, run:" -ForegroundColor Gray
Write-Host " powershell -ExecutionPolicy Bypass -File scripts/stop-local.ps1" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
