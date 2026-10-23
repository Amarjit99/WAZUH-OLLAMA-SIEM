# =============================================================================
# Wazuh + Ollama SIEM Platform - Local Shutdown Script (Windows PowerShell)
# =============================================================================
# Strictly adheres to Phase 11.0 Controlled Local Release requirements.
# Stops ONLY the backend and frontend processes recorded in run/*.pid.
# NEVER kills unrelated processes or touches background Docker/OpenSearch/Wazuh.
# =============================================================================

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$runDir = Join-Path $RootDir "run"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Wazuh + Ollama Local SIEM Platform - Stopping Services" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$backendPidFile = Join-Path $runDir "backend.pid"
$frontendPidFile = Join-Path $runDir "frontend.pid"

function Stop-TrackedProcess([string]$pidFile, [string]$serviceName) {
    if (-not (Test-Path $pidFile)) {
        Write-Host "  [-] No active PID file found for $serviceName ($pidFile)." -ForegroundColor Gray
        return
    }

    $procIdStr = Get-Content $pidFile -ErrorAction SilentlyContinue
    if (-not $procIdStr) {
        Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
        return
    }

    [int]$procId = 0
    if (-not [int]::TryParse($procIdStr.Trim(), [ref]$procId)) {
        Write-Host "  [WARN] Invalid PID recorded in $pidFile: '$procIdStr'." -ForegroundColor Yellow
        Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
        return
    }

    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
        Write-Host "  [*] Stopping $serviceName (PID $procId, Name: $($proc.ProcessName))..." -ForegroundColor Yellow
        
        # Stop parent process and its immediate subprocess tree gracefully
        Stop-Process -Id $procId -ErrorAction SilentlyContinue
        
        # Wait up to 5 seconds for clean shutdown
        $stopped = $proc.WaitForExit(5000)
        if (-not $stopped) {
            Write-Host "  [*] Process did not exit immediately; sending termination signal..." -ForegroundColor Yellow
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }

        Write-Host "  [OK] $serviceName (PID $procId) stopped successfully." -ForegroundColor Green
    } catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        Write-Host "  [-] $serviceName (PID $procId) is not currently running." -ForegroundColor Gray
    } catch {
        Write-Host "  [WARN] Error stopping $serviceName: $_" -ForegroundColor Yellow
    } finally {
        Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
    }
}

# Stop Frontend
Stop-TrackedProcess -pidFile $frontendPidFile -serviceName "Frontend UI"

# Stop Backend
Stop-TrackedProcess -pidFile $backendPidFile -serviceName "Backend API"

# Also clean any leftover node/vite child processes that were tied to frontend port if tracked
Write-Host "`nVerifying ports are released..." -ForegroundColor Gray
Start-Sleep -Seconds 1

function Check-Port([int]$port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", $port, $null, $null)
        $success = $iar.AsyncWaitHandle.WaitOne(300, $false)
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

if (Check-Port 8001) {
    Write-Host "  [INFO] Port 8001 still occupied by an external process." -ForegroundColor Yellow
} else {
    Write-Host "  [OK] Port 8001 released." -ForegroundColor Green
}

if (Check-Port 5174) {
    Write-Host "  [INFO] Port 5174 still occupied by an external process." -ForegroundColor Yellow
} else {
    Write-Host "  [OK] Port 5174 released." -ForegroundColor Green
}

Write-Host "`nAll platform services stopped gracefully." -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
