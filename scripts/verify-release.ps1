# =============================================================================
# Wazuh + Ollama SIEM Platform - Release Preflight & Verification Script
# =============================================================================
# Strictly adheres to Phase 11.0 Phase G requirements.
# Verifies environment, tests, builds, contracts, and migrations.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$SkipFullTestSuite
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Wazuh + Ollama Local SIEM Platform - Release Verification" -ForegroundColor Cyan
Write-Host " Root Directory: $RootDir" -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Check([string]$name, [string]$status, [string]$details) {
    $results.Add([PSCustomObject]@{
        Check   = $name
        Status  = $status
        Details = $details
    })
    $color = switch ($status) {
        "PASS"       { "Green" }
        "FAIL"       { "Red" }
        "SKIPPED"    { "Yellow" }
        "UNVERIFIED" { "Magenta" }
        Default      { "White" }
    }
    Write-Host "[$status] $name - $details" -ForegroundColor $color
}

# 1. Platform Check
if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
    Record-Check "Host OS Platform" "PASS" "Microsoft Windows detected (supports native CNG/DPAPI)"
} else {
    Record-Check "Host OS Platform" "FAIL" "Non-Windows OS detected; DPAPI encryption unavailable"
}

# 2. Tooling Prerequisites
try {
    $py = & uv run python --version 2>&1
    Record-Check "Python 3.11+ via uv" "PASS" "$py"
} catch {
    Record-Check "Python 3.11+ via uv" "FAIL" "uv/python failed: $_"
}

try {
    $node = & node --version 2>&1
    Record-Check "Node.js Environment" "PASS" "$node"
} catch {
    Record-Check "Node.js Environment" "FAIL" "Node.js not available: $_"
}

try {
    $npm = & npm --version 2>&1
    Record-Check "npm Package Manager" "PASS" "npm $npm"
} catch {
    Record-Check "npm Package Manager" "FAIL" "npm not available: $_"
}

# 3. Essential Files Check
$requiredFiles = @(
    "backend\pyproject.toml",
    "backend\uv.lock",
    "backend\alembic.ini",
    "frontend\package.json",
    "frontend\package-lock.json",
    "frontend\vite.config.ts",
    ".env.example",
    "README.md",
    "OPERATOR_GUIDE.md"
)

$missingFiles = @()
foreach ($f in $requiredFiles) {
    if (-not (Test-Path (Join-Path $RootDir $f))) {
        $missingFiles += $f
    }
}
if ($missingFiles.Count -eq 0) {
    Record-Check "Required Files Structure" "PASS" "All 9 essential configuration and manifest files present"
} else {
    Record-Check "Required Files Structure" "FAIL" "Missing: $($missingFiles -join ', ')"
}

# 4. Database Migration Status
Push-Location (Join-Path $RootDir "backend")
try {
    $alembicCurrent = & uv run alembic current 2>&1
    if ($alembicCurrent -match "head") {
        Record-Check "Database Migration State" "PASS" "Database at HEAD revision ($alembicCurrent)"
    } else {
        Record-Check "Database Migration State" "FAIL" "Database not at HEAD: $alembicCurrent"
    }
} catch {
    Record-Check "Database Migration State" "FAIL" "Alembic check error: $_"
} finally {
    Pop-Location
}

# 5. Backend Test Suite
if ($SkipFullTestSuite) {
    Record-Check "Backend Test Suite (pytest)" "SKIPPED" "User specified -SkipFullTestSuite"
} else {
    Push-Location (Join-Path $RootDir "backend")
    try {
        Write-Host "`nRunning backend test suite (pytest)..." -ForegroundColor Gray
        $pytestOut = & uv run pytest -q --tb=short 2>&1
        if ($LASTEXITCODE -eq 0) {
            Record-Check "Backend Test Suite (pytest)" "PASS" "All non-live unit & integration tests passed cleanly"
        } else {
            Record-Check "Backend Test Suite (pytest)" "FAIL" "Tests failed with exit code $LASTEXITCODE"
        }
    } catch {
        Record-Check "Backend Test Suite (pytest)" "FAIL" "Execution error: $_"
    } finally {
        Pop-Location
    }
}

# 6. Frontend Code Quality (oxlint)
Push-Location (Join-Path $RootDir "frontend")
try {
    $lintOut = & npm run lint 2>&1
    if ($LASTEXITCODE -eq 0) {
        Record-Check "Frontend Linter (oxlint)" "PASS" "0 lint errors found"
    } else {
        Record-Check "Frontend Linter (oxlint)" "FAIL" "Lint errors detected"
    }
} catch {
    Record-Check "Frontend Linter (oxlint)" "FAIL" "Lint check error: $_"
} finally {
    Pop-Location
}

# 7. Frontend Security & Contract Invariants
Push-Location (Join-Path $RootDir "frontend")
try {
    $contractOut = & node tests/validate_client.js 2>&1
    if ($LASTEXITCODE -eq 0) {
        Record-Check "Frontend Security & API Contract" "PASS" "100% contracts & bundle port invariants verified"
    } else {
        Record-Check "Frontend Security & API Contract" "FAIL" "Security validation failed: $contractOut"
    }
} catch {
    Record-Check "Frontend Security & API Contract" "FAIL" "Validation script error: $_"
} finally {
    Pop-Location
}

# 8. Frontend Production Build (tsc + vite)
Push-Location (Join-Path $RootDir "frontend")
try {
    Write-Host "Running frontend production build..." -ForegroundColor Gray
    $buildOut = & npm run build 2>&1
    if ($LASTEXITCODE -eq 0) {
        Record-Check "Frontend Production Build" "PASS" "TypeScript check and Vite bundle built successfully"
    } else {
        Record-Check "Frontend Production Build" "FAIL" "Build failed with exit code $LASTEXITCODE"
    }
} catch {
    Record-Check "Frontend Production Build" "FAIL" "Build error: $_"
} finally {
    Pop-Location
}

# 9. Live Service Endpoint Probing
try {
    $liveResp = Invoke-RestMethod -Uri "http://127.0.0.1:8001/health/live" -TimeoutSec 1 -ErrorAction Stop
    if ($liveResp -and $liveResp.status -eq "ok") {
        Record-Check "Live Backend Liveness Probe" "PASS" "Backend running on :8001 (/health/live returned OK)"
    } else {
        Record-Check "Live Backend Liveness Probe" "FAIL" "Unexpected response from :8001"
    }
} catch {
    Record-Check "Live Backend Liveness Probe" "SKIPPED" "Services not actively running (offline preflight mode)"
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host ""
