# =============================================================================
# Wazuh + Ollama SIEM Platform - Release Packaging Script (Windows PowerShell)
# =============================================================================
# Strictly adheres to Phase 11.0 Phase E requirements.
# Packages clean release ZIP archive excluding all secrets, production databases,
# keys, backups, virtualenvs, and node_modules.
# Verifies archive extraction and generates SHA-256 checksum.
# =============================================================================

[CmdletBinding()]
param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Wazuh + Ollama Local SIEM Platform - Packaging Release v$Version" -ForegroundColor Cyan
Write-Host " Root Directory: $RootDir" -ForegroundColor Gray
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Output directory preparation
$releasesDir = Join-Path $RootDir "releases"
if (-not (Test-Path $releasesDir)) {
    New-Item -ItemType Directory -Path $releasesDir -Force | Out-Null
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$releaseBaseName = "wazuh-ollama-siem-v${Version}_${timestamp}"
$stagingDir = Join-Path $releasesDir "${releaseBaseName}_staging"
$zipPath = Join-Path $releasesDir "${releaseBaseName}.zip"
$manifestPath = Join-Path $stagingDir "RELEASE_MANIFEST.json"
$checksumPath = Join-Path $releasesDir "${releaseBaseName}.sha256"

if (Test-Path $stagingDir) { Remove-Item -Recurse -Force $stagingDir }
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

Write-Host "[1/5] Staging release files into temporary clean directory..." -ForegroundColor Yellow

# Helper to copy directory structure safely
function Copy-CleanDirectory([string]$src, [string]$dst, [string[]]$excludePatterns) {
    if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst -Force | Out-Null }
    $items = Get-ChildItem -Path $src -Force
    foreach ($item in $items) {
        $skip = $false
        foreach ($pattern in $excludePatterns) {
            if ($item.Name -like $pattern) {
                $skip = $true
                break
            }
        }
        if ($skip) { continue }

        $targetPath = Join-Path $dst $item.Name
        if ($item.PSIsContainer) {
            Copy-CleanDirectory $item.FullName $targetPath $excludePatterns
        } else {
            Copy-Item -Path $item.FullName -Destination $targetPath -Force
        }
    }
}

# General exclusions
$commonExcludes = @(
    ".venv", "node_modules", "__pycache__", "*.pyc", "*.pyo",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.db", "*.db-shm", "*.db-wal", "*.sqlite3", "*.dpapi", "*.rec", "*.enc.db",
    "logs", "run", "tmp", "dist_test", "staging*"
)

# Copy Root essential files
$rootFiles = @(".env.example", "README.md", "OPERATOR_GUIDE.md")
foreach ($rf in $rootFiles) {
    $srcPath = Join-Path $RootDir $rf
    if (Test-Path $srcPath) {
        Copy-Item -Path $srcPath -Destination (Join-Path $stagingDir $rf) -Force
    }
}

# Copy Scripts
Write-Host "  -> Copying scripts/..." -ForegroundColor Gray
Copy-CleanDirectory (Join-Path $RootDir "scripts") (Join-Path $stagingDir "scripts") $commonExcludes

# Copy Backend (excluding data, .venv, caches, databases, keys)
Write-Host "  -> Copying backend/..." -ForegroundColor Gray
$backendExcludes = $commonExcludes + @("data", "models")
Copy-CleanDirectory (Join-Path $RootDir "backend") (Join-Path $stagingDir "backend") $backendExcludes

# Copy Frontend (excluding node_modules, .npm)
Write-Host "  -> Copying frontend/..." -ForegroundColor Gray
Copy-CleanDirectory (Join-Path $RootDir "frontend") (Join-Path $stagingDir "frontend") $commonExcludes

# Copy Specs
Write-Host "  -> Copying specs/..." -ForegroundColor Gray
Copy-CleanDirectory (Join-Path $RootDir "specs") (Join-Path $stagingDir "specs") $commonExcludes

# Ensure backend/data/backups and backend/data/keys placeholder directories exist with .gitkeep
$backendDataDir = Join-Path $stagingDir "backend\data"
New-Item -ItemType Directory -Path (Join-Path $backendDataDir "backups") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $backendDataDir "keys") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $backendDataDir "archives") -Force | Out-Null
Set-Content -Path (Join-Path $backendDataDir "backups\.gitkeep") -Value ""
Set-Content -Path (Join-Path $backendDataDir "keys\.gitkeep") -Value ""
Set-Content -Path (Join-Path $backendDataDir "archives\.gitkeep") -Value ""

# 2. Strict Security Audit of Staged Content
Write-Host "`n[2/5] Running strict security exclusion audit on staged files..." -ForegroundColor Yellow
$stagedFiles = Get-ChildItem -Path $stagingDir -Recurse -File

$forbiddenExtensions = @(".db", ".db-wal", ".db-shm", ".sqlite3", ".dpapi", ".key", ".pem", ".p12", ".pfx", ".rec")
$leakedFiles = @()

foreach ($file in $stagedFiles) {
    if ($file.Name -eq ".env" -or ($file.Name.StartsWith(".env.") -and $file.Name -ne ".env.example")) {
        $leakedFiles += $file.FullName
    }
    if ($forbiddenExtensions -contains $file.Extension.ToLower()) {
        $leakedFiles += $file.FullName
    }
}

if ($leakedFiles.Count -gt 0) {
    Write-Host "SECURITY ERROR: Leaked sensitive files found in staging:" -ForegroundColor Red
    $leakedFiles | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    Remove-Item -Recurse -Force $stagingDir
    exit 1
}
Write-Host "  [OK] Zero secrets, databases, DPAPI keys, or private certificates present in release package." -ForegroundColor Green

# 3. Create Release Manifest
Write-Host "`n[3/5] Generating release manifest..." -ForegroundColor Yellow
$manifest = [ordered]@{
    release_name       = "Wazuh + Ollama Local AI SIEM"
    version            = $Version
    build_timestamp    = $timestamp
    target_platform    = "Microsoft Windows x64 (Native CNG/DPAPI)"
    authoritative_docs = @("OPERATOR_GUIDE.md", "README.md", "specs/")
    entry_points       = [ordered]@{
        startup_script  = "scripts/start-local.ps1"
        shutdown_script = "scripts/stop-local.ps1"
        verify_script   = "scripts/verify-release.ps1"
    }
    ports              = [ordered]@{
        backend  = 8001
        frontend = 5174
    }
    dependencies       = [ordered]@{
        python = ">=3.11"
        node   = ">=18"
        uv     = "frozen (backend/uv.lock)"
        npm    = "frozen (frontend/package-lock.json)"
    }
    security_posture   = "Read-Only SIEM (ADR-003), Advisory AI (ADR-001), Blocked Audit Pruning (ADR-012/013)"
    total_files_count  = $stagedFiles.Count
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding utf8
$stagedCount = $stagedFiles.Count
Write-Host "  [OK] Manifest created: $stagedCount total files included." -ForegroundColor Green

# 4. Create ZIP Archive
Write-Host "`n[4/5] Compressing release package into ZIP archive..." -ForegroundColor Yellow
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
Remove-Item -Recurse -Force $stagingDir

$zipItem = Get-Item $zipPath
$zipName = $zipItem.Name
$zipBytes = $zipItem.Length
$zipSizeMB = [math]::Round($zipBytes / 1MB, 2)
Write-Host "  [OK] Created archive: $zipName - $zipSizeMB MB - $zipBytes bytes" -ForegroundColor Green

# 5. Checksum Generation and Extraction Verification
Write-Host "`n[5/5] Generating SHA-256 and verifying archive extractability..." -ForegroundColor Yellow
$sha256 = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
"$sha256  $zipName" | Set-Content -Path $checksumPath -Encoding utf8
Write-Host "  [OK] SHA-256 Checksum: $sha256" -ForegroundColor Green

# Verify archive extraction into isolated temp directory
$extractTestDir = Join-Path $releasesDir "verify_extract_$timestamp"
try {
    New-Item -ItemType Directory -Path $extractTestDir -Force | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractTestDir)
    
    # Verify essential files in extracted folder
    $testFiles = @("OPERATOR_GUIDE.md", ".env.example", "scripts\start-local.ps1", "backend\pyproject.toml", "frontend\package.json", "RELEASE_MANIFEST.json")
    foreach ($tf in $testFiles) {
        $p = Join-Path $extractTestDir $tf
        if (-not (Test-Path $p)) {
            throw "Extracted archive is missing expected file: $tf"
        }
    }
    Write-Host "  [OK] Archive successfully verified via test extraction: all key files intact." -ForegroundColor Green
} finally {
    if (Test-Path $extractTestDir) {
        Remove-Item -Recurse -Force $extractTestDir -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " RELEASE PACKAGING COMPLETE" -ForegroundColor Green
Write-Host " Archive:   $zipPath" -ForegroundColor White
Write-Host " Size:      $zipSizeMB MB - $zipBytes bytes" -ForegroundColor White
Write-Host " SHA-256:   $sha256" -ForegroundColor White
Write-Host " Checksum:  $checksumPath" -ForegroundColor White
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
