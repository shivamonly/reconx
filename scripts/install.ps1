param(
    [string]$Version = "latest",
    [switch]$Dev,
    [switch]$Help
)

if ($Help) {
    Write-Host "ReconX Installer"
    Write-Host "Usage: irm https://reconx.dev/install.ps1 | iex"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version <tag>  Install specific version (default: latest)"
    Write-Host "  -Dev            Install development dependencies"
    Write-Host "  -Help           Show this help message"
    exit 0
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ReconX - Web Reconnaissance Tool"
Write-Host "  https://github.com/anomalyco/reconx"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"

# Check Python
$python = $null
try {
    $python = (Get-Command python -ErrorAction Stop).Source
} catch {
    try {
        $python = (Get-Command python3 -ErrorAction Stop).Source
    } catch {
        Write-Host "[!] Python 3.10+ is required but not found." -ForegroundColor Red
        Write-Host "    Download from: https://python.org/downloads/"
        exit 1
    }
}
Write-Host "[OK] Python: $python" -ForegroundColor Green

# Check Python version
$pyVer = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$verParts = $pyVer -split '\.'
$major = [int]$verParts[0]
$minor = 0
if ($verParts.Count -ge 2) { $minor = [int]$verParts[1] }
if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
    Write-Host "[!] Python 3.10+ required (found $pyVer)" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Python version: $pyVer" -ForegroundColor Green

# Install reconx
Write-Host ""
Write-Host "[...] Installing reconx..." -ForegroundColor Yellow

if ($Dev) {
    $pipCmd = "pip install reconx[dev]"
} else {
    $pipCmd = "pip install reconx"
}

try {
    $output = & $python -m pip install --upgrade reconx 2>&1
    Write-Host "[OK] reconx installed successfully" -ForegroundColor Green
} catch {
    Write-Host "[!] pip install failed. Try:" -ForegroundColor Red
    Write-Host "    $python -m pip install --user reconx" -ForegroundColor Yellow
    exit 1
}

# Get the Scripts path
$scriptsPath = & $python -c "import sys; import os; print(os.path.join(sys.base_prefix, 'Scripts'))" 2>$null
$userScriptsPath = & $python -m site --user-site 2>$null
if ($userScriptsPath) {
    $userScriptsPath = Split-Path $userScriptsPath -Parent
}

$allPaths = @()
if ($userScriptsPath) { $allPaths += $userScriptsPath }
$allPaths += $scriptsPath

$onPath = $false
foreach ($p in $allPaths) {
    if ($env:Path -split ';' -contains $p) { $onPath = $true; break }
}

if (-not $onPath) {
    Write-Host ""
    Write-Host "[!] Add reconx to your PATH:" -ForegroundColor Yellow
    Write-Host "    `$env:Path += `";$scriptsPath`"" -ForegroundColor Cyan
    Write-Host "    (Add to your PowerShell profile for permanence)"
}

# Verify installation
Write-Host ""
try {
    $ver = & $python -m reconx --version 2>&1
    Write-Host "[OK] $ver" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ready! Run:" -ForegroundColor Cyan
    Write-Host "  reconx scan example.com" -ForegroundColor White
    Write-Host "  reconx --help" -ForegroundColor White
} catch {
    Write-Host "[!] Installation may have failed. Verify by running:" -ForegroundColor Yellow
    Write-Host "    python -m reconx --version"
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Scan responsibly. Stay legal." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
