# PhantomShell Setup Script for Windows PowerShell
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PhantomShell - Environment Setup" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# 1. Check Python
Write-Host "`n[1/4] Checking Python environment..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Error "Python 3.11+ is required but not found in PATH."
    exit 1
}

# 2. Install backend dependencies
Write-Host "`n[2/4] Installing backend Python packages..." -ForegroundColor Yellow
pip install -r backend/requirements.txt
if ($LASTEXITCODE -eq 0) {
    Write-Host "Backend dependencies installed successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to install Python dependencies."
    exit 1
}

# 3. Check Node.js and pnpm
Write-Host "`n[3/4] Checking Node.js and pnpm..." -ForegroundColor Yellow
$nodeVersion = node --version 2>&1
$pnpmVersion = pnpm --version 2>&1
Write-Host "Node: $nodeVersion | pnpm: $pnpmVersion" -ForegroundColor Green

# 4. Install frontend dependencies
Write-Host "`n[4/4] Installing frontend dependencies..." -ForegroundColor Yellow
pnpm install --prefix frontend
if ($LASTEXITCODE -eq 0) {
    Write-Host "Frontend dependencies installed successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to install frontend dependencies."
    exit 1
}

# 5. Initialize test sandbox directory
$sandboxPath = "./demo/sandbox"
if (-not (Test-Path $sandboxPath)) {
    New-Item -ItemType Directory -Path $sandboxPath -Force | Out-Null
    Write-Host "Created test sandbox at $sandboxPath" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "  Start with: ./scripts/run-all.ps1" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
