# PhantomShell Verification Diagnostic Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PhantomShell Diagnostic & Health Check" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# 1. Python check
Write-Host "`n[1] Checking Python installation..." -ForegroundColor Yellow
try {
    $py = python --version
    Write-Host "  [OK] $py" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Python not accessible." -ForegroundColor Red
}

# 2. Node & pnpm check
Write-Host "`n[2] Checking Node and pnpm..." -ForegroundColor Yellow
try {
    $nd = node --version
    $pn = pnpm --version
    Write-Host "  [OK] Node: $nd | pnpm: $pn" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Node or pnpm missing." -ForegroundColor Red
}

# 3. Ollama check
Write-Host "`n[3] Checking Local Ollama Status..." -ForegroundColor Yellow
try {
    $ollamaVer = ollama --version 2>&1
    Write-Host "  [INFO] $ollamaVer" -ForegroundColor Cyan
    $ollamaReq = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    if ($ollamaReq.StatusCode -eq 200) {
        Write-Host "  [OK] Ollama is active on http://127.0.0.1:11434" -ForegroundColor Green
    }
} catch {
    Write-Host "  [NOTE] Ollama daemon is currently offline." -ForegroundColor Yellow
    Write-Host "         PhantomShell will automatically use its deterministic Ghost fallback." -ForegroundColor Cyan
    Write-Host "         To enable live local LLM inference, run: ollama run phi4-mini" -ForegroundColor Cyan
}

# 4. Monitored Directory Check
Write-Host "`n[4] Checking Monitored Workspace Directory..." -ForegroundColor Yellow
$sandbox = "./demo/sandbox"
if (Test-Path $sandbox) {
    Write-Host "  [OK] Sandbox workspace exists at $sandbox" -ForegroundColor Green
} else {
    New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
    Write-Host "  [CREATED] Created missing sandbox at $sandbox" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Diagnostics Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
