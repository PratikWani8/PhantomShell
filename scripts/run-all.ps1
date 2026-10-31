# Launch both Backend and Frontend in separate concurrent PowerShell sessions
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Launching PhantomShell Full Stack" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

$root = Get-Location

# 1. Start Backend in new process
Write-Host "Starting Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; .\scripts\run-backend.ps1"

# 2. Wait briefly
Start-Sleep -Seconds 2

# 3. Start Frontend in new process
Write-Host "Starting Frontend on http://127.0.0.1:5173..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root'; .\scripts\run-frontend.ps1"

Write-Host "`nPhantomShell processes launched." -ForegroundColor Green
Write-Host "Open http://localhost:5173 in your browser." -ForegroundColor Cyan
