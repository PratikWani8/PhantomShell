# Run Automated Backend Tests
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Executing PhantomShell Automated Tests" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

python -m pytest backend/tests -v
