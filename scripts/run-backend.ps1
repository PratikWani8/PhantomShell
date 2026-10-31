# Run PhantomShell FastAPI Backend
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting PhantomShell Backend Server" -ForegroundColor Green
Write-Host "  Binding: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
