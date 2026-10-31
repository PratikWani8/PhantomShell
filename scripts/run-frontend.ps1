# Run PhantomShell React/Vite Frontend
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting PhantomShell Frontend (Vite)" -ForegroundColor Green
Write-Host "  Local URL: http://127.0.0.1:5173" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

pnpm --prefix frontend run dev
