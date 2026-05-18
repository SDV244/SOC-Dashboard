# SOC Dashboard - Script de arranque (Windows PowerShell)
Set-Location $PSScriptRoot

# Instalar dependencias Python si no existe el venv
if (-not (Test-Path ".venv")) {
    Write-Host "Instalando dependencias Python..." -ForegroundColor Cyan
    python -m uv sync --dev
}

# Build frontend
Write-Host "Construyendo frontend..." -ForegroundColor Cyan
Set-Location frontend
pnpm build
Set-Location ..

# Lanzar FastAPI con el Python del venv directamente
Write-Host "SOC Dashboard disponible en http://localhost:8000" -ForegroundColor Green
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
