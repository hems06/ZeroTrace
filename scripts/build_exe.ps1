# Builds ZeroTrace.exe: a single portable Windows executable containing the
# whole app (backend + built frontend). Run from any directory; paths below
# are resolved relative to this script's location.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
#
# Output: backend\dist\ZeroTrace.exe

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$frontend = Join-Path $root "frontend"
$backend = Join-Path $root "backend"

Write-Host "==> Building frontend..." -ForegroundColor Cyan
Push-Location $frontend
npm install
npm run build
Pop-Location

Write-Host "==> Copying frontend build into backend/frontend_dist..." -ForegroundColor Cyan
$frontendDist = Join-Path $backend "frontend_dist"
if (Test-Path $frontendDist) { Remove-Item -Recurse -Force $frontendDist }
Copy-Item (Join-Path $frontend "dist") $frontendDist -Recurse

Write-Host "==> Ensuring backend venv + PyInstaller are set up..." -ForegroundColor Cyan
Push-Location $backend
if (-not (Test-Path ".venv")) {
    py -m venv .venv
}
& ".venv\Scripts\python.exe" -m pip install --upgrade pip -q
& ".venv\Scripts\python.exe" -m pip install -r requirements.txt -q
& ".venv\Scripts\python.exe" -m pip install pyinstaller -q

Write-Host "==> Running PyInstaller (onefile)..." -ForegroundColor Cyan
& ".venv\Scripts\python.exe" -m PyInstaller --onefile --noconfirm --name ZeroTrace `
    --add-data "frontend_dist;frontend_dist" `
    --hidden-import uvicorn.logging `
    --hidden-import uvicorn.loops `
    --hidden-import uvicorn.loops.auto `
    --hidden-import uvicorn.protocols `
    --hidden-import uvicorn.protocols.http `
    --hidden-import uvicorn.protocols.http.auto `
    --hidden-import uvicorn.protocols.websockets `
    --hidden-import uvicorn.protocols.websockets.auto `
    --hidden-import uvicorn.lifespan `
    --hidden-import uvicorn.lifespan.on `
    launcher.py
Pop-Location

Write-Host "==> Done: $backend\dist\ZeroTrace.exe" -ForegroundColor Green
