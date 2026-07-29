# Build Nemesis (legacy PyQt) into a single Windows .exe.
#
#   powershell -ExecutionPolicy Bypass -File build_exe.ps1
#
# Output: dist\NemesisQt.exe

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/4] Ensuring build dependencies..." -ForegroundColor Cyan
python -m pip install --quiet --upgrade pyinstaller

Write-Host "[2/4] Regenerating module manifest..." -ForegroundColor Cyan
python tools/gen_manifest.py

Write-Host "[3/4] Cleaning previous build..." -ForegroundColor Cyan
if (Test-Path build) { Remove-Item -Recurse -Force build }
if (Test-Path dist)  { Remove-Item -Recurse -Force dist }

Write-Host "[4/4] Running PyInstaller (this can take a few minutes)..." -ForegroundColor Cyan
pyinstaller bugbounty.spec --noconfirm

if (Test-Path "dist\NemesisQt.exe") {
    $size = [math]::Round((Get-Item "dist\NemesisQt.exe").Length / 1MB, 1)
    Write-Host "`nDONE -> dist\NemesisQt.exe ($size MB)" -ForegroundColor Green
    Write-Host "참고: 최종 사용자 PC에 Chrome이 설치돼 있어야 합니다." -ForegroundColor Yellow
} else {
    Write-Host "`nBUILD FAILED — dist\NemesisQt.exe not found." -ForegroundColor Red
    exit 1
}
