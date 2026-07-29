# Build the HTML/web scanner into a single Windows .exe (Electron-style).
#
#   powershell -ExecutionPolicy Bypass -File build_web_exe.ps1
#
# Output: dist\NemesisWeb.exe  (double-click → server starts + browser opens)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/4] Ensuring build dependencies..." -ForegroundColor Cyan
python -m pip install --quiet --upgrade pyinstaller flask

Write-Host "[2/4] Regenerating module manifest..." -ForegroundColor Cyan
python tools/gen_manifest.py

Write-Host "[3/4] Cleaning previous build..." -ForegroundColor Cyan
if (Test-Path build) { Remove-Item -Recurse -Force build }

Write-Host "[4/4] Running PyInstaller (a few minutes)..." -ForegroundColor Cyan
pyinstaller bugbounty_web.spec --noconfirm

if (Test-Path "dist\NemesisWeb.exe") {
    $size = [math]::Round((Get-Item "dist\NemesisWeb.exe").Length / 1MB, 1)
    Write-Host "`nDONE -> dist\NemesisWeb.exe ($size MB)" -ForegroundColor Green
    Write-Host "더블클릭하면 로컬 서버가 뜨고 브라우저가 자동으로 열립니다." -ForegroundColor Yellow
    Write-Host "참고: 최종 사용자 PC에 Chrome이 설치돼 있어야 합니다." -ForegroundColor Yellow
} else {
    Write-Host "`nBUILD FAILED." -ForegroundColor Red
    exit 1
}
