param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildVenv = Join-Path $Root ".build-venv"
$Python = Join-Path $BuildVenv "Scripts\python.exe"
$DistExe = Join-Path $Root "dist\FileAudit.exe"

Set-Location $Root

if (-not (Test-Path $Python)) {
    python -m venv $BuildVenv
}

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt pyinstaller

if ($Clean) {
    if (Test-Path (Join-Path $Root "build")) {
        Remove-Item -LiteralPath (Join-Path $Root "build") -Recurse -Force
    }
    if (Test-Path (Join-Path $Root "dist")) {
        Remove-Item -LiteralPath (Join-Path $Root "dist") -Recurse -Force
    }
}

& $Python -m PyInstaller --noconfirm --clean FileAudit.spec

if (-not (Test-Path $DistExe)) {
    throw "Build finished, but FileAudit.exe was not found at $DistExe"
}

Write-Host ""
Write-Host "Build complete:"
Write-Host $DistExe
