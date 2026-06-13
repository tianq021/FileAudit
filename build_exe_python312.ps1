$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = "C:\Python312\python.exe"
$DistExe = Join-Path $Root "dist\FileAudit.exe"

Set-Location $Root

if (-not (Test-Path $Python)) {
    throw "Python 3.12 was not found at $Python"
}

& $Python -m pip show PySide6 | Out-Null
& $Python -m pip show PyInstaller | Out-Null

if (Test-Path (Join-Path $Root "build")) {
    Remove-Item -LiteralPath (Join-Path $Root "build") -Recurse -Force
}
if (Test-Path (Join-Path $Root "dist")) {
    Remove-Item -LiteralPath (Join-Path $Root "dist") -Recurse -Force
}

& $Python -m PyInstaller --noconfirm --clean FileAudit.spec

if (-not (Test-Path $DistExe)) {
    throw "Build finished, but FileAudit.exe was not found at $DistExe"
}

Write-Host ""
Write-Host "Build complete:"
Write-Host $DistExe
