$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$dist = "dist"

Write-Host "==> Cleaning $dist ..."
if (Test-Path $dist) {
    Remove-Item -LiteralPath $dist -Recurse -Force
}
New-Item -ItemType Directory -Path $dist | Out-Null

$ldflagsGui = '-ldflags="-s -w -H=windowsgui"'
$ldflags    = '-ldflags="-s -w"'

Write-Host "==> Building cmd/netwatch -> $dist/netwatch.exe"
go build $ldflagsGui -o "$dist/netwatch.exe" ./cmd/netwatch
if ($LASTEXITCODE -ne 0) { throw "netwatch build failed" }

Write-Host "==> Building cmd/monitor -> $dist/monitor.exe"
go build $ldflags -o "$dist/monitor.exe" ./cmd/monitor
if ($LASTEXITCODE -ne 0) { throw "monitor build failed" }

Write-Host "==> Copying blocklist.txt"
Copy-Item -LiteralPath "blocklist.txt" -Destination "$dist/blocklist.txt"

Write-Host "==> Searching for APK ..."
$apkCandidates = @(
    "android/app/build/outputs/apk/debug/app-debug.apk",
    "android/app-release.apk"
)
$apk = $apkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($apk) {
    Copy-Item -LiteralPath $apk -Destination "$dist/netwatch.apk"
    Write-Host "    Copied $apk -> $dist/netwatch.apk"
} else {
    Write-Warning "APK not found, skipping (build android first)"
}

Write-Host "==> Creating $dist/run.bat"
@"
@echo off
start "" "%~dp0netwatch.exe"
"@ | Set-Content -LiteralPath "$dist/run.bat" -Encoding ASCII

Write-Host "==> Creating $dist/VERSION.txt"
$version = git describe --tags --always --dirty 2>$null
if (-not $version) { $version = git rev-parse --short HEAD 2>$null }
if (-not $version) { $version = "unknown" }
$buildDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
"Build date : $buildDate
Version     : $version
Go          : $(go version)" | Set-Content -LiteralPath "$dist/VERSION.txt" -Encoding UTF8

Write-Host ""
Write-Host "==> Build complete. Files in $dist :"
Get-ChildItem $dist | ForEach-Object {
    $sizeKB = [math]::Round($_.Length / 1KB, 1)
    Write-Host ("    {0,-16} {1,10} KB" -f $_.Name, $sizeKB)
}
$totalMB = [math]::Round((Get-ChildItem $dist | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
Write-Host ("    Total: {0} MB" -f $totalMB)
