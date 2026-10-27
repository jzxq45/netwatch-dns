# Requires CGO_ENABLED=0 (pure-Go sqlite); set explicitly for build reproducibility.
$env:CGO_ENABLED = '0'

if (-not $args -or $args.Count -eq 0) {
    & "$PSScriptRoot\scripts\build_dist.ps1"
    exit $LASTEXITCODE
}
foreach ($cmd in $args) {
    if ($cmd -eq 'all') {
        go mod tidy
        go build ./...
        go vet ./...
    }
    else {
        go @args
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
