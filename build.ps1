# Pins all Go toolchain write-paths to D: so caches/binaries never land on C:.
$env:GOPATH = 'D:\projects\gopath'
$env:GOBIN = 'D:\projects\gopath\bin'      # go install output
# GOMODCACHE defaults to $GOPATH\pkg\mod — on D: automatically.
# Requires CGO_ENABLED=0 (pure-Go sqlite); set explicitly for build reproducibility.
$env:CGO_ENABLED = '0'

if (-not $args -or $args.Count -eq 0) {
    $args = @('build', './...')
}
"gofmt: " + ((gofmt -l . 2>$null) -join ', ')
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
