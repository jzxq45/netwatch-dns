//go:build !windows

// netwatch is the Windows desktop (WebView2) front-end of netwatch-dns.
// On other platforms run the console server instead: cmd/monitor.
package main

import "fmt"

func main() {
	fmt.Println("netwatch GUI is Windows-only; run the console server: go run ./cmd/monitor")
}
