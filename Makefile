GO ?= go
export CGO_ENABLED = 0

.PHONY: build test lint fmt tidy pcap run clean

build:
	$(GO) build ./...

test:
	$(GO) test -race ./...

lint:
	$(GO) vet ./... && gofmt -l .

fmt:
	gofmt -w .

tidy:
	$(GO) mod tidy

# needs Npcap (Windows) / libpcap (unix) and elevated privileges
pcap:
	$(GO) build -tags pcap -o monitor.exe ./cmd/monitor

run: build
	@./monitor.exe

clean:
	rm -f monitor.exe
