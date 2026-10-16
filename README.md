# monitor — passive LAN traffic monitor

Reads what devices on your own home network touch (DNS queries, TLS SNI,
device presence) without any client-side install. HTTPS content is **not**
inspected (no CA on the phone — by design).

## Build

Windows host (needs Npcap for packet capture):

    powershell -File build.ps1 all

Linux (systemd service box):

    CGO_ENABLED=0 go build -o monitor ./cmd/monitor

With packet capture + ARP scan (unix, privileged):

    CGO_ENABLED=1 go build -tags pcap -o monitor ./cmd/monitor

## Config (monitor.yaml)

    interface: eth0            # LAN iface for ARP/SNI capture
    upstream_dns: 1.1.1.1:53   # resolver the logger forwards to
    dns_listen: 0.0.0.0:53     # UDP+TCP DNS server
    web_listen: 127.0.0.1:8080
    db_path: monitor.db
    retention_days: 7

Env overrides: `MONITOR_INTERFACE`, `MONITOR_UPSTREAM_DNS`, `MONITOR_DNS_LISTEN`,
`MONITOR_WEB_LISTEN`, `MONITOR_DB_PATH`, `MONITOR_RETENTION_DAYS`.

## Router (firewall, not in Go)

1. DHCP option 6 → PC IP (DNS answers come from the monitor).
2. Force redirect/block any LAN→*.*.*.*:53 except PC.
3. Block outbound TCP/853 (DoT) from LAN.
4. Block known DoH endpoints:443 per device if needed (1.1.1.1, 8.8.8.8, 9.9.9.9).
   Optional/stronger: drop TLS ClientHello carrying an ECH extension (sniffer
   logs `<ech>` markers so devices relying on it are visible).

## Router (optional NetFlow)

If the router exports NetFlow v5/v9/IPFIX, `internal/flow` collector on :2055
lands it in `flow_log`; wiring is intentionally not enabled by default.

## Components

| package        | what                                                        |
|----------------|-------------------------------------------------------------|
| internal/dns   | miekg/dns UDP+TCP server, logs + async write via store.Sink |
| internal/sni   | TLS ClientHello parser, ECH marker, async insert             |
| internal/devices | device table updates from feed sources (DNS now; ARP/SNI when capture on) |
| internal/capture | packet-capture backends (stub by default, `-tags pcap` for real sniffing) |
| internal/web   | live feed / devices / top / JSON API / healthz (stdlib only)  |
| internal/store | modernc.org/sqlite (CGO=0), WAL, batch writer, retention      |

## Web UI

    GET /               live feed (last 100, meta-refresh 5s)
    GET /devices        device list with last_seen
    GET /top?period=1h  top domains per device (15m..7d)
    GET /api/events?since=<ts>   JSON feed for scripts
    GET /healthz

## Packet capture install (Windows)

Install Npcap (https://npcap.com/), then rebuild with `-tags pcap`;
`internal/capture` picks up WinPcap-compatible backend and SNI snooping turns
on. ARP/DHCP device discovery rides the same capture stream.

## Legal

Own network, users informed. Metadata only: domains/SNI/IP/port volumes —
no HTTPS content, no MITM.
