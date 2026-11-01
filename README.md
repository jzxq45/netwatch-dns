# netwatch-dns

> Passive DNS telemetry, ad-blocking and device intelligence for your home
> LAN. See what domains each device resolves, block trackers and ads, and
> identify every gadget on the network — with no client-side install on
> phones or laptops.

[![CI](https://github.com/jzxq45/netwatch-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/jzxq45/netwatch-dns/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Android APK](https://img.shields.io/badge/Android-APK-3DDC84?logo=android)](android/README.md)

*(badges/links point at `github.com/jzxq45/netwatch-dns`)*

---

## What it does

- Runs as the **LAN DNS resolver** on one always-on host (a PC on your network).
  The router hands out that host IP as the DNS server; every client device sends
  every hostname lookup to it, so it becomes a complete, passive record of
  network-wide DNS activity.
- **Inbound DNS-over-HTTPS (RFC 8484)**: `/dns-query` endpoint accepts binary and base64url
  DNS queries over HTTPS. Allows mobile phones and browsers outside your LAN to use NetWatch securely.
- **Zero-Day AI Threat Shield**: embedded Shannon entropy and homoglyph analyzer detects DGA
  malware domains and brand-spoofing phishing attacks before they appear in public blocklists.
- **SafeSearch Enforcement**: 1-click strict family filter for Google, YouTube, Bing, DuckDuckGo,
  and Yandex without installing client-side software.
- **Smart Home Privacy X-Ray**: identifies IoT gadgets (Smart TVs, speakers, cameras) via Win32 `SendARP`
  and IEEE OUI, calculates a Privacy Grade (A+ to F), and detects telemetry/ACR leaks.
- **Zero-Friction QR Pairing & Apple Profile**: scan the QR code to pair your phone; iPhones and Macs
  install a native `com.apple.dnsSettings.managed` profile (`/netwatch.mobileconfig`) in seconds.
- Every query is recorded: **client IP, domain, query type, timestamp** — into local SQLite (WAL mode).
- Returns **NXDOMAIN for known DoH/DoT endpoints** (`dns.google`, `chrome.cloudflare-dns.com`, …) —
  *preventing DNS filtering bypass by clients* that hardcode their own resolvers.
- **AdBlock engine**: ships with a built-in [`blocklist.txt`](blocklist.txt), 1-click services blocking
  (YouTube, TikTok, Telegram, Discord, Steam, Roblox, VK), and custom local rewrites (A/AAAA).
- **High-Performance DNS Engine**: parallel upstream racing (lowest latency wins), optimistic cache
  prefetch, RFC 1035/2181 Bailiwick poisoning defense, EDNS0 buffer clamping, and Singleflight deduplication.
- **Web UI & Live Intelligence**: live SSE query stream with real-time substring search,
  filter chips (Blocked / Allowed), per-device query log, 24h timeline chart, CSV/JSON export, and Prometheus metrics (`/metrics/prometheus`).
- **Mobile companion**: hand out `netwatch.apk` straight from the web panel (`/download/netwatch.apk`).
- Automatic retention: rows older than N days (default 7) are deleted daily.

## Comparison: NetWatch DNS vs Pi-hole vs AdGuard Home

| Feature | **NetWatch DNS** | **AdGuard Home** | **Pi-hole** |
|:---|:---:|:---:|:---:|
| **Architecture** | **Pure Go, zero CGO, single binary** | Go + Node build | C (FTL) + PHP + lighttpd |
| **Zero-Day AI Threat Shield** | **✅ Built-in DGA & Phishing Heuristics** | ❌ Blocklists only | ❌ Blocklists only |
| **Smart Home Privacy X-Ray** | **✅ IoT Leak Audit & Grade (A+..F)** | ❌ Raw query counts | ❌ Raw query counts |
| **Instant Apple DNS Profile** | **✅ Native `.mobileconfig` + SVG QR** | ❌ Manual config | ❌ Manual config |
| **Inbound DNS-over-HTTPS** | **✅ RFC 8484 (`/dns-query`)** | ✅ Supported | ⚠️ Extra proxy needed |
| **Family SafeSearch** | **✅ 1-Click (Google, YT, Bing, Yandex, DDG)** | ✅ Supported | ⚠️ Manual regex rules |
| **Parallel Upstream Racing** | **✅ Fastest upstream wins** | ⚠️ Optional | ⚠️ All or sequential |
| **Optimistic Cache Prefetch** | **✅ Refreshes hot entries before expiry** | ✅ Supported | ❌ Only on cache miss |
| **Live Stream Search & Filter** | **✅ Real-time substring & status filter** | ⚠️ Page refresh | ⚠️ Polling |
| **Native Windows Tray GUI** | **✅ Built-in WebView2 + System Tray** | ❌ Web service only | ❌ Linux only |

## What it does NOT do

- **No TLS/HTTPS inspection.** SNI is not captured, packet payloads are never
  read, and no CA is installed on any client device.
- **No MITM.** Rejected by design: it would break certificate pinning and
  require administrator rights on every phone.
- **No packet capture.** This build does not use pcap/SNI/NetFlow; there are
  no privileges beyond binding port 53.
- **No tracking of HTTP traffic.** Only DNS lookups (domain names), not which
  sites are opened or for how long.
- **No cloud.** Everything stays on the monitor host disk.

## How it works

```
 phone / laptop / TV        router (unchanged, but DHCP now hands
      |                     out the monitor host IP as DNS)
      └────────────────────────────┐
                                   ▼ UDP/TCP :53
 ┌───────────────────────── monitor host: monitor.exe ───────────────────┐
 │                                                                       │
 │  DNS server (udp+tcp :53)                                             │
 │    ├─ log query → async batch writer ──► SQLite (WAL)                 │
 │    ├─ DoH/DoT endpoints ──► NXDOMAIN per local policy                 │
 │    └─ forward ──► upstream 1.1.1.1:53 ──► answer back to client       │
 │                                                                       │
 │  device resolver (upsert by DNS activity)                             │
 │  web UI :8080 (read-only over SQLite)                                 │
 │  retention sweep (daily)                                              │
 └───────────────────────────────────────────────────────────────────────┘
```

*(screenshots are skipped for privacy — this ASCII mock with dummy data stands in; see / on the live monitor for the real thing)*

```
 ┌─────────────────────────────────────────────────────────────┐
 │ ● netwatch                Лента   Устройства   Топ          │
 ├─────────────────────────────────────────────────────────────┤
 │ 21:42:10  DNS  192.168.1.8   example.com                    │
 │ 21:42:08  DNS  192.168.1.8   test.example.org               │
 │ 21:42:07  SNI  192.168.1.8   cdn.example.org                │
 │ 21:41:50  DNS  192.168.1.15  fake.local                    │
 │ …                                                           │
 └─────────────────────────────────────────────────────────────┘
```

## Requirements

- A host that is always on: Windows / Linux / Raspberry Pi.
- Go 1.26+ to build — **or grab the ready-made Windows binaries** (see below).
- Admin rights only for port 53 on Windows (see [Troubleshooting]).
- Your router must allow setting the LAN DNS server (almost all do; see
  [docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md)).

## Downloads (Windows, no build needed)

Grab [`netwatch-windows-amd64.zip`](https://github.com/jzxq45/netwatch-dns/releases/latest)
from GitHub Releases. It contains:

- **`netwatch.exe`** — zero-friction desktop app:
  - auto-detects the LAN IP and the router gateway;
  - **one-click DNS switch** to point Windows at netwatch (and back);
  - **auto-start** via the Windows registry (toggle in the UI);
  - **automatic Windows Firewall tuning** — opens UDP 53 and TCP 8080 for you;
  - minimizes to the **system tray** with an icon and a context menu;
    closing the tray stops the servers gracefully;
  - if port 53 is taken by the OS, it **falls back to a LAN IP** and keeps
    serving. Errors surface as native dialogs; logs land in `netwatch.log`
    next to the binary. Requires the WebView2 runtime (preinstalled on
    Windows 11; on old Windows 10 installs it via https://aka.ms/webview2 —
    otherwise the UI automatically opens in your default browser).
- **`monitor.exe`** — classic console server (for scheduled tasks, services,
  remote hosts): same engine, logs to stdout.
- `blocklist.txt` — starter blocklist (trackers/ads) loaded at first run.
- `run.bat` — double-click launcher for `netwatch.exe`.
- `netwatch.apk` — prebuilt Android app, if the zip was cut with it.
- `VERSION.txt` — build timestamp and git version.

Both binaries are built with `CGO_ENABLED=0` and embed everything (UI, static
assets); only the WebView2 runtime on the user's machine is external. To cut
a local release zip, run `scripts/build_dist.ps1`.

## Quick Start

### 1. Get the binary

Either put `netwatch.exe` from the [releases zip](#downloads-windows-no-build-needed)
next to a `monitor.yaml`, or build from source:

```
git clone https://github.com/jzxq45/netwatch-dns && cd netwatch-dns
# Windows (PowerShell):
$env:CGO_ENABLED='0'; go build -o monitor.exe ./cmd/monitor          # console
$env:CGO_ENABLED='0'; go build -ldflags "-s -w -H windowsgui" -o netwatch.exe ./cmd/netwatch  # GUI window
# Linux/macOS:
CGO_ENABLED=0 go build -o monitor ./cmd/monitor
```

### 2. Free port 53 (Windows)

Port 53 is usually taken by the OS DNS cache or ICS. Easiest first check:
```
# Windows (PowerShell, admin):
netstat -ano | findstr :53
sc.exe config dnscache start= disabled; net stop dnscache
```
Full guide with restore steps: [docs/WINDOWS-PORT53.md](docs/WINDOWS-PORT53.md).
On Linux check `resolv.conf` / `systemd-resolved` and `ss -lunp :53`.
If freeing the port is not desirable, just move the listener:
`dns_listen: 0.0.0.0:5300` plus a router DNS-forwarding rule.

### 3. Docker / Docker Compose

Run without building anything on the host:

```bash
# Docker Compose
docker compose up -d
```

The compose file mounts `./data:/data` for persistent SQLite storage (the DB
survives container restarts and upgrades) and exposes port **53 (UDP/TCP)**
for DNS queries and **8080 (TCP)** for the web UI:

```yaml
ports:
  - "53:53/udp"
  - "53:53/tcp"
  - "8080:8080"
volumes:
  - ./data:/data
```

Then point your router's DHCP DNS at the Docker host IP.

### 4. Reserve a static IP for the monitor host

Router → DHCP settings → bind the host MAC to a fixed lease
(e.g. `192.168.1.5`) or set a static IP on the host itself.

### 5. Run monitor

```
.\netwatch.exe         # desktop window with the UI; closing it stops everything cleanly
.\monitor.exe          # console server — keep the window open; for scripts/services
# or as a scheduled task / systemd unit: see deploy/monitor.service (Linux)
```
Output (console build): `msg=started db=… dns=0.0.0.0:53 upstream=1.1.1.1:53 web=127.0.0.1:8080`.
The GUI build writes the same lines to `netwatch.log` next to the binary.

### 6. Verify locally

```
nslookup example.com 127.0.0.1     # Windows
dig @127.0.0.1 example.com         # Linux
```
Expect an answer and a `dns query` line in the console.

### 7. Configure the router

- DHCP → DNS server = monitor host IP (e.g. `192.168.1.5`).
- Optional: block outbound DoT (:853) so clients cannot bypass the resolver —
  see [docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md).

### 8. Reconnect a client device

Toggle Wi-Fi off/on (or reboot the phone) so it picks the new DNS via DHCP.

No-router alternative for iPhones/iPads/Macs: install the managed DNS
profile `http://<monitor-ip>:8080/netwatch.mobileconfig` once and the device
uses netwatch-resolver without touching DHCP (details:
[docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md), "Per-device DNS").

### 9. Open the web UI

`http://<monitor-ip>:8080` from any browser. On the phone: Add to Home Screen
(see [docs/MOBILE.md](docs/MOBILE.md)) or install the
[Android WebView app](android/README.md).

## Configuration

`monitor.yaml` next to the binary (missing file = built-in defaults; a full
example lives in [monitor.yaml.example](monitor.yaml.example)). Any option can
be overridden with `MONITOR_*` env vars (`MONITOR_DNS_LISTEN=0.0.0.0:5300`).

```yaml
upstream_dns: 1.1.1.1:53    # where real queries go
dns_listen: 0.0.0.0:53      # UDP+TCP listener; :5300 is a safe alternative
web_listen: 127.0.0.1:8080  # 0.0.0.0:8080 to reach the UI from phones
db_path: monitor.db
retention_days: 7

skip_ptr: true               # do not log reverse (PTR in-addr.arpa) lookups
search_suffixes: [IGD_xxx]   # router search suffixes to strip from logged names
doh_log_level: debug         # debug | info | off for nx-on-DoH log lines
doh_aggregate_window: 10s    # one aggregated line per (client, domain) per window

# web_token: when non-empty, the UI requires X-Auth-Token / ?token=… / cookie
# (netwatch.exe signs in by itself — it navigates with ?token= once and keeps the cookie)
web_token: ""

# Extra background domains to keep out of the feed (still stored with noise=1):
noise_domains:
  - "*.gstatic.com"
```

## Mobile & PWA

Open `http://<monitor-ip>:8080` in a phone browser and "Add to Home Screen" —
see [docs/MOBILE.md](docs/MOBILE.md) for what works without HTTPS (and why a
service worker needs HTTPS). For a real app with launcher icon: build the
Android WebView wrapper — [android/README.md](android/README.md).

## Legal & Ethical Scope

This is an instrument for the **administrator of self-owned networks**. Read
[docs/LEGAL.md](docs/LEGAL.md) before deploying. Summary: notify household
members, do not use logs against people, keep logs local, do not republish.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| netwatch.exe shows "Server failed to start … bind:" | the port is taken (see next row) — free port 53 or change `dns_listen`/`web_listen` in `monitor.yaml` and start again |
| `bind: ...` port 53 busy at start | [docs/WINDOWS-PORT53.md](docs/WINDOWS-PORT53.md) or set `dns_listen: 0.0.0.0:5300` |
| Devices never appear in `/devices` | router still hands out the old DNS (reconnect the client); verify DHCP config |
| Phone can reach `:8080`? No — "connection refused" | check `web_listen` is `0.0.0.0:8080` and add a Windows firewall rule for TCP 8080 |
| Everything resolves but nothing is logged | check `upstream_dns` reachability, look for `upstream` error lines in the console |
| nslookup prints `Server: UnKnown` | cosmetic: no PTR for 127.0.0.1; the query still logs |
| DoH apps still work | those clients use IPv6 or 1.1.1.1 raw UDP; add CIDR firewall block for :853 and known resolver IPs on the router, see [ROUTER-SETUP] |
| 401 in the app/browser | `web_token` is set on the server but empty in the client — set the same token |

More: [docs/ANDROID.md](docs/ANDROID.md) (mobile app specifics).

## Roadmap

- [x] DNS server, logging, retention, web UI, DoH enforcement
- [x] Noise separation (noise=1 rows, hidden by default)
- [x] Android WebView app, optional web_token
- [x] Hardening: full server timeouts, panic recovery, per-IP rate limiting,
      read/write DB pool split, chunked retention, DNS admission control +
      LAN-only ACL, Prometheus metrics exposed at `/metrics`
- [x] Windows desktop app (`netwatch.exe`, WebView2 window, graceful close),
      system tray, one-click DNS switch, registry auto-start, firewall tuning
- [x] Zero-friction desktop: LAN IP/gateway autodetection, port-53 fallback
- [x] DNS response cache + upstream singleflight (no per-query sockets)
- [x] Blocklist engine: built-in `blocklist.txt`, local files, remote URL
      feeds with background refresh, whitelist priority, one-click block,
      CSV/JSON export, 24h activity chart
- [x] Device intelligence: `SendARP` MAC resolution, IEEE OUI vendor names,
      user-assigned device names, `netwatch.apk` download from the web panel
- [ ] SNI + NetFlow when a router supports mirroring/flow export
  (schema slots `sni_log`/`flow_log` already exist)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small table-driven PRs that keep
`go test -race ./...` green are the fastest way in.

## License

[MIT](LICENSE). This software ships as-is; you are responsible for how you
use it on your networks (see [docs/LEGAL.md](docs/LEGAL.md)).
