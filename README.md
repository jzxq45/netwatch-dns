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
- Every query is recorded: **client IP, domain, query type, timestamp** — into
  local SQLite.
- Returns **NXDOMAIN for known DoH/DoT endpoints** (`dns.google`,
  `chrome.cloudflare-dns.com`, …) — *preventing DNS filtering bypass by
  clients* that hardcode their own resolvers.
- **AdBlock engine**: ships with a built-in [`blocklist.txt`](blocklist.txt),
  supports background refresh by URL (`blocklist_urls`), whitelist always
  wins, and you can send an offending domain to the blocklist in one click
  straight from the live feed (🚫).
- **Device intelligence**: Win32 `SendARP` resolves MAC addresses without
  any drivers, an IEEE OUI vendor database names the maker (Apple, Samsung,
  Xiaomi, …), and devices can be renamed by hand.
- **Powerful DNS engine**: RFC 1035-compliant response cache, DNS-over-HTTPS
  (DoH) upstream, thundering-herd protection (singleflight collapse of
  identical in-flight queries), and automatic fallback to a LAN IP if port
  53 is taken by the OS.
- Web UI (server-rendered, no build step): a live feed, a device list with a
  per-device query log, per-device top domains for any time window, a 24h
  activity graph, history export to CSV and JSON (`/api/export`), and a
  small JSON API.
- **Mobile companion**: hand out `netwatch.apk` straight from the web panel
  (`/download/netwatch.apk`); the UI is fully responsive on phones.
- Automatic retention: rows older than N days (default 7) are deleted daily.

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
- Go 1.23+ to build — **or grab the ready-made Windows binaries** (see below).
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
- `monitor.yaml.example` — annotated config template.

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

### 3. Reserve a static IP for the monitor host

Router → DHCP settings → bind the host MAC to a fixed lease
(e.g. `192.168.1.5`) or set a static IP on the host itself.

### 4. Run monitor

```
.\netwatch.exe         # desktop window with the UI; closing it stops everything cleanly
.\monitor.exe          # console server — keep the window open; for scripts/services
# or as a scheduled task / systemd unit: see deploy/monitor.service (Linux)
```
Output (console build): `msg=started db=… dns=0.0.0.0:53 upstream=1.1.1.1:53 web=127.0.0.1:8080`.
The GUI build writes the same lines to `netwatch.log` next to the binary.

### 5. Verify locally

```
nslookup example.com 127.0.0.1     # Windows
dig @127.0.0.1 example.com         # Linux
```
Expect an answer and a `dns query` line in the console.

### 6. Configure the router

- DHCP → DNS server = monitor host IP (e.g. `192.168.1.5`).
- Optional: block outbound DoT (:853) so clients cannot bypass the resolver —
  see [docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md).

### 7. Reconnect a client device

Toggle Wi-Fi off/on (or reboot the phone) so it picks the new DNS via DHCP.

### 8. Open the web UI

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
      LAN-only ACL, expvar counters exposed at `/metrics`
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
