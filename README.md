# monitor — passive LAN traffic monitor (DNS-focused scope)

Reads which devices on your own home network resolve which domains via DNS,
without any client-side install. HTTPS content is **not** inspected (no CA on
the phone — by design); packet capture (SNI/flow) is intentionally omitted in
this build — see "Skipped phases".

## Build

Any host:

    CGO_ENABLED=0 go build -o monitor ./cmd/monitor
    # or on Windows: powershell -File build.ps1 all

## Config (monitor.yaml)

    interface: eth0            # (reserved for future capture phases; unused now)
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
4. (Optional) Block known DoH endpoints:443 per device (1.1.1.1, 8.8.8.8, 9.9.9.9).

## Skipped phases (by design of this build)

- **Phase 4 (SNI sniffing) и Phase 6 (NetFlow) — пропущены.** Скоуп ограничен
  DNS+devices+web+ops: ПК не шлюз и не зеркалит трафик, роутер работает
  штатно, поэтому единственный видимый источник метаданных — DNS-лог и
  устройства, наблюдаемые по DNS-активности. Схема `sni_log`/`flow_log`
  остаётся в БД (пустые); код захвата (Npcap-зависимый) есть только в истории
  коммитов. Для возврата SNI нужен port mirroring или ПК-шлюз.
- Devices без ARP/DHCP: hostname и MAC остаются пустыми/неизвестными —
  таблица устройств наполняется по активности DNS-клиентов.

## Components

| package          | what                                                        |
|------------------|-------------------------------------------------------------|
| internal/dns     | miekg/dns UDP+TCP server, logs + async write via store.Sink |
| internal/devices | device table updates from the DNS feed                       |
| internal/web     | live feed / devices / top / JSON API / healthz (stdlib only)  |
| internal/store   | modernc.org/sqlite (CGO=0), WAL, batch writer, retention      |

## Web UI

    GET /               live feed (last 100, meta-refresh 5s)
    GET /devices        device list with last_seen
    GET /top?period=1h  top domains per device (15m..7d)
    GET /api/events?since=<ts>   JSON feed for scripts
    GET /healthz

## Legal

Own network, users informed. Metadata only: domains/IP —
no HTTPS content, no MITM, no packet capture in this scope.
