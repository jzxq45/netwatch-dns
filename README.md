# monitor вЂ” passive LAN traffic monitor (DNS-focused scope)

Reads which devices on your own home network resolve which domains via DNS,
without any client-side install. HTTPS content is **not** inspected (no CA on
the phone вЂ” by design); packet capture (SNI/flow) is intentionally omitted in
this build вЂ” see "Skipped phases".

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

1. DHCP option 6 в†’ PC IP (DNS answers come from the monitor).
2. Force redirect/block any LANв†’*.*.*.*:53 except PC.
3. Block outbound TCP/853 (DoT) from LAN.
4. (Optional) Block known DoH endpoints:443 per device (1.1.1.1, 8.8.8.8, 9.9.9.9).

## Skipped phases (by design of this build)

- **Phase 4 (SNI sniffing) Рё Phase 6 (NetFlow) вЂ” РїСЂРѕРїСѓС‰РµРЅС‹.** РЎРєРѕСѓРї РѕРіСЂР°РЅРёС‡РµРЅ
  DNS+devices+web+ops: РџРљ РЅРµ С€Р»СЋР· Рё РЅРµ Р·РµСЂРєР°Р»РёС‚ С‚СЂР°С„РёРє, СЂРѕСѓС‚РµСЂ СЂР°Р±РѕС‚Р°РµС‚
  С€С‚Р°С‚РЅРѕ, РїРѕСЌС‚РѕРјСѓ РµРґРёРЅСЃС‚РІРµРЅРЅС‹Р№ РІРёРґРёРјС‹Р№ РёСЃС‚РѕС‡РЅРёРє РјРµС‚Р°РґР°РЅРЅС‹С… вЂ” DNS-Р»РѕРі Рё
  СѓСЃС‚СЂРѕР№СЃС‚РІР°, РЅР°Р±Р»СЋРґР°РµРјС‹Рµ РїРѕ DNS-Р°РєС‚РёРІРЅРѕСЃС‚Рё. РЎС…РµРјР° `sni_log`/`flow_log`
  РѕСЃС‚Р°С‘С‚СЃСЏ РІ Р‘Р” (РїСѓСЃС‚С‹Рµ); РєРѕРґ Р·Р°С…РІР°С‚Р° (Npcap-Р·Р°РІРёСЃРёРјС‹Р№) РµСЃС‚СЊ С‚РѕР»СЊРєРѕ РІ РёСЃС‚РѕСЂРёРё
  РєРѕРјРјРёС‚РѕРІ. Р”Р»СЏ РІРѕР·РІСЂР°С‚Р° SNI РЅСѓР¶РµРЅ port mirroring РёР»Рё РџРљ-С€Р»СЋР·.
- Devices Р±РµР· ARP/DHCP: hostname Рё MAC РѕСЃС‚Р°СЋС‚СЃСЏ РїСѓСЃС‚С‹РјРё/РЅРµРёР·РІРµСЃС‚РЅС‹РјРё вЂ”
  С‚Р°Р±Р»РёС†Р° СѓСЃС‚СЂРѕР№СЃС‚РІ РЅР°РїРѕР»РЅСЏРµС‚СЃСЏ РїРѕ Р°РєС‚РёРІРЅРѕСЃС‚Рё DNS-РєР»РёРµРЅС‚РѕРІ.

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

Own network, users informed. Metadata only: domains/IP вЂ”
no HTTPS content, no MITM, no packet capture in this scope.

## Android APK

WebView wrapper (ndroid/): иконка «DNS Monitor» в лаунчере, fullscreen WebView,
pull-to-refresh, экран ошибки и встроенные Настройки (адрес сервера + API-токен,
проверка через /healthz). Не TWA: TWA требует HTTPS, монитор работает по HTTP в LAN.

- Готовый APK: GitHub Actions > артефакт app-debug.apk (или собери: см. android/README.md).
- Установка: db install app-debug.apk или открыть файл на телефоне.
- Troubleshooting: docs/ANDROID.md.
- Опциональный токен: web_token: в monitor.yaml (см. monitor.yaml.example); в приложении задать его в Настройках.

