# netwatch-dns

> Пассивный DNS-мониторинг домашней/офисной LAN: видно, какие домены резолвит
> каждое устройство — без установки чего-либо на телефон/ноутбук.

[![CI](https://github.com/jzxq45/netwatch-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/jzxq45/netwatch-dns/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Android APK](https://img.shields.io/badge/Android-APK-3DDC84?logo=android)](android/README.md)

*(`github.com/jzxq45/netwatch-dns`)*

---

## Что это делает

- Работает как **DNS-резолвер для всей сети** на одном постоянно включённом
  хосте (ПК). Роутер раздаёт через DHCP IP этого хоста в качестве DNS, поэтому
  каждое клиентское устройство присылает ему все свои hostname-запросы.
- Каждый запрос записывается: **IP клиента, домен, тип запроса, время** —
  в локальный SQLite.
- Возвращает **NXDOMAIN на известные DoH/DoT-эндпоинты** (`dns.google`,
  `chrome.cloudflare-dns.com`, …) — *чтобы клиент не мог обойти заданный
  резолвер* (DNS policy enforcement).
- Web UI (серверный рендер, без сборки фронта): живая лента, список устройств
  с историей по каждому, топ доменов за окно, мини JSON API.
- Retention: строки старше N дней (по умолчанию 7) удаляются раз в сутки.

## Что НЕ делает

- **Нет инспекции TLS/HTTPS.** SNI не читается, содержимое пакетов не
  просматривается, CA на клиентских устройствах не устанавливается.
- **Нет MITM.** Отклонено принципиально: ломает certificate pinning, требует
  прав администратора на каждом телефоне.
- **Нет перехвата пакетов.** В этой сборке нет pcap/SNI/NetFlow; привилегий
  выше «занять порт 53» не требуется.
- **Не отслеживает HTTP-трафик.** Только DNS-запросы (имена доменов), не
  какие сайты открыты и сколько времени там провели.
- **Без облака.** Всё остаётся на диске хоста.
- В таблице devices пока только IP и времена first/last seen; MAC/hostname
  пусты — по сооскоупу (нет слушания ARP/DHCP).

## Как это работает

```
 телефон / ноутбук / ТВ      роутер (не меняется, но DHCP выдаёт
      |                      IP хоста-монитора как DNS)
      └─────────────────────────────┐
                                    ▼ UDP/TCP :53
 ┌──────────────────────── монит-хост: monitor.exe ──────────────────────┐
 │                                                                       │
 │  DNS-сервер (udp+tcp :53)                                             │
 │    ├─ лог запроса → async batch writer ──► SQLite (WAL)               │
 │    ├─ DoH/DoT-эндпоинты ──► NXDOMAIN по локальной политике            │
 │    └─ форвард ──► upstream 1.1.1.1:53 ──► ответ клиенту               │
 │                                                                       │
 │  device resolver (upsert по DNS-активности)                           │
 │  web UI :8080 (только чтение SQLite)                                  │
 │  retention sweep (раз в сутки)                                        │
 └───────────────────────────────────────────────────────────────────────┘
```

*(скриншоты оставлены за кадром «не публиковать реальные данные» — ниже
текстовый образ на фиктивных данных; настоящий вид — на живом мониторе)*

```
 ┌─────────────────────────────────────────────────────────────┐
 │ ● netwatch                Лента   Устройства   Топ          │
 ├─────────────────────────────────────────────────────────────┤
 │ 21:42:10  DNS  192.168.1.8   example.com                    │
 │ 21:42:08  DNS  192.168.1.8   test.example.org               │
 │ 21:42:07  SNI  192.168.1.8   cdn.example.org                │
 │ 21:41:50  DNS  192.168.1.15  fake.local                     │
 │ …                                                           │
 └─────────────────────────────────────────────────────────────┘
```

## Требования

- Всегда включённый хост: Windows / Linux / Raspberry Pi.
- Go 1.23+ для сборки — **или скачай готовые Windows-бинарники** (см. ниже).
- Права администратора — только для порта 53 на Windows (см. Troubleshooting).
- Роутер, который позволяет задать LAN DNS (почти все умеют; см.
  [docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md)).

## Готовые сборки (Windows, без Go)

Скачай [`netwatch-windows-amd64.zip`](https://github.com/jzxq45/netwatch-dns/releases/latest)
со страницы GitHub Releases. Внутри:

- **`netwatch.exe`** — настольное приложение: окно с живым интерфейсом
  (WebView2). Закрытие окна штатно останавливает все сервисы. Запустил
  двойным щелчком — и всё. Ошибки всплывают нативными диалогами, логи — в
  `netwatch.log` рядом с бинарником. Нужен WebView2 runtime (предустановлен
  в Windows 11; на старых Windows 10 ставится с https://aka.ms/webview2 —
  иначе интерфейс автоматически откроется в обычном браузере).
- **`monitor.exe`** — классический консольный сервер (для планировщика,
  служб, удалённых хостов): тот же движок, логи в stdout.
- `monitor.yaml.example` — конфиг с комментариями.

Оба бинарника собраны с `CGO_ENABLED=0` и содержат всё (UI, статику);
снаружи — только WebView2 runtime на машине пользователя.

## Быстрый старт

### 1. Получить бинарник

Положи `netwatch.exe` из [архива релизов](#готовые-сборки-windows-без-go)
рядом с `monitor.yaml` — либо собери из исходников:

```
git clone https://github.com/jzxq45/netwatch-dns && cd netwatch-dns
# Windows (PowerShell):
$env:CGO_ENABLED='0'; go build -o monitor.exe ./cmd/monitor           # консоль
$env:CGO_ENABLED='0'; go build -ldflags "-s -w -H windowsgui" -o netwatch.exe ./cmd/netwatch  # окно GUI
# Linux/macOS:
CGO_ENABLED=0 go build -o monitor ./cmd/monitor
```

### 2. Освободить порт 53 (Windows)

Порт 53 обычно занят DNS-кэшем ОС или ICS. Быстрая проверка:
```
# Windows (PowerShell, админ):
netstat -ano | findstr :53
sc.exe config dnscache start= disabled; net stop dnscache
```
Полный гайд с восстановлением: [docs/WINDOWS-PORT53.md](docs/WINDOWS-PORT53.md).
На Linux проверьте `resolv.conf` / `systemd-resolved` и `ss -lunp :53`.
Если освобождать не хочется — сдвинуть слушатель:
`dns_listen: 0.0.0.0:5300` + правило форварда DNS на роутере.

### 3. Статический IP для хоста-монитора

Роутер → DHCP → привязать MAC хоста к фиксированному адресу
(например `192.168.1.5`), либо статический IP на самом хосте.

### 4. Запустить monitor

```
.\netwatch.exe         # окно с интерфейсом; закрытие окна = корректная остановка
.\monitor.exe          # консольный сервер — окно не закрывать; для скриптов/служб
# либо scheduled task / systemd unit: deploy/monitor.service (Linux)
```
Вывод (консольная сборка): `msg=started db=… dns=0.0.0.0:53 upstream=1.1.1.1:53 web=127.0.0.1:8080`.
GUI-сборка пишет те же строки в `netwatch.log` рядом с бинарником.

### 5. Проверить локально

```
nslookup example.com 127.0.0.1     # Windows
dig @127.0.0.1 example.com         # Linux
```
Ожидается ответ и строка `dns query` в консоли.

### 6. Настроить роутер

- DHCP → DNS-сервер = IP хоста (например `192.168.1.5`).
- Опционально: заблокировать наружу DoT (:853), чтобы клиенты не могли
  обойти резолвер — см. [docs/ROUTER-SETUP.md](docs/ROUTER-SETUP.md).

### 7. Переподключить клиент

Выключить/включить Wi-Fi (или перезагрузить телефон), чтобы устройство
получило новый DNS по DHCP.

### 8. Открыть web UI

`http://<ip-монитора>:8080` в любом браузере. На телефоне: «Добавить на
главный экран» (см. [docs/MOBILE.md](docs/MOBILE.md)) или установить
[Android-приложение](android/README.md).

## Конфигурация

`monitor.yaml` рядом с бинарником (нет файла — встроенные дефолты; полный
пример в [monitor.yaml.example](monitor.yaml.example)). Любое поле
перекрывается через `MONITOR_*` (`MONITOR_DNS_LISTEN=0.0.0.0:5300`).

```yaml
upstream_dns: 1.1.1.1:53    # куда идут реальные запросы
dns_listen: 0.0.0.0:53      # UDP+TCP; :5300 как безопасная альтернатива
web_listen: 127.0.0.1:8080  # 0.0.0.0:8080 чтобы открывать с телефона
db_path: monitor.db
retention_days: 7

skip_ptr: true               # не логировать reverse-запросы (PTR in-addr.arpa)
search_suffixes: [IGD_xxx]   # search-суффиксы роутера, отрезаемые у имён
doh_log_level: debug         # debug | info | off для строк анализа DoH
doh_aggregate_window: 10s    # одна агрегированная строка на окно (client, domain)

# web_token: если непусто — UI требует X-Auth-Token / ?token=… / cookie
# (netwatch.exe логинится сам: первый переход с ?token= создаёт cookie)
web_token: ""

# фоновые домены вне ленты (в БД пишутся с noise=1):
noise_domains:
  - "*.gstatic.com"
```

## Мобильные устройства и PWA

Открой `http://<ip-монитора>:8080` в браузере телефона и «Добавить на главный
экран» — что работает без HTTPS и почему service worker требует HTTPS,
см. [docs/MOBILE.md](docs/MOBILE.md). Для настоящего приложения с иконкой —
собери Android-обёртку: [android/README.md](android/README.md).

## Правовой и этический скоуп

Инструмент для **администратора собственной сети**. Прочитай
[docs/LEGAL.md](docs/LEGAL.md) перед внедрением. Кратко: уведоми членов
семьи/сотрудников, не используй логи против людей, храни логи локально,
не публиковай их.

## Troubleshooting

| Симптом | Решение |
| --- | --- |
| netwatch.exe показывает «Server failed to start … bind:» | порт занят (см. следующую строку) — освободи порт 53 или поменяй `dns_listen`/`web_listen` в `monitor.yaml` и запусти снова |
| `bind: ...` порт 53 занят при старте | [docs/WINDOWS-PORT53.md](docs/WINDOWS-PORT53.md) или `dns_listen: 0.0.0.0:5300` |
| Устройства не появляются в `/devices` | роутер всё ещё раздаёт старый DNS (переподключи клиент); проверь настройку DHCP |
| С телефона `:8080` недоступен — connection refused | проверь `web_listen: 0.0.0.0:8080` и правило firewall для TCP 8080 |
| Всё резолвится, но в БД пусто | проверь доступность `upstream_dns`, ищи строки `upstream` с ошибками в консоли |
| nslookup показывает `Server: UnKnown` | косметика: нет PTR для 127.0.0.1; запрос всё равно логируется |
| DoH-приложения всё равно работают | такие клиенты идут на IPv6 или 1.1.1.1 напрямую; добавь firewall-правило для :853 и известных адресов на роутере, см. [ROUTER-SETUP] |
| 401 в приложении/браузере | на сервере задан `web_token`, а в клиенте пусто — впиши тот же токен |

Ещё: [docs/ANDROID.md](docs/ANDROID.md) (проблемы мобильного приложения).

## Roadmap

- [x] DNS-сервер, логирование, retention, web UI, DoH enforcement
- [x] Разделение шума (rows noise=1, скрыты по умолчанию)
- [x] Android WebView-приложение, опциональный web_token
- [x] Hardening: полные таймауты сервера, panic recovery, per-IP rate limiting,
      разделение пулов read/write, чанкованный retention, DNS admission
      control + LAN-only ACL, счётчики expvar на `/metrics`
- [x] Настольное приложение Windows (`netwatch.exe`, окно WebView2, graceful close)
- [ ] DNS-кэш + переиспользование upstream-соединений (убрать сокет на запрос)
- [ ] Подгрузка blocklist-фидов (URL/списки) — «фишка в стиле Pi-hole»
- [ ] Имена устройств через чтение DHCP-аренд (админская сторона, без сниффинга)
- [ ] SNI + NetFlow, когда роутер поддерживает зеркалирование/экспорт потоков
  (слоты `sni_log`/`flow_log` в схеме уже есть)

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Быстрый путь — маленькие table-driven
PR, которые держат `go test -race ./...` зелёным.

## Лицензия

[MIT](LICENSE). Программное обеспечение поставляется «как есть»; ответственность
за использование в своих сетях — на владельце (см. [docs/LEGAL.md](docs/LEGAL.md)).
