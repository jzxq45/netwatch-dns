# ПРОЕКТ: passive LAN monitor (DNS-скоуп)

Документ описывает: что построено, как это устроено, как работает,
что осталось сделать и как. Обновляется по мере развития.

---

## 1. ИДЕЯ И СКОУП

- Мониторить домашний Wi-Fi: кто какие домены резолвит и когда активен,
  БЕЗ установки чего-либо на телефон.
- ПК выступает ТОЛЬКО DNS-сервером (роутер работает как прежде).
- Захвата пакетов (SNI/NetFlow) в этой версии НЕТ — см. §10.
- HTTPS-контент никогда не читается (нет CA на телефоне, MITM запрещён).

---

## 2. АРХИТЕКТУРА (текущая)

```
 phone / laptop / iot ──► роутер (неизменён; DHCP выдаёт DNS = IP ПК)
                          │
                          ▼  udp/tcp :53
 ┌─────────────────────── ПК: monitor.exe ───────────────────┐
 │                                                           │
 │  dns server ──► store.Sink (batch writer) ──► sqlite WAL  │
 │      │                       │                            │
 │      └── OnRecord ──► devices resolver (upsert devices)    │
 │                                                           │
 │  web UI :8080  ◄── только чтение sqlite (read pool)       │
 │  retention — удаляет строки старше N дней раз в сутки      │
 └───────────────────────────────────────────────────────────┘
```

Поток данных DNS:
```
телефон → dns-сервер → [лог в dns_log (async)] → upstream (1.1.1.1) → ответ назад
              └→ devices (обновление device.IP по активности)
web UI читает sqlite и рисует ленту/устройства/топ/историю
```

---

## 3. СТРУКТУРА РЕПОЗИТОРИЯ

```
cmd/monitor/main.go           — wiring: config → store → компоненты → errgroup + graceful
internal/config/config.go     — YAML + env-override (MONITOR_*), значения по умолчанию
internal/store/store.go       — открытие SQLite (WAL, busy_timeout), миграция схемы
internal/store/schema.sql     — таблицы + индексы (идемпотентно, IF NOT EXISTS)
internal/store/sink.go        — общий async batch writer для всех лог-таблиц
internal/store/queries.go     — read-методы для web (feed/devices/top/history)
internal/dns/server.go        — DNS-сервер: логирование + форвард на upstream
internal/devices/resolver.go  — устройства: upsert по DNS-активности
internal/web/server.go        — HTTP: / , /devices, /device, /top, /api/events, /healthz
internal/retention/retention.go — периодическое удаление старых строк
build.ps1 / Makefile          — сборка (GOPATH закреплён на D:)
deploy/monitor.service        — systemd unit (Linux)
TODO.txt                      — ручные шаги пользователя (простым языком)
README.md                     — краткий мануал (англ.)
```

---

## 4. СХЕМА ДАННЫХ (SQLite, modernc.org/sqlite, CGO=0)

```sql
devices (ip PK, mac, hostname, last_seen)               -- ts = unix seconds
dns_log (id PK, client_ip, domain, qtype, ts)
sni_log (…)                                             -- пустая, задел фазы 4
flow_log(…)                                             -- пустая, задел фазы 6
индексы: dns(ts), dns(client_ip), sni(ts), flow(src)
```

Прагма-настройки: journal_mode=WAL, busy_timeout=5000, synchronous=NORMAL,
макс. 1 соединение (безопасная сериализация записей pure-Go драйвера).

Retention: строки старше `retention_days` удаляются (стартовый sweep + каждые 24 ч).

---

## 5. КЛЮЧЕВЫЕ ЛОГИКИ

### 5.1 DNS-сервер
- Два listener-а (UDP и TCP) на одном адресе, живут в errgroup.
- Порядок в обработчике:
  1) валидация (0 вопросов → SERVFAIL),
  2) slog-запись (client/domain/qtype/ts),
  3) `Sink.TrySend(client_ip, domain, qtype, ts)` — НЕ блокирует serve-поток,
  4) обмен с upstream и отправка ответа клиенту.
- Форвард: новый msg `SetQuestion(RecurisionDesired)`, клиент создаётся на
  каждый запрос (miekg `dns.Client` не документован как thread-safe);
  UDP → TCP fallback при усечении/потере.
- ВАЖНО: `resp.Id = r.Id` после форварда — иначе клиент игнорирует ответ
  (несовпадающий transaction ID) и это выглядело как таймаут.
- Ошибка upstream → SERVFAIL клиенту, сервер не падает.

### 5.2 Async batch writer (store.Sink)
- Буфер 1024, батч 100 строк или 100 мс.
- `TrySend` не блокирует; при переполнении писатель дропает строку и логирует.
  Мониторинг никогда не тормозит DNS.
- На shutdown finally: добирает всё из буфера и комитит последним tx —
  всё, что было принято, гарантированно попадает в базу. Только после этого
  компонент возвращается и main закрывает SQLite.
- Flush использует `context.WithoutCancel` — сброс переживает cancel.

### 5.3 Devices resolver
- Источник — DNS-активность: `dnsSrv.OnRecord → devRes.Feed → upsert`.
- Upsert: `ON CONFLICT(ip) DO UPDATE`, mac/hostname передаются NULL и
  `COALESCE` сохраняет старые значения (не затирать данные будущих
  источников с настоящими MAC/hostname).
- Ограничение скоупа: mac/hostname остаются NULL (нет слушания ARP/DHCP).

### 5.4 Web UI
- stdlib net/http + html/template, серверный рендер, meta-refresh 5 с на live.
- Маршруты:
  - `/` — live-лента (UNION dns+sni, ORDER BY ts DESC, LIMIT 100);
  - `/devices` — список устройств по last_seen DESC, IP кликабельный;
  - `/device?ip=X` — карточка (mac/hostname/last seen) + история LIMIT 100;
  - `/top?period=1h` — count(domain) group by device+domain, окно 15 м..7 д;
  - `/api/events?since=<ts>` — JSON (до 500 событий);
  - `/healthz` — "ok".
- Безопасность: html/template экранирует весь вывод; ip-параметр проверяется
  `net.ParseIP` (мусор → 400); все SQL — параметризованы.
- Клиентские IP в лентах и списке — ссылки на `/device?ip=…`.

### 5.5 Retention
- Whitelist таблиц (`RetentionTables`) — DELETE собирается только по ним.
- Sweep сразу на старте (покрывает простой ПК) + тик каждые 24 ч.
- cutoff = now − `retention_days` (default 7).

---

## 6. КОНФИГ (monitor.yaml; каждое поле переопределяется env)

```yaml
interface: eth0            # зарезервировано под фазы с захватом (не юзается)
upstream_dns: 1.1.1.1:53   # куда форвардится запрос
dns_listen: 0.0.0.0:53     # UDP+TCP listener
web_listen: 127.0.0.1:8080
db_path: monitor.db
retention_days: 7
```

Порядок применения: defaults → yaml → env (MONITOR_INTERFACE, MONITOR_UPSTREAM_DNS,
MONITOR_DNS_LISTEN, MONITOR_WEB_LISTEN, MONITOR_DB_PATH, MONITOR_RETENTION_DAYS).

---

## 7. ЗАПУСК И ПРОВЕРКА

```
.\monitor.exe                     # окно остаётся открытым — это сервер
nslookup example.com 127.0.0.1    # во втором окне; в логе появится "dns query"
http://127.0.0.1:8080             # UI
```

Замечание: "Server: UnKnown" у nslookup — норма (PTR для 127.0.0.1 не резолвится,
в логе видно `qtype=PTR domain=1.0.0.127.in-addr.arpa.`). Если порт 53 занят
д другим сервисом — перевесить `dns_listen` или освободить порт.

---

## 8. ТЕСТЫ (все зелёные: `go test -race ./internal/...`)

- internal/dns: эфемерный порт + фейковый upstream; проверка записи в dns_log
  и graceful-останова (дренаж батча).
- internal/devices: spy-store; дроп при переполнении очереди; дренаж после cancel.
- internal/store: идемпотентность схемы при повторном Open; UpsertDevice COALESCE;
  DeleteOld whitelist.
- internal/web: httptest по всем роутам, история устройства, invalid ip → 400,
  unknown ip → пустая история, JSON API (порядок по ts DESC).

Сборка/проверка: `build.ps1 all` или `make test`.

---

## 9. РАЗВЁРТЫВАНИЕ

- Windows (сейчас): ручной запуск PowerShell. Автозапуск — Планировщик задач
  (см. TODO.txt §5 / roadmap §11.2).
- Linux/Raspberry: `deploy/monitor.service` (systemd), рабочий каталог
  /var/lib/monitor, права через CAP_NET_RAW (запас под будущий pcap).
- Сборка: `build.ps1`/`make` (CGO_ENABLED=0, GOPATH → D:\projects\gopath).

---

## 10. ЧТО ПРОПУЩЕНО И ПОЧЕМУ (сфокусированный скоуп)

- **Фаза 4 (SNI) и фаза 6 (NetFlow collector) — пропущены.**
  Причины: ПК не шлюз, роутер штатный (нет зеркалирования/NetFlow-экспорта),
  к телефону ничего не прикладывается. Всё, что требует перехвата пакетов,
  в текущем скоупе недостижимо по определению.
  Частично написанный для фаз 3/4/6 код (pcap-капча, sni-парсер, ARP-фид)
  вырезан из дерева и живёт в git-истории (`6cfda17`, `58ba395`).
- MAC/hostname устройств — до включения захвата остаются NULL.
- Таблицы sni_log / flow_log в схеме есть, но пустые (задел);
  unified-читалка web уже умеет их показывать, когда появятся данные.

---

## 11. ROADMAP ДАЛЬШЕ

1. Организационная проверка (твои руки): роутер DHCP DNS → ПК (TODO.txt §1),
   телефон в /devices, nslookup-verify.
2. Автозапуск Windows: Task Scheduler + лог в файл (тихий режим).
3. Простой DNS-кэш (domain+qtype → TTL): уменьшить долю запросов в upstream.
4. Фаза 3 (инфrastructure): Npcap + ARP/DHCP listener → mac/hostname в devices.
5. Фаза 4: TCP reassembly для ClientHello, маркер `<ech>` — парсер в истории git.
6. Фаза 6: NetFlow/IPFIX :2055 → flow_log (когда появится роутер с экспортом).
7. Экспорты: CSV dump, метрики для Prometheus — по запросу.
8. Hardening: IP-allowlist на DNS (LAN only), rate-limit, ротация логов.

---

## 12. ИЗВЕСТНЫЕ ОГРАНИЧЕНИЯ / КОНТРОЛЬ

- SQLite пишет через одно соединение: throughput записи ~1–2k строк/мин —
  для домашней сети с запасом; при нагрузке — пересмотреть пул/режим записи.
- DNS-сервер сейчас отвечает всем, кто дотянется до :53 — добавить разрешение
  только LAN-адресов (roadmap §11.8), иначе возможна амлификация снаружи.
- Retention не ограничивает рост между sweeps — ок для дней, не для лет.
- Захвата пакетов нет ⇒ SNI/объёмы и настоящий MAC/hostname недоступны — это
  не баг, а свойство скоупа (см. §10).
