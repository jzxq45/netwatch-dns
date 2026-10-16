# Architecture

Stack: Go 1.23+ · `github.com/miekg/dns` · `modernc.org/sqlite` (pure Go,
CGO=0) · `log/slog` · `net/http` + `html/template` · errgroup.

## Layers

```
 cmd/monitor          wiring: config → store → components → errgroup
   internal/config    YAML + MONITOR_* env overrides (defaults → yaml → env)
   internal/store     SQLite open (WAL), schema, async Sink, read queries
   internal/dns       DNS server (:53): log+enforce+forward, noise/block matchers
   internal/devices   device table upserts from DNS activity
   internal/web       HTTP UI :8080 + JSON API, optional web_token auth
   internal/retention daily delete of rows older than retention_days
```

Dependencies point strictly downwards: `dns`, `devices`, `web`, `retention`
depend on `store`; `store` knows nothing about them.

## Data flow (happy path)

```mermaid
sequenceDiagram
    participant C as 192.168.1.8 (client)
    participant D as dns server
    participant S as store.Sink (async)
    participant U as upstream 1.1.1.1
    C->>D: A example.com.
    D->>D: strip LAN search suffix for log (not for forward)
    D->>S: TrySend(client, domain, qtype, ts, noise) [non-blocking]
    alt doh endpoint blocked
        D-->>C: NXDOMAIN per local policy (no upstream contact)
    else noise (matcher hit)
        Note over D: no stdout log; row stored with noise=1
    end
    D->>U: forward original question
    U-->>D: answer
    D-->>C: answer (tx-id restored)
    S->>S: batch 100 rows / 100ms → tx insert
```

## Database schema

```sql
devices  (ip PK, mac NULL, hostname NULL, last_seen)      -- last_seen always refreshed
dns_log  (id PK AI, client_ip, domain, qtype, ts, noise INTEGER DEFAULT 0)
sni_log  (id PK AI, client_ip, sni, ts)                   -- empty: scoped out
flow_log (id PK AI, src_ip, dst_ip, dst_port, bytes, ts)  -- empty: scoped out
indices: dns(ts), dns(client_ip), sni(ts), flow(ts), flow(src)
```

Pragmas: `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`,
pool = 1 connection (single-writer serialization for the pure-Go driver).
DNS rows carry `noise=1` for background traffic and enforced-DoH attempts;
readers filter them by default (`/?show=all` reveals them).

## Concurrency model

| Goroutine | Lifetime | Channels/notes |
| --- | --- | --- |
| main → errgroup | process | ctx from `signal.NotifyContext` |
| dns: udp listener | errgroup | `serve()` waits for `ListenAndServe` or ctx |
| dns: tcp listener | errgroup | same handler as udp |
| dns: block-log flusher | errgroup | ticker=10s; aggregated `dns_blocked_doh` lines |
| dns: Sink writer | errgroup child | `values chan []any` (cap 1024); TrySend never blocks; overflow = drop + warn |
| devices resolver | errgroup | fed synchronously from `dnsSrv.OnRecord` |
| web http.Server | errgroup | read-only queries |
| retention | errgroup | startup sweep + 24h ticker |

Key rule: **the serve path never blocks on storage**. The batch writer owns
DB writes; the web UI reads via the same single-connection pool (WAL allows
readers during writes).

## Graceful shutdown

SIGINT/SIGTERM → ctx canceled:

1. listeners closed (miek `Shutdown` fired/backgrounded, don't wait the
   close-wait);
2. Flusher flushes its last aggregated line;
3. Sink drains every accepted row from the channel (drain-on-cancel), commits
   the final batch with `context.WithoutCancel`;
4. `errgroup.Wait` returns only after that — `main`'s deferred `db.Close()`
   runs later in defer order, so nothing is lost.

Tests lock this in: every store-backed test asserts rows are present after
the server context is canceled.