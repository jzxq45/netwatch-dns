# Contributing

Спасибо за интерес к проекту. Правила минимальны и сводятся к:
маленькие PR, тестированный код, нейтральная терминология.

## Build / run

```
git clone https://github.com/jzxq45/netwatch-dns && cd netwatch-dns
go build ./...
```

| | Windows (PowerShell) | Linux |
| --- | --- | --- |
| Build binary | `$env:CGO_ENABLED='0'; go build -o monitor.exe ./cmd/monitor` | `CGO_ENABLED=0 go build -o monitor ./cmd/monitor` |
| Run | `.\monitor.exe` | `./monitor` |

## Tests

```
go test -race ./...
```

Windows: для race-детектора нужен cgo, поэтому при необходимости:
`$env:CGO_ENABLED='1'; go test -race ./...`.

Новые фичи покрываются table-driven тестами (`t.Parallel()`), без
mock-фреймворков — лёгкие spy/fake реализации прямо в пакете.

## Style

- `gofmt` / `goimports` обязателен.
- `golangci-lint run` локально — желательно (CI использую минимальный набор:
  govet, errcheck, ineffassign, gofmt).
- Ошибки заворачиваются с контекстом: `fmt.Errorf("op: %w", err)`.
- Конкурентность: context-first + errgroup; serve-пути не блокируются
  (см. docs/ARCHITECTURE.md).
- Никакого MITM/capture-кода: это скоуп проекта (README → What it does NOT do).

## PR process

1. Форк → ветка `feature/<короткое-имя>`.
2. Прогон тестов в PR-описании.
3. Один PR = одна логическая вещь.
4. Скриншоты UI — только с фейковыми данными (192.168.1.x, example.com).

## Documentation language

README — английский, mirrors — русский. Не используй "spy"/"hack";
см. [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md).