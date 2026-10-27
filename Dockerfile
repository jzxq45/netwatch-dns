# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/netwatch ./cmd/monitor

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

RUN mkdir -p /data

COPY --from=builder /bin/netwatch /usr/local/bin/netwatch

ENV MONITOR_DB_PATH=/data/monitor.db
ENV MONITOR_WEB_LISTEN=0.0.0.0:8080
ENV MONITOR_DNS_LISTEN=0.0.0.0:53

EXPOSE 53/udp 53/tcp 8080/tcp

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/netwatch"]
