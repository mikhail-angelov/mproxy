# ---- build stage ----
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Кэшируем слой с зависимостями отдельно от исходников
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Статическая линковка — не нужны системные библиотеки в финальном образе
RUN CGO_ENABLED=0 GOOS=linux go build -o /mproxy .

# ---- final stage ----
FROM alpine:3.21

# ca-certificates нужны, чтобы forwarding на https:// сайты проходил TLS-верификацию
RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 10001 appuser

WORKDIR /app
COPY --from=builder /mproxy .

USER appuser

# 8080 — plain HTTP, 8443 — HTTPS (если PROXY_HTTPS_PORT задан)
EXPOSE 8080 8443

ENTRYPOINT ["/app/mproxy"]
