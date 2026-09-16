# syntax=docker/dockerfile:1.4
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache modules download
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build all binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/totvs-horus ./cmd/totvs-horus/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/gateway ./cmd/gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/scan ./cmd/scan/

# Final minimal image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl jq bash tzdata && \
    addgroup -S harpia && adduser -S harpia -G harpia

WORKDIR /app

# Copy binaries
COPY --from=builder /bin/totvs-horus /usr/local/bin/
COPY --from=builder /bin/gateway /usr/local/bin/
COPY --from=builder /bin/scan /usr/local/bin/

# Copy web dashboard
COPY --from=builder /src/web/dashboard/ ./web/dashboard/

# Copy scripts
COPY --from=builder /src/scripts/ /opt/harpia/scripts/
RUN chmod +x /opt/harpia/scripts/*.sh 2>/dev/null || true

# Environment
ENV TZ=UTC
EXPOSE 8080 9090

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

USER harpia

ENTRYPOINT ["totvs-horus"]
CMD ["-port", "9090"]
