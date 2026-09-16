# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH

RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(cat VERSION 2>/dev/null || echo 'dev')" -o /bin/totvs-horus ./cmd/totvs-horus/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/gateway ./cmd/gateway/ \
 && CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/scan ./cmd/scan/

FROM --platform=$TARGETPLATFORM alpine:3.19

RUN apk --no-cache add ca-certificates curl jq bash tzdata && \
    addgroup -S harpia && adduser -S harpia -G harpia

WORKDIR /app

COPY --from=builder /bin/totvs-horus /usr/local/bin/
COPY --from=builder /bin/gateway /usr/local/bin/
COPY --from=builder /bin/scan /usr/local/bin/

COPY --from=builder /src/web/dashboard/ ./web/dashboard/

COPY --from=builder /src/scripts/ /opt/harpia/scripts/
RUN chmod +x /opt/harpia/scripts/*.sh 2>/dev/null || true

ENV TZ=UTC
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

USER harpia

ENTRYPOINT ["totvs-horus"]
CMD ["-port", "9090"]
