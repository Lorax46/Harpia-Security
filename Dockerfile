FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o harpia-security cmd/harpia/main.go

FROM alpine:3.20
RUN apk add --no-cache bash curl jq python3 py3-pip
COPY --from=builder /app/harpia-security /usr/local/bin/
COPY scripts/ /opt/harpia/scripts/
RUN chmod +x /opt/harpia/scripts/*.sh 2>/dev/null || true
WORKDIR /data
ENTRYPOINT ["harpia-security"]
CMD ["--help"]
