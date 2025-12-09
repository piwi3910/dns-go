# Multi-stage build for DNS Go binaries
# Supports building: dns-server (standalone), dns-control, dns-worker

FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build all binaries
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/dns-server ./cmd/dns-server
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/dns-control ./cmd/dns-control
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/dns-worker ./cmd/dns-worker

# Final minimal image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 dns && adduser -u 1000 -G dns -s /bin/sh -D dns

# Copy binaries from builder
COPY --from=builder /bin/dns-server /usr/local/bin/
COPY --from=builder /bin/dns-control /usr/local/bin/
COPY --from=builder /bin/dns-worker /usr/local/bin/

# Create config directory
RUN mkdir -p /etc/dns-go && chown dns:dns /etc/dns-go

# Default to dns-server (standalone mode)
USER dns
WORKDIR /home/dns

EXPOSE 53/udp 53/tcp 8080 9090 6060

# Entrypoint allows selecting which binary to run
ENTRYPOINT ["/usr/local/bin/dns-server"]
CMD ["-config", "/etc/dns-go/config.yaml"]
