# DNS-GO - High-Performance DNS Server

A high-performance, RFC-compliant DNS server implementation in Go, designed to achieve **500,000+ QPS** with linear multi-core scaling. Includes a modern web GUI for management and monitoring.

## Features

### Core DNS Server (v0.4)
- **True Recursive Resolution**: Iterative queries from root servers (a-m.root-servers.net)
  - Full DNS hierarchy traversal: root → TLD → authoritative nameservers
  - Complete independence from external resolvers
  - NS delegation following with glue record support
- **Per-Core I/O Architecture**: Dedicated UDP socket per CPU core with `SO_REUSEPORT`
- **Three-Level Caching**:
  - L1 Message Cache: Complete response caching (configurable, zero-copy serving)
  - L2 RRset Cache: Individual resource record caching (2x message cache)
  - L3 Infrastructure Cache: Server metrics for smart selection
- **Fast-Path Optimization**: 90% of queries bypass slow path (<100µs response time)
- **Zero-Allocation Hot Path**: `sync.Pool` and buffer reuse eliminate GC pressure
- **Lock-Free Reads**: Sharded caches using `sync.Map` for concurrent access
- **Dual Resolution Modes**: Recursive (from root) or Forwarding (to upstream)
- **Request Coalescing**: Deduplicates identical in-flight queries
- **YAML Configuration**: Full configuration file support

### Web GUI (NEW in v0.4)
- **Modern Dashboard**: Real-time metrics with interactive charts
  - Memory usage graph (area chart)
  - Cache hit rate comparison (multi-line chart)
  - QPS sparklines in stat cards
- **Dark/Light Theme**: System-aware theme toggle with glass morphism effects
- **Real-Time Updates**: Server-Sent Events (SSE) for live stats streaming
- **JWT Authentication**: Secure login with session management
- **Management Pages**:
  - Dashboard: Overview with live metrics and charts
  - Zones: DNS zone management
  - Upstreams: Configure upstream resolvers
  - Cache: View and manage DNS cache
  - Configuration: Server settings

## Quick Start

### Building

```bash
# Build server
go build -o dns-server ./cmd/dns-server

# Build with production optimizations
go build -ldflags="-s -w" -o dns-server ./cmd/dns-server

# Build test client
go build -o dns-test-client ./cmd/dns-test-client

# Run tests
go test ./...

# Run benchmarks
go test -bench=. -benchmem ./...
```

### Running

```bash
# Start with config file
./dns-server -config configs/config.yaml

# Start on default port (5353) with auto-detected CPU count
./dns-server

# Start on standard DNS port (requires sudo)
sudo ./dns-server -listen :53
```

### Web GUI Access

1. Start the server with API enabled (default in config)
2. Open http://localhost:8080 in your browser
3. Login with default credentials: `admin` / `admin`
4. View real-time dashboard with metrics and charts

### Testing

```bash
# Using dig
dig @127.0.0.1 -p 5353 example.com A

# Using test client
./dns-test-client -server 127.0.0.1:5353 -domain example.com -type A

# Multiple queries for cache testing
./dns-test-client -server 127.0.0.1:5353 -domain example.com -type A -count 1000
```

## Configuration

Configuration is managed via YAML file. See [configs/config.yaml](configs/config.yaml) for a complete example.

```yaml
server:
  listen_address: "127.0.0.1:5353"
  num_workers: 4
  enable_tcp: true

cache:
  message_cache:
    max_size_mb: 64
    num_shards: 32
  rrset_cache:
    max_size_mb: 128
    num_shards: 64
  prefetch:
    enabled: true
    threshold_hits: 100

resolver:
  mode: "parallel"
  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
    - "9.9.9.9:53"

api:
  enabled: true
  listen_address: ":8080"
  auth:
    username: "admin"
```

## Project Structure

```
dns-go/
├── cmd/
│   ├── dns-server/        # Main server binary
│   └── dns-test-client/   # Test client utility
├── configs/               # Configuration files
│   └── config.yaml        # Example configuration
├── pkg/
│   ├── api/              # REST API and web server
│   │   └── types/        # API request/response types
│   ├── cache/            # Three-level caching system
│   ├── config/           # Configuration loading
│   ├── dnssec/           # DNSSEC validation
│   ├── edns0/            # EDNS0 extension support
│   ├── io/               # Per-core I/O with SO_REUSEPORT
│   ├── plugin/           # Plugin system (optional)
│   ├── resolver/         # Recursive/forward resolver
│   ├── security/         # Rate limiting, validation
│   ├── server/           # DNS request handler
│   └── zone/             # Zone file management
└── web/
    ├── embed.go          # Go embed for frontend
    └── frontend/         # React + TypeScript frontend
        ├── src/
        │   ├── components/  # UI components
        │   ├── hooks/       # React hooks (SSE, auth)
        │   ├── lib/         # API client, utilities
        │   └── pages/       # Page components
        └── ...
```

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **Throughput** | 500,000+ QPS | 16-core system |
| **Per-Core QPS** | 50,000+ QPS | Linear scaling |
| **Cache Hit Rate** | 95%+ | With prefetch enabled |
| **Cached Latency** | <100µs | Fast path |
| **Recursive Latency** | <50ms | Slow path |
| **p99 Latency** | <200µs | Cache hits |
| **Memory Usage** | <2GB | Configurable cache |

### Architecture Highlights

**Avoids CoreDNS Bottlenecks:**
- CoreDNS caps at ~90K QPS on multi-core systems
- DNS-GO targets 500K+ QPS with linear scaling

**Key Optimizations:**
1. No shared state between cores (avoids lock contention)
2. Inline fast-path detection (no plugin overhead)
3. Pure Go recursive resolver (no CGO overhead)
4. Sharded everything (64+ shards per cache)

## Development

### Prerequisites

- Go 1.21+
- Node.js 18+ (for frontend development)

### Frontend Development

```bash
cd web/frontend

# Install dependencies
npm install

# Start development server with hot reload
npm run dev

# Build for production
npm run build
```

### Code Quality

```bash
# Format code
go fmt ./...

# Lint (requires golangci-lint)
golangci-lint run

# Run tests with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Performance Profiling

```bash
# CPU profiling
go test -bench=. -cpuprofile=cpu.out ./pkg/server
go tool pprof cpu.out

# Memory profiling
go test -bench=. -memprofile=mem.out ./pkg/cache
go tool pprof mem.out

# Runtime profiling (with pprof enabled)
go tool pprof http://localhost:6060/debug/pprof/profile
```

## RFC Compliance

Implemented and tested against:
- RFC 1034, 1035 - Core DNS protocol
- RFC 2181 - DNS specification clarifications
- RFC 2308 - Negative caching
- RFC 6891 - EDNS0

Planned:
- RFC 4033, 4034, 4035 - DNSSEC
- RFC 7766 - DNS over TCP
- RFC 8499 - DNS terminology

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Built with [miekg/dns](https://github.com/miekg/dns) - Battle-tested DNS library
- Frontend uses [React](https://react.dev), [Recharts](https://recharts.org), [Tailwind CSS](https://tailwindcss.com)
- Architecture inspired by Unbound's sophisticated caching strategies
