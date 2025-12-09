# DNS-GO - High-Performance DNS Server

A high-performance, RFC-compliant DNS server implementation in Go, designed to achieve **500,000+ QPS** with linear multi-core scaling. Includes a modern web GUI for management and monitoring.

## Features

### Deployment Modes (NEW in v0.5)
- **Standalone Mode**: Single-process deployment for simple setups
- **Distributed Mode**: Control plane + worker architecture for high availability
  - Control Plane: Manages workers, aggregates stats, serves web GUI
  - Workers: Handle DNS queries, auto-scale based on load
- **Multiple Deployment Options**:
  - Docker / Docker Compose (standalone or distributed)
  - Kubernetes manifests with Kustomize
  - Helm chart with HPA, PDB, ServiceMonitor
  - Kubernetes Operator with DNSCluster CRD

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

### Hot-Reload & Config Persistence (NEW in v0.7)
- **Runtime Configuration Updates**: Change settings via GUI/API without restart
  - Cache TTL settings (min/max/negative TTL)
  - Prefetch configuration (enabled, thresholds)
  - Resolver coalescing and parallel settings
  - Upstream servers
- **Automatic Config Persistence**: Changes made via GUI are saved to config file
- **Graceful Restart**: Settings requiring restart (e.g., resolver mode) trigger automatic graceful restart
- **Multiple Config Stores**:
  - `FileConfigStore`: YAML file persistence for standalone mode
  - `CRDConfigStore`: Kubernetes Custom Resource for K8s deployments
  - `MemoryConfigStore`: In-memory storage for testing

### Distributed Cache Architecture (NEW in v0.6)
- **Three Cache Modes**: Standalone, Local-Only, or Hybrid with shared Redis
- **HA Redis Support**: Redis Sentinel and Redis Cluster for multi-site deployments
- **Cache Invalidation Strategies**: Local-only, PubSub (Redis), or Broadcast
- **Per-Worker L1/L2 Caches**: Each worker maintains its own high-performance local cache
- **Shared L3 Cache**: Optional Redis backend for cache persistence and cross-worker sharing
- **Multi-Cluster Cache**: Share cache state across geographically distributed clusters

See [Cache Architecture Documentation](docs/architecture/cache-architecture.md) for detailed configuration guides.

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

### Option 1: Docker (Recommended)

```bash
# Standalone mode (single container)
cd deploy/docker
docker-compose --profile standalone up

# Distributed mode (control + workers)
docker-compose --profile distributed up

# Scale workers
docker-compose --profile distributed up --scale dns-worker=5
```

### Option 2: Kubernetes

```bash
# Using raw manifests
kubectl apply -k deploy/kubernetes/

# Using Helm
helm install dns-go deploy/helm/dns-go/

# Using Operator
cd deploy/operator
make install && make deploy
kubectl apply -f config/samples/dns_v1alpha1_dnscluster.yaml
```

### Option 3: Build from Source

```bash
# Build server
go build -o dns-server ./cmd/dns-server

# Build with production optimizations
go build -ldflags="-s -w" -o dns-server ./cmd/dns-server

# Build all binaries (server, control, worker)
go build ./cmd/dns-server
go build ./cmd/dns-control
go build ./cmd/dns-worker

# Run tests
go test ./...
```

### Running Locally

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

### Configuration Hot-Reload

When running with a config file (`-config config.yaml`), configuration changes made via the web GUI or API are automatically persisted to the config file and survive restarts.

**Hot-Reloadable Settings** (no restart required):
- Cache TTL settings (min_ttl, max_ttl, negative_ttl)
- Prefetch configuration (enabled, threshold_hits, threshold_ttl_percent)
- Resolver coalescing settings
- Parallel resolver settings (num_parallel, fallback_to_recursive)
- Upstream servers
- Logging settings

**Settings Requiring Restart** (automatic graceful restart):
- Resolver mode (forwarding, parallel, recursive)
- Listen address
- Number of workers
- Cache size/shards

When a restart-requiring setting is changed via the GUI, the server automatically performs a graceful restart to apply the new configuration.

### Kubernetes Configuration (CRD)

For Kubernetes deployments, use the `DNSConfig` Custom Resource:

```yaml
apiVersion: dns.piwi3910.io/v1alpha1
kind: DNSConfig
metadata:
  name: dns-server-config
spec:
  server:
    listenAddress: "0.0.0.0:53"
    numWorkers: 10
  cache:
    prefetch:
      enabled: true
      thresholdHits: 100
  resolver:
    mode: parallel
    upstreams:
      - "8.8.8.8:53"
      - "1.1.1.1:53"
```

Apply the CRD first:
```bash
kubectl apply -f deploy/kubernetes/crd.yaml
kubectl apply -f deploy/kubernetes/example-dnsconfig.yaml
```

## Project Structure

```
dns-go/
├── cmd/
│   ├── dns-server/        # Standalone server binary
│   ├── dns-control/       # Control plane binary
│   ├── dns-worker/        # Worker binary
│   └── dns-test-client/   # Test client utility
├── configs/               # Configuration files
│   └── config.yaml        # Example configuration
├── deploy/
│   ├── docker/            # Docker deployment
│   │   ├── Dockerfile*    # Container images
│   │   ├── docker-compose.yaml
│   │   └── config/        # Pre-configured YAML files
│   ├── kubernetes/        # Raw K8s manifests
│   ├── helm/dns-go/       # Helm chart
│   └── operator/          # Kubernetes Operator
│       ├── api/v1alpha1/  # CRD types
│       ├── controllers/   # Reconciliation logic
│       └── config/        # RBAC, CRDs, samples
├── pkg/
│   ├── api/              # REST API and web server
│   ├── bridge/           # Abstraction layer (local/remote)
│   ├── cache/            # Three-level caching system
│   ├── config/           # Configuration loading
│   ├── control/          # Control plane components
│   │   ├── registry/     # Worker registry
│   │   ├── sync/         # Zone/config sync
│   │   └── stats/        # Stats aggregation
│   ├── io/               # Per-core I/O with SO_REUSEPORT
│   ├── proto/            # gRPC protobuf definitions
│   ├── resolver/         # Recursive/forward resolver
│   ├── server/           # DNS request handler
│   ├── worker/           # Worker components
│   │   ├── client/       # gRPC client
│   │   └── sync/         # Zone handler
│   └── zone/             # Zone file management
└── web/
    └── frontend/         # React + TypeScript frontend
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

## Deployment Guide

### Docker Standalone

The simplest deployment - single container with everything built-in:

```bash
cd deploy/docker
docker-compose --profile standalone up -d

# Test it
dig @127.0.0.1 google.com

# Access web GUI at http://localhost:8080
```

### Docker Distributed

For high availability with automatic worker scaling:

```bash
cd deploy/docker
docker-compose --profile distributed up -d

# Scale workers based on load
docker-compose --profile distributed up -d --scale dns-worker=5

# Control plane GUI at http://localhost:8080
```

### Kubernetes with Helm

```bash
# Install with default values
helm install dns-go deploy/helm/dns-go/ -n dns-go --create-namespace

# Install with custom values
helm install dns-go deploy/helm/dns-go/ -n dns-go --create-namespace \
  --set workers.replicas=5 \
  --set workers.autoscaling.enabled=true \
  --set workers.autoscaling.maxReplicas=20

# Upgrade
helm upgrade dns-go deploy/helm/dns-go/ -n dns-go
```

### Kubernetes with Operator

For GitOps-style declarative management:

```bash
# Install CRDs and operator
cd deploy/operator
make install
make deploy

# Create a DNS cluster
kubectl apply -f - <<EOF
apiVersion: dns.dns-go.io/v1alpha1
kind: DNSCluster
metadata:
  name: production-dns
spec:
  controlPlane:
    replicas: 1
  workers:
    replicas: 3
    minReplicas: 2
    maxReplicas: 10
  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
EOF
```

### Multi-Cluster Deployment

Deploy DNS workers across multiple Kubernetes clusters with centralized management:

```bash
# Step 1: Register remote clusters
# Create a secret with kubeconfig for each cluster
kubectl create secret generic cluster-us-west-kubeconfig \
  --from-file=kubeconfig=/path/to/us-west-kubeconfig.yaml

# Step 2: Create ClusterRegistration resources
kubectl apply -f - <<EOF
apiVersion: dns.dns-go.io/v1alpha1
kind: ClusterRegistration
metadata:
  name: us-west-1
spec:
  displayName: "US West Production"
  region: us-west
  zone: us-west-1a
  kubeconfigSecret:
    name: cluster-us-west-kubeconfig
    namespace: dns-go
    key: kubeconfig
  capacity:
    maxWorkers: 20
EOF

# Step 3: Create multi-cluster DNSCluster
kubectl apply -f - <<EOF
apiVersion: dns.dns-go.io/v1alpha1
kind: DNSCluster
metadata:
  name: global-dns
spec:
  controlPlane:
    replicas: 1
  workers:
    replicas: 10
  multiCluster:
    enabled: true
    workerPlacements:
      - clusterRef: us-west-1
        weight: 50
      - clusterRef: eu-central-1
        weight: 30
      - clusterRef: ap-southeast-1
        weight: 20
    globalDistribution:
      strategy: Weighted
      failoverPolicy:
        enabled: true
        failoverThreshold: "5m"
        rebalanceOnRecovery: true
  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
EOF
```

**Distribution Strategies:**
- `Balanced`: Equal workers per cluster
- `Weighted`: Distribute by cluster weight
- `Geographic`: Optimize for geographic coverage
- `FollowLoad`: Distribute based on current load

**Features:**
- Automatic failover when clusters become unhealthy
- Worker rebalancing on cluster recovery
- Per-cluster status tracking
- Region/zone-aware placement with anti-affinity

### Distributed Cache Deployment

**Simple Single-Site (Local Cache Only)**
```bash
# Docker Compose - local caching per worker
cd deploy/docker
docker-compose --profile distributed up -d
```

**Single-Site with Redis (Hybrid Cache)**
```bash
# Docker Compose with Redis for cache persistence
cd deploy/docker
docker-compose --profile hybrid up -d
```

**Multi-Site HA with Redis Sentinel**
```bash
# Kubernetes with HA Redis
kubectl apply -f - <<EOF
apiVersion: dns.dns-go.io/v1alpha1
kind: DNSCluster
metadata:
  name: dns-ha
spec:
  workers:
    replicas: 6
  cache:
    mode: hybrid
    sharedCache:
      enabled: true
      type: redis-sentinel
      redisSentinel:
        masterName: dns-cache
        addresses:
          - "redis-sentinel-0:26379"
          - "redis-sentinel-1:26379"
          - "redis-sentinel-2:26379"
    invalidation:
      strategy: pubsub
  highAvailability:
    enabled: true
    quorum:
      type: WorkerWitness
      minimumQuorum: 3
EOF
```

See [Cache Architecture Documentation](docs/architecture/cache-architecture.md) for complete configuration guides.

### High Availability Control Plane

Deploy the control plane in HA mode with split-brain prevention using workers as witness nodes:

```bash
kubectl apply -f - <<EOF
apiVersion: dns.dns-go.io/v1alpha1
kind: DNSCluster
metadata:
  name: ha-dns
spec:
  controlPlane:
    replicas: 2

  workers:
    replicas: 6
    minReplicas: 4

  multiCluster:
    enabled: true
    workerPlacements:
      - clusterRef: site-a
        minReplicas: 2
      - clusterRef: site-b
        minReplicas: 2

  highAvailability:
    enabled: true
    mode: ActivePassive
    controlPlanePlacements:
      - clusterRef: site-a
        priority: 1
        preferredLeader: true
      - clusterRef: site-b
        priority: 2
    quorum:
      type: WorkerWitness
      minimumQuorum: 3
      fencingEnabled: true
      gracePeriod: "30s"
      workerWitness:
        # Require workers from BOTH sites to prevent split-brain
        minClustersRequired: 2
        minWorkersPerCluster: 2

  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
EOF
```

**HA Modes:**
- `ActivePassive`: One leader accepts writes, others on standby
- `ActiveActive`: All instances accept reads, only leader accepts writes

**Quorum Types:**
- `WorkerWitness`: Workers vote for reachable control plane (ideal for 2-site deployments)
- `Majority`: Traditional majority quorum (requires 3+ control planes)
- `ExternalWitness`: Use external service (etcd, Consul) as witness

**Split-Brain Prevention:**
In a 2-site deployment, workers act as witness nodes. When network partitions:
- Each control plane only has quorum if workers from BOTH sites can reach it
- This prevents both sides from becoming active simultaneously
- The side that loses connectivity to workers will fence itself (stop accepting writes)

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
