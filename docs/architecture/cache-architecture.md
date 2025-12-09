# DNS-GO Distributed Cache Architecture

This document describes the caching architecture in DNS-GO, including deployment options for standalone, distributed, and multi-cluster environments.

## Table of Contents

1. [Overview](#overview)
2. [Cache Layers](#cache-layers)
3. [Deployment Modes](#deployment-modes)
4. [Single-Site Deployment](#single-site-deployment)
5. [Multi-Site Deployment with HA Redis](#multi-site-deployment-with-ha-redis)
6. [Configuration Reference](#configuration-reference)
7. [Cache Management API](#cache-management-api)

---

## Overview

DNS-GO implements a sophisticated two-level caching strategy inspired by Unbound's architecture, designed to achieve 95%+ cache hit rates while supporting horizontal scaling across multiple workers and clusters.

### Cache Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DNS Queries                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Load Balancer / DNS                                 │
│                    (Round Robin / Geographic / Anycast)                      │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                │                │
                    ▼                ▼                ▼
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│     Worker 1        │  │     Worker 2        │  │     Worker N        │
│  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │
│  │ L1: Message   │  │  │  │ L1: Message   │  │  │  │ L1: Message   │  │
│  │    Cache      │  │  │  │    Cache      │  │  │  │    Cache      │  │
│  │ (Local/Fast)  │  │  │  │ (Local/Fast)  │  │  │  │ (Local/Fast)  │  │
│  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │
│         │           │  │         │           │  │         │           │
│         ▼ Miss      │  │         ▼ Miss      │  │         ▼ Miss      │
│  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │
│  │ L2: RRset     │  │  │  │ L2: RRset     │  │  │  │ L2: RRset     │  │
│  │    Cache      │  │  │  │    Cache      │  │  │  │    Cache      │  │
│  │ (Local/Shared)│  │  │  │ (Local/Shared)│  │  │  │ (Local/Shared)│  │
│  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │ (Optional: Shared L2)
                                   ▼
              ┌────────────────────────────────────────────┐
              │         Shared Cache Layer (Optional)       │
              │  ┌──────────────────────────────────────┐  │
              │  │     Redis Cluster / Redis Sentinel    │  │
              │  │         (HA + Replication)            │  │
              │  └──────────────────────────────────────┘  │
              └────────────────────────────────────────────┘
```

---

## Cache Layers

### L1: Message Cache (Local, Per-Worker)

The L1 cache stores complete DNS response messages, enabling zero-copy serving for exact query matches.

**Characteristics:**
- **Scope**: Local to each worker (not shared)
- **Content**: Complete DNS response bytes
- **Key**: Hash(query_name + query_type + flags)
- **Performance**: <100µs response time
- **Default Size**: 64MB (configurable)
- **Shards**: NumCPU * 4 (power of 2)
- **Target Hit Rate**: 80% of all queries

**Why Local?**
- Zero network latency for cache hits
- No shared state contention between workers
- Works perfectly for anycast/geographic load balancing where the same clients hit the same workers

### L2: RRset Cache (Local or Shared)

The L2 cache stores individual resource record sets, allowing flexible response assembly for query variations.

**Characteristics:**
- **Scope**: Local (standalone) or Shared (distributed with Redis)
- **Content**: Individual resource record sets
- **Key**: Hash(domain + record_type)
- **Performance**: <1ms (local), <5ms (Redis)
- **Default Size**: 128MB (local) or configurable (Redis)
- **Shards**: NumCPU * 8 (local)
- **Target Hit Rate**: 15% of remaining queries

**Why Shared (Optional)?**
- New workers inherit cache warmth immediately
- Cache survives worker restarts
- Better utilization in multi-cluster deployments
- Enables cache synchronization across sites

### L3: Infrastructure Cache (Local)

Stores metadata about upstream servers for intelligent selection.

**Content:**
- RTT measurements per upstream server
- Failure counts and success rates
- Last response time
- Server health status

---

## Deployment Modes

DNS-GO supports three cache deployment modes:

| Mode | L1 Cache | L2 Cache | Use Case |
|------|----------|----------|----------|
| **Standalone** | Local | Local | Single server, development, simple deployments |
| **Local-Only** | Local | Local | Multiple workers, no shared state needed |
| **Hybrid** | Local | Shared (Redis) | Multi-worker/multi-cluster with cache sharing |

### Mode Selection Guide

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Which Cache Mode to Use?                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                            Single Server?
                                    │
                    ┌───────────────┴───────────────┐
                   Yes                              No
                    │                               │
                    ▼                               │
              STANDALONE                     Multiple Workers?
                                                    │
                                    ┌───────────────┴───────────────┐
                                   Yes                              No
                                    │                               │
                                    │                               ▼
                        Need Cache Sharing?                    STANDALONE
                                    │
                    ┌───────────────┴───────────────┐
                   Yes                              No
                    │                               │
                    ▼                               ▼
                 HYBRID                        LOCAL-ONLY
           (with Redis)
```

---

## Single-Site Deployment

### Option 1: Standalone (Single Container)

The simplest deployment for development, testing, or low-traffic environments.

**Docker Compose:**
```yaml
version: '3.8'
services:
  dns:
    image: ghcr.io/piwi3910/dns-go:latest
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/dns-go/config.yaml:ro
```

**Configuration (config.yaml):**
```yaml
server:
  listen_address: "0.0.0.0:53"
  num_workers: 4

cache:
  mode: standalone  # Local L1 + Local L2
  message_cache:
    max_size_mb: 64
    num_shards: 32
  rrset_cache:
    max_size_mb: 128
    num_shards: 64
  prefetch:
    enabled: true
    threshold_hits: 100

api:
  enabled: true
  listen_address: ":8080"
```

### Option 2: Distributed (Multiple Workers, Local Cache)

For horizontal scaling with independent caches per worker.

**Docker Compose:**
```yaml
version: '3.8'
services:
  control:
    image: ghcr.io/piwi3910/dns-go-control:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./control-config.yaml:/etc/dns-go/config.yaml:ro

  worker:
    image: ghcr.io/piwi3910/dns-go-worker:latest
    ports:
      - "53/udp"
    environment:
      - CONTROL_PLANE_ADDRESS=control:9090
    deploy:
      replicas: 3
```

**Control Plane Configuration:**
```yaml
control:
  grpc_address: ":9090"
  heartbeat_timeout: 30s

cache:
  mode: local-only  # Each worker has independent L1+L2
  message_cache:
    max_size_mb: 64
  rrset_cache:
    max_size_mb: 128

api:
  enabled: true
  listen_address: ":8080"
```

### Option 3: Distributed with Shared Redis Cache

For cache sharing and persistence across workers.

**Docker Compose:**
```yaml
version: '3.8'
services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 3

  control:
    image: ghcr.io/piwi3910/dns-go-control:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./control-config.yaml:/etc/dns-go/config.yaml:ro
    depends_on:
      redis:
        condition: service_healthy

  worker:
    image: ghcr.io/piwi3910/dns-go-worker:latest
    ports:
      - "53/udp"
    environment:
      - CONTROL_PLANE_ADDRESS=control:9090
    depends_on:
      - control
    deploy:
      replicas: 3

volumes:
  redis-data:
```

**Control Plane Configuration:**
```yaml
control:
  grpc_address: ":9090"

cache:
  mode: hybrid  # Local L1 + Shared L2 (Redis)
  message_cache:
    max_size_mb: 64
  shared_cache:
    enabled: true
    type: redis
    address: "redis:6379"
    database: 0
    key_prefix: "dns:"
    ttl_multiplier: 1.5  # Store in Redis 1.5x DNS TTL

api:
  enabled: true
  listen_address: ":8080"
```

---

## Multi-Site Deployment with HA Redis

For production multi-cluster deployments requiring cache replication across sites.

### Architecture: Redis Sentinel (2-Site HA)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Site A (Primary)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Control Plane (Active)                                              │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                             │    │
│  │  │Worker 1 │  │Worker 2 │  │Worker 3 │                             │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘                             │    │
│  │       │            │            │                                   │    │
│  │       └────────────┼────────────┘                                   │    │
│  │                    │                                                │    │
│  │                    ▼                                                │    │
│  │  ┌─────────────────────────────────────────────────────────────┐   │    │
│  │  │                    Redis Master                              │   │    │
│  │  │                    (6379)                                    │   │    │
│  │  └─────────────────────────────────────────────────────────────┘   │    │
│  │            │                                                        │    │
│  │  ┌─────────┴─────────┐                                             │    │
│  │  │ Sentinel 1 (26379)│                                             │    │
│  │  └───────────────────┘                                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    Replication (Async) │
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Site B (Secondary)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Control Plane (Standby)                                            │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                             │    │
│  │  │Worker 4 │  │Worker 5 │  │Worker 6 │                             │    │
│  │  └────┬────┘  └────┬────┘  └────┬────┘                             │    │
│  │       │            │            │                                   │    │
│  │       └────────────┼────────────┘                                   │    │
│  │                    │                                                │    │
│  │                    ▼                                                │    │
│  │  ┌─────────────────────────────────────────────────────────────┐   │    │
│  │  │                  Redis Replica (Read)                        │   │    │
│  │  │                    (6379)                                    │   │    │
│  │  └─────────────────────────────────────────────────────────────┘   │    │
│  │            │                                                        │    │
│  │  ┌─────────┴─────────┐                                             │    │
│  │  │ Sentinel 2 (26379)│                                             │    │
│  │  └───────────────────┘                                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Docker Compose: Multi-Site with Redis Sentinel

**Site A (docker-compose.site-a.yaml):**
```yaml
version: '3.8'
services:
  redis-master:
    image: redis:7-alpine
    command: >
      redis-server
      --appendonly yes
      --replica-announce-ip ${SITE_A_IP}
      --replica-announce-port 6379
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - dns-network

  redis-sentinel:
    image: redis:7-alpine
    command: >
      redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel-a.conf:/etc/redis/sentinel.conf
    ports:
      - "26379:26379"
    depends_on:
      - redis-master
    networks:
      - dns-network

  control:
    image: ghcr.io/piwi3910/dns-go-control:latest
    environment:
      - SITE_ID=site-a
      - HA_PRIORITY=1
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./control-ha.yaml:/etc/dns-go/config.yaml:ro
    networks:
      - dns-network

  worker:
    image: ghcr.io/piwi3910/dns-go-worker:latest
    environment:
      - CONTROL_PLANE_ADDRESS=control:9090
    ports:
      - "53/udp"
    deploy:
      replicas: 3
    networks:
      - dns-network

networks:
  dns-network:
    driver: bridge

volumes:
  redis-data:
```

**sentinel-a.conf:**
```
port 26379
sentinel monitor dns-cache ${SITE_A_IP} 6379 2
sentinel down-after-milliseconds dns-cache 5000
sentinel failover-timeout dns-cache 60000
sentinel parallel-syncs dns-cache 1
sentinel announce-ip ${SITE_A_IP}
sentinel announce-port 26379
```

**Site B (docker-compose.site-b.yaml):**
```yaml
version: '3.8'
services:
  redis-replica:
    image: redis:7-alpine
    command: >
      redis-server
      --appendonly yes
      --replicaof ${SITE_A_IP} 6379
      --replica-announce-ip ${SITE_B_IP}
      --replica-announce-port 6379
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - dns-network

  redis-sentinel:
    image: redis:7-alpine
    command: >
      redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel-b.conf:/etc/redis/sentinel.conf
    ports:
      - "26379:26379"
    depends_on:
      - redis-replica
    networks:
      - dns-network

  control:
    image: ghcr.io/piwi3910/dns-go-control:latest
    environment:
      - SITE_ID=site-b
      - HA_PRIORITY=2
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./control-ha.yaml:/etc/dns-go/config.yaml:ro
    networks:
      - dns-network

  worker:
    image: ghcr.io/piwi3910/dns-go-worker:latest
    environment:
      - CONTROL_PLANE_ADDRESS=control:9090
    ports:
      - "53/udp"
    deploy:
      replicas: 3
    networks:
      - dns-network

networks:
  dns-network:
    driver: bridge

volumes:
  redis-data:
```

**control-ha.yaml (shared between sites):**
```yaml
control:
  grpc_address: ":9090"

cache:
  mode: hybrid
  message_cache:
    max_size_mb: 64
  shared_cache:
    enabled: true
    type: redis-sentinel
    sentinel:
      master_name: dns-cache
      addresses:
        - "${SITE_A_IP}:26379"
        - "${SITE_B_IP}:26379"
    database: 0
    key_prefix: "dns:"
    read_preference: replica  # Read from local replica when possible

high_availability:
  enabled: true
  mode: active_passive
  quorum:
    type: worker_witness
    minimum: 3
    min_clusters_required: 2

api:
  enabled: true
  listen_address: ":8080"
```

### Kubernetes: Multi-Cluster with Redis Cluster

For Kubernetes deployments, use Redis Cluster for automatic sharding and HA.

**Redis Cluster Helm Values (redis-values.yaml):**
```yaml
architecture: cluster
cluster:
  nodes: 6
  replicas: 1
auth:
  enabled: true
  existingSecret: redis-password

master:
  persistence:
    enabled: true
    size: 10Gi
  resources:
    requests:
      memory: 256Mi
      cpu: 100m
    limits:
      memory: 1Gi
      cpu: 500m

replica:
  persistence:
    enabled: true
    size: 10Gi

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

**DNSCluster with Redis Cache (Operator):**
```yaml
apiVersion: dns.dns-go.io/v1alpha1
kind: DNSCluster
metadata:
  name: ha-dns-redis
spec:
  controlPlane:
    replicas: 2

  workers:
    replicas: 6
    minReplicas: 4
    maxReplicas: 20

  cache:
    mode: hybrid
    messageCache:
      maxSizeMB: 64
      numShards: 32
    sharedCache:
      enabled: true
      type: redis-cluster
      redisCluster:
        addresses:
          - "redis-cluster-0.redis-cluster-headless:6379"
          - "redis-cluster-1.redis-cluster-headless:6379"
          - "redis-cluster-2.redis-cluster-headless:6379"
        authSecret:
          name: redis-password
          key: password
        database: 0
        keyPrefix: "dns:"
        maxRetries: 3
        minRetryBackoff: "8ms"
        maxRetryBackoff: "512ms"
        poolSize: 10
        minIdleConns: 5
        readPreference: replicaPreferred

  multiCluster:
    enabled: true
    workerPlacements:
      - clusterRef: site-a
        weight: 50
        minReplicas: 2
      - clusterRef: site-b
        weight: 50
        minReplicas: 2

  highAvailability:
    enabled: true
    mode: ActivePassive
    controlPlanePlacements:
      - clusterRef: site-a
        priority: 1
      - clusterRef: site-b
        priority: 2
    quorum:
      type: WorkerWitness
      minimumQuorum: 3
      minClustersRequired: 2

  upstreams:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
```

---

## Configuration Reference

### Cache Configuration Options

```yaml
cache:
  # Mode: standalone | local-only | hybrid
  mode: hybrid

  # L1: Message Cache (always local)
  message_cache:
    max_size_mb: 64        # Maximum size in MB
    num_shards: 32         # Number of shards (power of 2)
    min_ttl: 60            # Minimum TTL in seconds
    max_ttl: 86400         # Maximum TTL in seconds

  # L2: RRset Cache (local in standalone/local-only, shared in hybrid)
  rrset_cache:
    max_size_mb: 128       # Maximum size in MB (local)
    num_shards: 64         # Number of shards (power of 2)

  # Shared Cache Configuration (only used in hybrid mode)
  shared_cache:
    enabled: true
    type: redis            # redis | redis-sentinel | redis-cluster

    # Single Redis
    address: "redis:6379"

    # Redis Sentinel
    sentinel:
      master_name: dns-cache
      addresses:
        - "sentinel-1:26379"
        - "sentinel-2:26379"
        - "sentinel-3:26379"

    # Redis Cluster
    cluster_addresses:
      - "redis-0:6379"
      - "redis-1:6379"
      - "redis-2:6379"

    # Common options
    database: 0
    password: ""                  # Or use password_secret
    password_secret:
      name: redis-credentials
      key: password
    key_prefix: "dns:"
    ttl_multiplier: 1.5          # Store in Redis for 1.5x DNS TTL

    # Connection pool
    pool_size: 10
    min_idle_conns: 5
    max_retries: 3
    read_timeout: "500ms"
    write_timeout: "500ms"

    # Read preference (sentinel/cluster only)
    read_preference: replicaPreferred  # master | replica | replicaPreferred

  # Prefetch Configuration
  prefetch:
    enabled: true
    threshold_hits: 100          # Prefetch if hit count > threshold
    threshold_ttl_pct: 10        # Prefetch when TTL < 10% remaining

  # Negative Caching
  negative_cache:
    enabled: true
    ttl: 3600                    # Default negative TTL
```

### Cache Invalidation

DNS-GO supports several cache invalidation strategies:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **local-only** | Each worker manages its own cache | Standalone/local-only mode |
| **pubsub** | Redis Pub/Sub for real-time invalidation | Hybrid mode with Redis |
| **broadcast** | gRPC broadcast to all workers | Distributed without shared cache |

**Configuration:**
```yaml
cache:
  invalidation:
    strategy: pubsub           # local-only | pubsub | broadcast
    pubsub:
      channel: "dns:invalidate"
      batch_size: 100
      batch_delay: "100ms"
```

---

## Cache Management API

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cache/distributed` | Get cache stats across all workers |
| DELETE | `/api/cache/distributed` | Clear cache (supports targeting) |

### Get Distributed Cache Stats

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/cache/distributed
```

**Response:**
```json
{
  "mode": "hybrid",
  "workers": [
    {
      "workerId": "worker-1",
      "clusterName": "site-a",
      "address": "10.0.0.10:53",
      "status": "healthy",
      "messageCache": {
        "hits": 150000,
        "misses": 5000,
        "evicts": 100,
        "hit_rate": 96.77,
        "size_bytes": 52428800,
        "max_size_bytes": 67108864,
        "num_shards": 32
      },
      "rrsetCache": {
        "hits": 10000,
        "misses": 5000,
        "evicts": 50,
        "hit_rate": 66.67,
        "size_bytes": 104857600,
        "max_size_bytes": 134217728,
        "num_shards": 64
      },
      "lastUpdated": "2024-01-15T10:30:00Z"
    }
  ],
  "sharedCache": {
    "type": "redis-cluster",
    "address": "redis-cluster:6379",
    "status": "connected",
    "stats": {
      "hits": 500000,
      "misses": 25000,
      "hit_rate": 95.24,
      "size_bytes": 268435456
    },
    "lastSync": "2024-01-15T10:30:00Z"
  },
  "aggregated": {
    "totalHits": 660000,
    "totalMisses": 35000,
    "averageHitRate": 94.96,
    "totalSizeBytes": 425721856,
    "workerCount": 6
  },
  "architecture": {
    "description": "Hybrid mode: Local L1 message cache + Shared L2 Redis cluster",
    "l1Type": "local-message-cache",
    "l2Type": "redis-cluster",
    "replication": "cluster",
    "invalidation": "pubsub",
    "features": ["two-level-cache", "negative-caching", "prefetch", "distributed-invalidation"]
  }
}
```

### Clear Cache

**Clear all caches on all workers:**
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "all", "cacheType": "all"}' \
  http://localhost:8080/api/cache/distributed
```

**Clear message cache on specific workers:**
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "worker", "workerIds": ["worker-1", "worker-2"], "cacheType": "message"}' \
  http://localhost:8080/api/cache/distributed
```

**Clear shared cache only:**
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "shared", "cacheType": "all"}' \
  http://localhost:8080/api/cache/distributed
```

**Response:**
```json
{
  "success": true,
  "clearedCount": 6,
  "results": [
    {"workerId": "worker-1", "success": true, "cleared": ["message", "rrset"]},
    {"workerId": "worker-2", "success": true, "cleared": ["message", "rrset"]}
  ],
  "sharedCleared": true
}
```

---

## Best Practices

### Sizing Guidelines

| Deployment Size | Message Cache | RRset Cache | Redis Memory |
|-----------------|---------------|-------------|--------------|
| Small (<10K QPS) | 32MB | 64MB | N/A or 256MB |
| Medium (10K-100K QPS) | 64MB | 128MB | 512MB-1GB |
| Large (100K-500K QPS) | 128MB | 256MB | 2GB-4GB |
| Enterprise (500K+ QPS) | 256MB | 512MB | 8GB+ (cluster) |

### Redis Cluster Sizing

For multi-cluster deployments with Redis Cluster:

- **Minimum nodes**: 6 (3 masters + 3 replicas)
- **Memory per node**: 2-4GB for 500K+ QPS
- **Network**: Low-latency links between clusters (<50ms RTT)
- **Persistence**: Enable AOF with fsync every second

### Monitoring

Key metrics to monitor:

1. **Cache Hit Rates**: L1 should be >80%, combined >95%
2. **Redis Latency**: p99 should be <5ms
3. **Memory Usage**: Alert at 80% of configured limits
4. **Eviction Rate**: High evictions indicate undersized cache
5. **Replication Lag**: For Redis replicas, <100ms is healthy

---

## Troubleshooting

### Common Issues

**1. Low Cache Hit Rate**

Possible causes:
- Cache too small (increase `max_size_mb`)
- High cardinality queries (many unique domains)
- TTL too short (check `min_ttl` setting)

**2. Redis Connection Failures**

Check:
- Redis server is running and healthy
- Network connectivity between workers and Redis
- Authentication credentials are correct
- Connection pool not exhausted (increase `pool_size`)

**3. Cache Inconsistency Across Workers**

Ensure:
- All workers connect to the same Redis instance/cluster
- Pub/Sub invalidation is enabled and working
- Clock synchronization across nodes (NTP)

**4. Memory Pressure**

Solutions:
- Reduce cache sizes
- Enable more aggressive eviction
- Increase sharding to reduce lock contention
