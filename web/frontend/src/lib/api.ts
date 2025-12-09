const API_BASE = '/api'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = 'ApiError'
  }
}

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    throw new ApiError(response.status, errorData.error || response.statusText)
  }

  return response.json()
}

// Auth API
export const authApi = {
  login: (username: string, password: string) =>
    fetchApi<{ message: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    fetchApi<{ message: string }>('/auth/logout', {
      method: 'POST',
    }),

  me: () => fetchApi<{ username: string; authenticated: boolean }>('/auth/me'),
}

// Stats API
export interface Stats {
  server: {
    version: string
    uptime_seconds: number
    go_version: string
    num_cpu: number
    num_goroutines: number
    memory_mb: number
  }
  cache: {
    message_cache: {
      hits: number
      misses: number
      evicts: number
      hit_rate: number
      size_bytes: number
      max_size_bytes: number
      num_shards: number
    }
    rrset_cache: {
      hits: number
      misses: number
      evicts: number
      hit_rate: number
      size_bytes: number
      max_size_bytes: number
      num_shards: number
    }
  }
  resolver: {
    in_flight_queries: number
    mode: string
  }
  zones: {
    count: number
    total_records: number
  }
}

export const statsApi = {
  get: () => fetchApi<Stats>('/stats'),
}

// Upstreams API
export interface UpstreamStats {
  address: string
  rtt_ms: number
  queries: number
  failures: number
  failure_rate: number
  healthy: boolean
}

export interface UpstreamsResponse {
  upstreams: UpstreamStats[]
  mode: string
}

export const upstreamsApi = {
  list: () => fetchApi<UpstreamsResponse>('/upstreams'),

  update: (upstreams: string[]) =>
    fetchApi<{ message: string; upstreams: string[] }>('/upstreams', {
      method: 'PUT',
      body: JSON.stringify({ upstreams }),
    }),
}

// Zones API
export interface ZoneInfo {
  origin: string
  record_count: number
  transfer_acl: string[]
  update_acl: string[]
}

export interface ZoneDetail {
  origin: string
  record_count: number
  records: string[]
  transfer_acl: string[]
  update_acl: string[]
}

export const zonesApi = {
  list: () => fetchApi<{ zones: ZoneInfo[] }>('/zones'),

  get: (origin: string) => fetchApi<ZoneDetail>(`/zones/${encodeURIComponent(origin)}`),

  create: (data: { origin: string; zone_file_content?: string; transfer_acl?: string[]; update_acl?: string[] }) =>
    fetchApi<{ message: string; origin: string }>('/zones', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  delete: (origin: string) =>
    fetchApi<{ message: string }>(`/zones/${encodeURIComponent(origin)}`, {
      method: 'DELETE',
    }),
}

// Cache API
export interface CacheStats {
  message_cache: {
    entries: number
    hits: number
    misses: number
    hit_rate: number
    size_bytes: number
  }
  rrset_cache: {
    entries: number
    hits: number
    misses: number
    hit_rate: number
    size_bytes: number
  }
  infra_cache: {
    entries: number
  }
}

export const cacheApi = {
  stats: () => fetchApi<CacheStats>('/cache'),

  clear: (cacheType: 'all' | 'message' | 'rrset' | 'infra') =>
    fetchApi<{ message: string; cache_type: string }>('/cache', {
      method: 'DELETE',
      body: JSON.stringify({ cache_type: cacheType }),
    }),
}

// Config API
export interface ServerConfig {
  server: {
    listen_address: string
    num_workers: number
    enable_tcp: boolean
    pprof_address: string
    graceful_shutdown_timeout_seconds: number
    stats_report_interval_seconds: number
  }
  cache: {
    message_cache: {
      max_size_mb: number
      num_shards: number
    }
    rrset_cache: {
      max_size_mb: number
      num_shards: number
    }
    prefetch: {
      enabled: boolean
      threshold_hits: number
      threshold_ttl_percent: number
    }
    min_ttl_seconds: number
    max_ttl_seconds: number
    negative_ttl_seconds: number
  }
  resolver: {
    mode: string
    upstreams: string[]
    root_hints_file: string
    max_recursion_depth: number
    query_timeout_seconds: number
    enable_coalescing: boolean
    parallel?: {
      num_parallel: number
      fallback_to_recursive: boolean
      success_rcodes: number[]
    }
  }
  logging: {
    level: string
    format: string
    enable_query_log: boolean
  }
  api: {
    enabled: boolean
    listen_address: string
    cors_origins: string[]
  }
}

export const configApi = {
  get: () => fetchApi<ServerConfig>('/config'),

  update: (updates: Partial<{
    cache: {
      prefetch?: { enabled?: boolean; threshold_hits?: number; threshold_ttl_percent?: number }
      min_ttl_seconds?: number
      max_ttl_seconds?: number
      negative_ttl_seconds?: number
    }
    resolver: {
      mode?: string
      upstreams?: string[]
      enable_coalescing?: boolean
      parallel?: { num_parallel?: number; fallback_to_recursive?: boolean; success_rcodes?: number[] }
    }
    logging: {
      level?: string
      format?: string
      enable_query_log?: boolean
    }
  }>) =>
    fetchApi<{ message: string }>('/config', {
      method: 'PUT',
      body: JSON.stringify(updates),
    }),
}

// Health API
export const healthApi = {
  check: () => fetchApi<{ status: string; timestamp: string }>('/health'),
}

// Clusters API (Multi-Cluster Support)
export interface ClusterInfo {
  name: string
  displayName: string
  region: string
  zone: string
  status: 'Ready' | 'NotReady' | 'Connecting' | 'Error'
  lastHeartbeat: string
  workerCount: number
  healthyWorkers: number
  labels: Record<string, string>
  capacity: {
    maxWorkers: number
    currentWorkers: number
    availableWorkers: number
  }
}

export interface ClusterWorker {
  id: string
  clusterName: string
  region: string
  zone: string
  status: 'Running' | 'Stopped' | 'Starting' | 'Error' | 'Unknown'
  address: string
  lastHeartbeat: string
  metrics: {
    qps: number
    cacheHitRate: number
    memoryMB: number
    cpuPercent: number
    uptime: number
  }
}

export interface ClustersResponse {
  clusters: ClusterInfo[]
  totalWorkers: number
  healthyWorkers: number
}

export interface WorkersResponse {
  workers: ClusterWorker[]
  totalCount: number
  byCluster: Record<string, number>
  byRegion: Record<string, number>
}

export const clustersApi = {
  list: () => fetchApi<ClustersResponse>('/clusters'),

  get: (name: string) => fetchApi<ClusterInfo>(`/clusters/${encodeURIComponent(name)}`),

  getWorkers: (clusterName?: string) => {
    const endpoint = clusterName
      ? `/workers?cluster=${encodeURIComponent(clusterName)}`
      : '/workers'
    return fetchApi<WorkersResponse>(endpoint)
  },
}

// HA (High Availability) API
export interface HAStatus {
  enabled: boolean
  mode: 'ActivePassive' | 'ActiveActive'
  leader: {
    isLeader: boolean
    leaderID: string
    leaderCluster: string
    leaseExpiry: string
    lastRenewal: string
  }
  quorum: {
    hasQuorum: boolean
    quorumType: 'WorkerWitness' | 'Majority' | 'ExternalWitness'
    votersTotal: number
    votersReachable: number
    clusterVotes: ClusterVote[]
    lastCheck: string
    quorumLostSince: string | null
  }
  fencing: {
    isFenced: boolean
    reason: string
    quorumLostAt: string | null
    gracePeriodEnd: string | null
  }
  controlPlanes: ControlPlaneInstance[]
}

export interface ClusterVote {
  clusterID: string
  workersTotal: number
  workersVoting: number
  lastHeartbeat: string
  voteValid: boolean
}

export interface ControlPlaneInstance {
  id: string
  clusterRef: string
  priority: number
  isLeader: boolean
  status: 'Active' | 'Standby' | 'Failed' | 'Unknown'
  lastHeartbeat: string
  address: string
}

export const haApi = {
  status: () => fetchApi<HAStatus>('/ha/status'),

  forceFailover: (targetID?: string) =>
    fetchApi<{ message: string; newLeader: string }>('/ha/failover', {
      method: 'POST',
      body: JSON.stringify({ targetID }),
    }),
}

// Distributed Cache API
export interface WorkerCacheInfo {
  workerId: string
  clusterName: string
  address: string
  status: string
  messageCache: {
    hits: number
    misses: number
    evicts: number
    hit_rate: number
    size_bytes: number
    max_size_bytes: number
    num_shards: number
  }
  rrsetCache: {
    hits: number
    misses: number
    evicts: number
    hit_rate: number
    size_bytes: number
    max_size_bytes: number
    num_shards: number
  }
  infraCache: {
    server_count: number
  }
  lastUpdated: string
}

export interface SharedCacheInfo {
  type: string
  address: string
  status: string
  stats: {
    hits: number
    misses: number
    evicts: number
    hit_rate: number
    size_bytes: number
    max_size_bytes: number
    num_shards: number
  }
  lastSync: string
}

export interface AggregatedCacheStats {
  totalHits: number
  totalMisses: number
  totalEvicts: number
  averageHitRate: number
  totalSizeBytes: number
  totalMaxSizeBytes: number
  workerCount: number
}

export interface CacheArchitectureInfo {
  description: string
  l1Type: string
  l2Type: string
  replication: string
  invalidation: string
  features: string[]
}

export interface DistributedCacheResponse {
  mode: string
  workers: WorkerCacheInfo[]
  sharedCache: SharedCacheInfo | null
  aggregated: AggregatedCacheStats
  architecture: CacheArchitectureInfo
}

export interface WorkerClearResult {
  workerId: string
  success: boolean
  cleared: string[]
  error?: string
}

export interface ClearDistributedCacheResponse {
  success: boolean
  clearedCount: number
  results: WorkerClearResult[]
  sharedCleared: boolean
}

export const distributedCacheApi = {
  get: () => fetchApi<DistributedCacheResponse>('/cache/distributed'),

  clear: (options: {
    target: 'all' | 'worker' | 'shared'
    workerIds?: string[]
    cacheType: 'all' | 'message' | 'rrset' | 'infra'
  }) =>
    fetchApi<ClearDistributedCacheResponse>('/cache/distributed', {
      method: 'DELETE',
      body: JSON.stringify(options),
    }),
}
