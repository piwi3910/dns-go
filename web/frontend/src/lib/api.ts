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
