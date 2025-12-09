// Package types contains request and response types for the API.
package types

import "time"

// APIResponse is the standard API response wrapper.
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	Uptime    string `json:"uptime"`
}

// StatsResponse contains server statistics.
type StatsResponse struct {
	Server   ServerStats   `json:"server"`
	Cache    CacheStats    `json:"cache"`
	Resolver ResolverStats `json:"resolver"`
	Zones    ZonesStats    `json:"zones"`
}

// ServerStats contains server-level statistics.
type ServerStats struct {
	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	GoVersion     string  `json:"go_version"`
	NumCPU        int     `json:"num_cpu"`
	NumGoroutines int     `json:"num_goroutines"`
	MemoryMB      float64 `json:"memory_mb"`
}

// CacheStats contains cache statistics.
type CacheStats struct {
	MessageCache CacheTypeStats `json:"message_cache"`
	RRsetCache   CacheTypeStats `json:"rrset_cache"`
}

// CacheTypeStats contains stats for a specific cache type.
type CacheTypeStats struct {
	Hits         int64   `json:"hits"`
	Misses       int64   `json:"misses"`
	Evicts       int64   `json:"evicts"`
	HitRate      float64 `json:"hit_rate"`
	SizeBytes    int64   `json:"size_bytes"`
	MaxSizeBytes int64   `json:"max_size_bytes"`
	NumShards    int     `json:"num_shards"`
}

// ResolverStats contains resolver statistics.
type ResolverStats struct {
	InFlightQueries int    `json:"in_flight_queries"`
	Mode            string `json:"mode"`
}

// ZonesStats contains zone statistics.
type ZonesStats struct {
	Count        int `json:"count"`
	TotalRecords int `json:"total_records"`
}

// UpstreamsResponse contains upstream server information.
type UpstreamsResponse struct {
	Upstreams []UpstreamInfo `json:"upstreams"`
}

// UpstreamInfo contains information about a single upstream server.
type UpstreamInfo struct {
	Address       string    `json:"address"`
	RTTMS         float64   `json:"rtt_ms"`
	Failures      int32     `json:"failures"`
	InFlight      int32     `json:"in_flight"`
	LastSuccess   time.Time `json:"last_success"`
	LastFailure   time.Time `json:"last_failure"`
	TotalQueries  int64     `json:"total_queries"`
	TotalFailures int64     `json:"total_failures"`
	FailureRate   float64   `json:"failure_rate"`
	Score         float64   `json:"score"`
	Healthy       bool      `json:"healthy"`
}

// ZonesResponse contains a list of zones.
type ZonesResponse struct {
	Zones []ZoneInfo `json:"zones"`
}

// ZoneInfo contains basic zone information.
type ZoneInfo struct {
	Origin       string    `json:"origin"`
	Serial       uint32    `json:"serial"`
	RecordCount  int       `json:"record_count"`
	LastModified time.Time `json:"last_modified"`
	HasSOA       bool      `json:"has_soa"`
}

// ZoneDetailResponse contains detailed zone information.
type ZoneDetailResponse struct {
	Origin      string       `json:"origin"`
	Serial      uint32       `json:"serial"`
	SOA         *SOAInfo     `json:"soa,omitempty"`
	Records     []RecordInfo `json:"records"`
	TransferACL []string     `json:"transfer_acl"`
	UpdateACL   []string     `json:"update_acl"`
}

// SOAInfo contains SOA record information.
type SOAInfo struct {
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	Minimum    uint32 `json:"minimum"`
}

// RecordInfo contains DNS record information.
type RecordInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// CacheResponse contains cache information.
type CacheResponse struct {
	MessageCache CacheTypeStats `json:"message_cache"`
	RRsetCache   CacheTypeStats `json:"rrset_cache"`
	InfraCache   InfraCacheInfo `json:"infra_cache"`
}

// InfraCacheInfo contains infrastructure cache information.
type InfraCacheInfo struct {
	ServerCount int `json:"server_count"`
}

// DistributedCacheResponse contains distributed cache information across workers.
type DistributedCacheResponse struct {
	Mode         string                    `json:"mode"`          // "standalone", "local-only", "hybrid"
	Workers      []WorkerCacheInfo         `json:"workers"`       // Per-worker cache stats
	SharedCache  *SharedCacheInfo          `json:"sharedCache"`   // Shared L2 cache (nil if not configured)
	Aggregated   AggregatedCacheStats      `json:"aggregated"`    // Totals across all workers
	Architecture CacheArchitectureInfo     `json:"architecture"`  // Description of cache setup
}

// WorkerCacheInfo contains cache information for a specific worker.
type WorkerCacheInfo struct {
	WorkerID      string         `json:"workerId"`
	ClusterName   string         `json:"clusterName"`
	Address       string         `json:"address"`
	Status        string         `json:"status"`
	MessageCache  CacheTypeStats `json:"messageCache"`
	RRsetCache    CacheTypeStats `json:"rrsetCache"`
	InfraCache    InfraCacheInfo `json:"infraCache"`
	LastUpdated   time.Time      `json:"lastUpdated"`
}

// SharedCacheInfo contains information about the shared L2 cache.
type SharedCacheInfo struct {
	Type          string         `json:"type"`          // "redis", "etcd", "none"
	Address       string         `json:"address"`       // Connection address
	Status        string         `json:"status"`        // "connected", "disconnected", "degraded"
	Stats         CacheTypeStats `json:"stats"`         // Shared cache stats
	LastSync      time.Time      `json:"lastSync"`      // Last sync time
}

// AggregatedCacheStats contains totals across all worker caches.
type AggregatedCacheStats struct {
	TotalHits         int64   `json:"totalHits"`
	TotalMisses       int64   `json:"totalMisses"`
	TotalEvicts       int64   `json:"totalEvicts"`
	AverageHitRate    float64 `json:"averageHitRate"`
	TotalSizeBytes    int64   `json:"totalSizeBytes"`
	TotalMaxSizeBytes int64   `json:"totalMaxSizeBytes"`
	WorkerCount       int     `json:"workerCount"`
}

// CacheArchitectureInfo describes the cache architecture.
type CacheArchitectureInfo struct {
	Description   string   `json:"description"`
	L1Type        string   `json:"l1Type"`        // "local-message-cache"
	L2Type        string   `json:"l2Type"`        // "local-rrset-cache", "shared-redis", "none"
	Replication   string   `json:"replication"`   // "none", "async", "sync"
	Invalidation  string   `json:"invalidation"`  // "local-only", "pubsub", "broadcast"
	Features      []string `json:"features"`      // ["prefetch", "negative-caching", etc.]
}

// ClearDistributedCacheRequest specifies which caches to clear.
type ClearDistributedCacheRequest struct {
	Target    string   `json:"target"`    // "all", "worker", "shared"
	WorkerIDs []string `json:"workerIds"` // Specific workers (if target="worker")
	CacheType string   `json:"cacheType"` // "all", "message", "rrset", "infra"
}

// ClearDistributedCacheResponse is returned after clearing distributed cache.
type ClearDistributedCacheResponse struct {
	Success       bool                    `json:"success"`
	ClearedCount  int                     `json:"clearedCount"`
	Results       []WorkerClearResult     `json:"results"`
	SharedCleared bool                    `json:"sharedCleared"`
}

// WorkerClearResult contains the result of clearing a worker's cache.
type WorkerClearResult struct {
	WorkerID string   `json:"workerId"`
	Success  bool     `json:"success"`
	Cleared  []string `json:"cleared"`
	Error    string   `json:"error,omitempty"`
}

// ConfigResponse contains the current configuration.
type ConfigResponse struct {
	Server   ServerConfigResponse   `json:"server"`
	Cache    CacheConfigResponse    `json:"cache"`
	Resolver ResolverConfigResponse `json:"resolver"`
	Logging  LoggingConfigResponse  `json:"logging"`
	API      APIConfigResponse      `json:"api"`
}

// ServerConfigResponse contains server configuration.
type ServerConfigResponse struct {
	ListenAddress               string `json:"listen_address"`
	NumWorkers                  int    `json:"num_workers"`
	EnableTCP                   bool   `json:"enable_tcp"`
	PprofAddress                string `json:"pprof_address"`
	GracefulShutdownTimeoutSecs int    `json:"graceful_shutdown_timeout_seconds"`
	StatsReportIntervalSecs     int    `json:"stats_report_interval_seconds"`
}

// CacheConfigResponse contains cache configuration.
type CacheConfigResponse struct {
	MessageCache MessageCacheConfigResponse `json:"message_cache"`
	RRsetCache   RRsetCacheConfigResponse   `json:"rrset_cache"`
	Prefetch     PrefetchConfigResponse     `json:"prefetch"`
	MinTTLSecs   int                        `json:"min_ttl_seconds"`
	MaxTTLSecs   int                        `json:"max_ttl_seconds"`
	NegTTLSecs   int                        `json:"negative_ttl_seconds"`
}

// MessageCacheConfigResponse contains message cache configuration.
type MessageCacheConfigResponse struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// RRsetCacheConfigResponse contains RRset cache configuration.
type RRsetCacheConfigResponse struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// PrefetchConfigResponse contains prefetch configuration.
type PrefetchConfigResponse struct {
	Enabled             bool    `json:"enabled"`
	ThresholdHits       int64   `json:"threshold_hits"`
	ThresholdTTLPercent float64 `json:"threshold_ttl_percent"`
}

// ResolverConfigResponse contains resolver configuration.
type ResolverConfigResponse struct {
	Mode              string                       `json:"mode"`
	Upstreams         []string                     `json:"upstreams"`
	RootHintsFile     string                       `json:"root_hints_file"`
	MaxRecursionDepth int                          `json:"max_recursion_depth"`
	QueryTimeoutSecs  int                          `json:"query_timeout_seconds"`
	EnableCoalescing  bool                         `json:"enable_coalescing"`
	Parallel          ParallelConfigResponse       `json:"parallel"`
}

// ParallelConfigResponse contains parallel forwarding configuration.
type ParallelConfigResponse struct {
	NumParallel         int   `json:"num_parallel"`
	FallbackToRecursive bool  `json:"fallback_to_recursive"`
	SuccessRcodes       []int `json:"success_rcodes"`
}

// LoggingConfigResponse contains logging configuration.
type LoggingConfigResponse struct {
	Level          string `json:"level"`
	Format         string `json:"format"`
	EnableQueryLog bool   `json:"enable_query_log"`
}

// APIConfigResponse contains API configuration.
type APIConfigResponse struct {
	Enabled       bool     `json:"enabled"`
	ListenAddress string   `json:"listen_address"`
	CORSOrigins   []string `json:"cors_origins"`
}

// AuthResponse is returned after successful login.
type AuthResponse struct {
	Success bool     `json:"success"`
	User    UserInfo `json:"user"`
}

// UserInfo contains user information.
type UserInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// MeResponse is returned by the /auth/me endpoint.
type MeResponse struct {
	Authenticated bool      `json:"authenticated"`
	User          *UserInfo `json:"user,omitempty"`
}

// ClearCacheResponse is returned after clearing cache.
type ClearCacheResponse struct {
	Success bool     `json:"success"`
	Cleared []string `json:"cleared"`
}

// UpdateUpstreamsResponse is returned after updating upstreams.
type UpdateUpstreamsResponse struct {
	Success   bool     `json:"success"`
	Upstreams []string `json:"upstreams"`
}

// CreateZoneResponse is returned after creating a zone.
type CreateZoneResponse struct {
	Success bool              `json:"success"`
	Zone    ZoneDetailResponse `json:"zone"`
}

// DeleteZoneResponse is returned after deleting a zone.
type DeleteZoneResponse struct {
	Success bool   `json:"success"`
	Origin  string `json:"origin"`
}

// UpdateConfigResponse is returned after updating configuration.
type UpdateConfigResponse struct {
	Success         bool           `json:"success"`
	Config          ConfigResponse `json:"config"`
	RequiresRestart bool           `json:"requires_restart"`
}

// ClustersResponse contains cluster information for multi-cluster deployments.
type ClustersResponse struct {
	Clusters       []ClusterInfo `json:"clusters"`
	TotalWorkers   int           `json:"totalWorkers"`
	HealthyWorkers int           `json:"healthyWorkers"`
}

// ClusterInfo contains information about a registered cluster.
type ClusterInfo struct {
	Name           string            `json:"name"`
	DisplayName    string            `json:"displayName"`
	Region         string            `json:"region"`
	Zone           string            `json:"zone"`
	Status         string            `json:"status"`
	LastHeartbeat  time.Time         `json:"lastHeartbeat"`
	WorkerCount    int               `json:"workerCount"`
	HealthyWorkers int               `json:"healthyWorkers"`
	Labels         map[string]string `json:"labels"`
	Capacity       ClusterCapacity   `json:"capacity"`
}

// ClusterCapacity contains capacity information for a cluster.
type ClusterCapacity struct {
	MaxWorkers       int `json:"maxWorkers"`
	CurrentWorkers   int `json:"currentWorkers"`
	AvailableWorkers int `json:"availableWorkers"`
}

// WorkersResponse contains worker information across clusters.
type WorkersResponse struct {
	Workers    []WorkerInfo       `json:"workers"`
	TotalCount int                `json:"totalCount"`
	ByCluster  map[string]int     `json:"byCluster"`
	ByRegion   map[string]int     `json:"byRegion"`
}

// WorkerInfo contains information about a DNS worker.
type WorkerInfo struct {
	ID            string        `json:"id"`
	ClusterName   string        `json:"clusterName"`
	Region        string        `json:"region"`
	Zone          string        `json:"zone"`
	Status        string        `json:"status"`
	Address       string        `json:"address"`
	LastHeartbeat time.Time     `json:"lastHeartbeat"`
	Metrics       WorkerMetrics `json:"metrics"`
}

// WorkerMetrics contains performance metrics for a worker.
type WorkerMetrics struct {
	QPS          float64 `json:"qps"`
	CacheHitRate float64 `json:"cacheHitRate"`
	MemoryMB     float64 `json:"memoryMB"`
	CPUPercent   float64 `json:"cpuPercent"`
	Uptime       float64 `json:"uptime"`
}

// HAStatusResponse contains high availability status information.
type HAStatusResponse struct {
	Enabled       bool                     `json:"enabled"`
	Mode          string                   `json:"mode"`
	Leader        HALeaderInfo             `json:"leader"`
	Quorum        HAQuorumInfo             `json:"quorum"`
	Fencing       HAFencingInfo            `json:"fencing"`
	ControlPlanes []ControlPlaneInstance   `json:"controlPlanes"`
}

// HALeaderInfo contains leader election information.
type HALeaderInfo struct {
	IsLeader      bool      `json:"isLeader"`
	LeaderID      string    `json:"leaderID"`
	LeaderCluster string    `json:"leaderCluster"`
	LeaseExpiry   time.Time `json:"leaseExpiry"`
	LastRenewal   time.Time `json:"lastRenewal"`
}

// HAQuorumInfo contains quorum status information.
type HAQuorumInfo struct {
	HasQuorum        bool              `json:"hasQuorum"`
	QuorumType       string            `json:"quorumType"`
	VotersTotal      int               `json:"votersTotal"`
	VotersReachable  int               `json:"votersReachable"`
	ClusterVotes     []ClusterVoteInfo `json:"clusterVotes"`
	LastCheck        time.Time         `json:"lastCheck"`
	QuorumLostSince  *time.Time        `json:"quorumLostSince"`
}

// ClusterVoteInfo contains voting information for a cluster.
type ClusterVoteInfo struct {
	ClusterID     string    `json:"clusterID"`
	WorkersTotal  int       `json:"workersTotal"`
	WorkersVoting int       `json:"workersVoting"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
	VoteValid     bool      `json:"voteValid"`
}

// HAFencingInfo contains fencing status information.
type HAFencingInfo struct {
	IsFenced       bool       `json:"isFenced"`
	Reason         string     `json:"reason"`
	QuorumLostAt   *time.Time `json:"quorumLostAt"`
	GracePeriodEnd *time.Time `json:"gracePeriodEnd"`
}

// ControlPlaneInstance contains information about a control plane instance.
type ControlPlaneInstance struct {
	ID            string    `json:"id"`
	ClusterRef    string    `json:"clusterRef"`
	Priority      int       `json:"priority"`
	IsLeader      bool      `json:"isLeader"`
	Status        string    `json:"status"`
	LastHeartbeat time.Time `json:"lastHeartbeat"`
	Address       string    `json:"address"`
}

// HAFailoverResponse is returned after triggering a failover.
type HAFailoverResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	NewLeader string `json:"newLeader"`
}
