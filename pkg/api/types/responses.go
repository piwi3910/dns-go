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
	Success        bool           `json:"success"`
	Config         ConfigResponse `json:"config"`
	RequiresRestart bool          `json:"requires_restart"`
}
