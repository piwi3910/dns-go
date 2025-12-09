// Package bridge provides the abstraction layer between the API/management plane
// and the DNS worker/data plane. This enables the management plane to control
// either local (in-process) or remote (distributed) DNS workers.
package bridge

import (
	"context"
	"time"
)

// DNSService is the main interface for interacting with DNS functionality.
// This can be implemented by a local (in-process) service or a remote
// (gRPC-based) service for distributed deployments.
type DNSService interface {
	StatsService
	ZoneService
	UpstreamService
	CacheService
	ConfigService
}

// StatsService provides access to DNS server statistics.
type StatsService interface {
	// GetStats returns current server statistics.
	GetStats(ctx context.Context) (*StatsResponse, error)

	// SubscribeStats returns a channel that receives stats updates.
	// The channel is closed when the context is cancelled.
	SubscribeStats(ctx context.Context) (<-chan *StatsResponse, error)
}

// ZoneService manages DNS zones.
type ZoneService interface {
	// GetZones returns all configured zones.
	GetZones(ctx context.Context) ([]ZoneInfo, error)

	// GetZone returns detailed information about a specific zone.
	GetZone(ctx context.Context, origin string) (*ZoneDetail, error)

	// CreateZone creates a new zone.
	CreateZone(ctx context.Context, req CreateZoneRequest) (*ZoneDetail, error)

	// DeleteZone removes a zone.
	DeleteZone(ctx context.Context, origin string) error
}

// UpstreamService manages upstream DNS resolvers.
type UpstreamService interface {
	// GetUpstreams returns the list of configured upstream servers.
	GetUpstreams(ctx context.Context) ([]UpstreamInfo, error)

	// SetUpstreams updates the list of upstream servers.
	SetUpstreams(ctx context.Context, upstreams []string) error
}

// CacheService manages DNS caches.
type CacheService interface {
	// GetCacheStats returns cache statistics.
	GetCacheStats(ctx context.Context) (*CacheStatsResponse, error)

	// ClearCache clears the specified cache type.
	// Valid types: "all", "message", "rrset", "infra"
	ClearCache(ctx context.Context, cacheType string) ([]string, error)
}

// ConfigService provides access to server configuration.
type ConfigService interface {
	// GetConfig returns the current configuration.
	GetConfig(ctx context.Context) (*ConfigResponse, error)

	// UpdateConfig updates the configuration.
	// Returns true if a restart is required.
	UpdateConfig(ctx context.Context, req UpdateConfigRequest) (bool, error)
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

// ZoneInfo contains basic zone information.
type ZoneInfo struct {
	Origin       string    `json:"origin"`
	Serial       uint32    `json:"serial"`
	RecordCount  int       `json:"record_count"`
	LastModified time.Time `json:"last_modified"`
	HasSOA       bool      `json:"has_soa"`
}

// ZoneDetail contains detailed zone information.
type ZoneDetail struct {
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

// CreateZoneRequest is the request to create a new zone.
type CreateZoneRequest struct {
	Origin      string   `json:"origin"`
	TransferACL []string `json:"transfer_acl"`
	UpdateACL   []string `json:"update_acl"`
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

// CacheStatsResponse contains cache statistics.
type CacheStatsResponse struct {
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
	Server   ServerConfig   `json:"server"`
	Cache    CacheConfig    `json:"cache"`
	Resolver ResolverConfig `json:"resolver"`
	Logging  LoggingConfig  `json:"logging"`
	API      APIConfig      `json:"api"`
}

// ServerConfig contains server configuration.
type ServerConfig struct {
	ListenAddress               string `json:"listen_address"`
	NumWorkers                  int    `json:"num_workers"`
	EnableTCP                   bool   `json:"enable_tcp"`
	PprofAddress                string `json:"pprof_address"`
	GracefulShutdownTimeoutSecs int    `json:"graceful_shutdown_timeout_seconds"`
	StatsReportIntervalSecs     int    `json:"stats_report_interval_seconds"`
}

// CacheConfig contains cache configuration.
type CacheConfig struct {
	MessageCache MessageCacheConfig `json:"message_cache"`
	RRsetCache   RRsetCacheConfig   `json:"rrset_cache"`
	Prefetch     PrefetchConfig     `json:"prefetch"`
	MinTTLSecs   int                `json:"min_ttl_seconds"`
	MaxTTLSecs   int                `json:"max_ttl_seconds"`
	NegTTLSecs   int                `json:"negative_ttl_seconds"`
}

// MessageCacheConfig contains message cache configuration.
type MessageCacheConfig struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// RRsetCacheConfig contains RRset cache configuration.
type RRsetCacheConfig struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// PrefetchConfig contains prefetch configuration.
type PrefetchConfig struct {
	Enabled             bool    `json:"enabled"`
	ThresholdHits       int64   `json:"threshold_hits"`
	ThresholdTTLPercent float64 `json:"threshold_ttl_percent"`
}

// ResolverConfig contains resolver configuration.
type ResolverConfig struct {
	Mode              string         `json:"mode"`
	Upstreams         []string       `json:"upstreams"`
	RootHintsFile     string         `json:"root_hints_file"`
	MaxRecursionDepth int            `json:"max_recursion_depth"`
	QueryTimeoutSecs  int            `json:"query_timeout_seconds"`
	EnableCoalescing  bool           `json:"enable_coalescing"`
	Parallel          ParallelConfig `json:"parallel"`
}

// ParallelConfig contains parallel forwarding configuration.
type ParallelConfig struct {
	NumParallel         int   `json:"num_parallel"`
	FallbackToRecursive bool  `json:"fallback_to_recursive"`
	SuccessRcodes       []int `json:"success_rcodes"`
}

// LoggingConfig contains logging configuration.
type LoggingConfig struct {
	Level          string `json:"level"`
	Format         string `json:"format"`
	EnableQueryLog bool   `json:"enable_query_log"`
}

// APIConfig contains API configuration.
type APIConfig struct {
	Enabled       bool     `json:"enabled"`
	ListenAddress string   `json:"listen_address"`
	CORSOrigins   []string `json:"cors_origins"`
}

// UpdateConfigRequest is the request to update configuration.
type UpdateConfigRequest struct {
	Cache    *CacheConfigUpdate    `json:"cache,omitempty"`
	Resolver *ResolverConfigUpdate `json:"resolver,omitempty"`
	Logging  *LoggingConfigUpdate  `json:"logging,omitempty"`
}

// CacheConfigUpdate contains cache configuration updates.
type CacheConfigUpdate struct {
	Prefetch   *PrefetchConfigUpdate `json:"prefetch,omitempty"`
	MinTTLSecs *int                  `json:"min_ttl_seconds,omitempty"`
	MaxTTLSecs *int                  `json:"max_ttl_seconds,omitempty"`
	NegTTLSecs *int                  `json:"negative_ttl_seconds,omitempty"`
}

// PrefetchConfigUpdate contains prefetch configuration updates.
type PrefetchConfigUpdate struct {
	Enabled             *bool    `json:"enabled,omitempty"`
	ThresholdHits       *int64   `json:"threshold_hits,omitempty"`
	ThresholdTTLPercent *float64 `json:"threshold_ttl_percent,omitempty"`
}

// ResolverConfigUpdate contains resolver configuration updates.
type ResolverConfigUpdate struct {
	Mode             *string               `json:"mode,omitempty"`
	Upstreams        []string              `json:"upstreams,omitempty"`
	EnableCoalescing *bool                 `json:"enable_coalescing,omitempty"`
	Parallel         *ParallelConfigUpdate `json:"parallel,omitempty"`
}

// ParallelConfigUpdate contains parallel forwarding configuration updates.
type ParallelConfigUpdate struct {
	NumParallel         *int  `json:"num_parallel,omitempty"`
	FallbackToRecursive *bool `json:"fallback_to_recursive,omitempty"`
}

// LoggingConfigUpdate contains logging configuration updates.
type LoggingConfigUpdate struct {
	Level          *string `json:"level,omitempty"`
	EnableQueryLog *bool   `json:"enable_query_log,omitempty"`
}
