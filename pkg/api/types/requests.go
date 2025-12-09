package types

// LoginRequest is the request body for login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UpdateUpstreamsRequest is the request body for updating upstreams.
type UpdateUpstreamsRequest struct {
	Upstreams []string `json:"upstreams"`
}

// CreateZoneRequest is the request body for creating a zone.
type CreateZoneRequest struct {
	Origin          string   `json:"origin"`
	ZoneFileContent string   `json:"zone_file_content,omitempty"`
	TransferACL     []string `json:"transfer_acl,omitempty"`
	UpdateACL       []string `json:"update_acl,omitempty"`
}

// ClearCacheRequest is the request body for clearing cache.
type ClearCacheRequest struct {
	CacheType string `json:"cache_type"` // "all", "message", "rrset", "infra"
}

// UpdateConfigRequest is the request body for updating configuration.
type UpdateConfigRequest struct {
	Cache    *UpdateCacheConfig    `json:"cache,omitempty"`
	Resolver *UpdateResolverConfig `json:"resolver,omitempty"`
	Logging  *UpdateLoggingConfig  `json:"logging,omitempty"`
}

// UpdateCacheConfig contains cache configuration updates.
type UpdateCacheConfig struct {
	Prefetch   *UpdatePrefetchConfig `json:"prefetch,omitempty"`
	MinTTLSecs *int                  `json:"min_ttl_seconds,omitempty"`
	MaxTTLSecs *int                  `json:"max_ttl_seconds,omitempty"`
	NegTTLSecs *int                  `json:"negative_ttl_seconds,omitempty"`
}

// UpdatePrefetchConfig contains prefetch configuration updates.
type UpdatePrefetchConfig struct {
	Enabled             *bool    `json:"enabled,omitempty"`
	ThresholdHits       *int64   `json:"threshold_hits,omitempty"`
	ThresholdTTLPercent *float64 `json:"threshold_ttl_percent,omitempty"`
}

// UpdateResolverConfig contains resolver configuration updates.
type UpdateResolverConfig struct {
	Mode              *string                  `json:"mode,omitempty"`
	Upstreams         []string                 `json:"upstreams,omitempty"`
	EnableCoalescing  *bool                    `json:"enable_coalescing,omitempty"`
	Parallel          *UpdateParallelConfig    `json:"parallel,omitempty"`
}

// UpdateParallelConfig contains parallel forwarding configuration updates.
type UpdateParallelConfig struct {
	NumParallel         *int  `json:"num_parallel,omitempty"`
	FallbackToRecursive *bool `json:"fallback_to_recursive,omitempty"`
	SuccessRcodes       []int `json:"success_rcodes,omitempty"`
}

// UpdateLoggingConfig contains logging configuration updates.
type UpdateLoggingConfig struct {
	Level          *string `json:"level,omitempty"`
	Format         *string `json:"format,omitempty"`
	EnableQueryLog *bool   `json:"enable_query_log,omitempty"`
}
