// Package config provides YAML configuration support for the DNS server.
package config

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// Configuration errors.
var (
	ErrInvalidConfig      = errors.New("invalid configuration")
	ErrConfigNotFound     = errors.New("configuration file not found")
	ErrInvalidMode        = errors.New("invalid resolution mode")
	ErrInvalidNumShards   = errors.New("number of shards must be a power of 2")
	ErrInvalidWorkerCount = errors.New("worker count must be positive")
)

// Config represents the complete DNS server configuration.
type Config struct {
	// Mode is the deployment mode: "standalone", "control", or "worker"
	// - standalone: Original single-process mode (default, backward compatible)
	// - control: Run as control plane server (manages distributed workers)
	// - worker: Run as DNS worker (connects to control plane)
	Mode string `yaml:"mode"`

	Server       ServerConfig       `yaml:"server"`
	Cache        CacheConfig        `yaml:"cache"`
	Resolver     ResolverConfig     `yaml:"resolver"`
	Logging      LoggingConfig      `yaml:"logging"`
	API          APIConfig          `yaml:"api"`
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	Worker       WorkerModeConfig   `yaml:"worker"`
}

// ControlPlaneConfig holds control plane configuration.
type ControlPlaneConfig struct {
	// GRPCAddress is the address for the gRPC server (worker connections)
	GRPCAddress string `yaml:"grpc_address"`

	// HeartbeatTimeout is the timeout for considering a worker stale
	HeartbeatTimeout time.Duration `yaml:"heartbeat_timeout"`
}

// WorkerModeConfig holds worker mode configuration.
type WorkerModeConfig struct {
	// WorkerID is a unique identifier for this worker (auto-generated if empty)
	WorkerID string `yaml:"worker_id"`

	// ControlPlaneAddress is the address of the control plane to connect to
	ControlPlaneAddress string `yaml:"control_plane_address"`

	// HeartbeatInterval is the interval between heartbeats
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// ReconnectDelay is the delay before attempting to reconnect
	ReconnectDelay time.Duration `yaml:"reconnect_delay"`
}

// APIConfig holds configuration for the management API.
type APIConfig struct {
	// Enabled enables the management API server
	Enabled bool `yaml:"enabled"`

	// ListenAddress is the address for the API server (e.g., ":8080")
	ListenAddress string `yaml:"listen_address"`

	// CORSOrigins is the list of allowed CORS origins (for development)
	CORSOrigins []string `yaml:"cors_origins"`

	// Auth holds authentication configuration
	Auth AuthConfig `yaml:"auth"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// Username is the admin username
	Username string `yaml:"username"`

	// PasswordHash is the bcrypt hash of the admin password
	PasswordHash string `yaml:"password_hash"`

	// JWTSecret is the secret key for signing JWT tokens
	JWTSecret string `yaml:"jwt_secret"`

	// TokenExpiry is the JWT token expiration duration
	TokenExpiry time.Duration `yaml:"token_expiry"`
}

// ServerConfig holds server-related configuration.
type ServerConfig struct {
	// ListenAddress is the address to listen on (e.g., ":8083" or "0.0.0.0:53")
	ListenAddress string `yaml:"listen_address"`

	// NumWorkers is the number of I/O workers (default: NumCPU)
	NumWorkers int `yaml:"num_workers"`

	// EnableTCP enables the TCP listener
	EnableTCP bool `yaml:"enable_tcp"`

	// PprofAddress is the address for the pprof HTTP server (empty to disable)
	PprofAddress string `yaml:"pprof_address"`

	// GracefulShutdownTimeout is the timeout for graceful shutdown
	GracefulShutdownTimeout time.Duration `yaml:"graceful_shutdown_timeout"`

	// StatsReportInterval is the interval for reporting stats
	StatsReportInterval time.Duration `yaml:"stats_report_interval"`
}

// CacheConfig holds cache-related configuration.
type CacheConfig struct {
	// MessageCache configuration for L1 cache
	MessageCache MessageCacheConfig `yaml:"message_cache"`

	// RRsetCache configuration for L2 cache
	RRsetCache RRsetCacheConfig `yaml:"rrset_cache"`

	// Prefetch configuration
	Prefetch PrefetchConfig `yaml:"prefetch"`

	// MinTTL is the minimum TTL for any cache entry
	MinTTL time.Duration `yaml:"min_ttl"`

	// MaxTTL is the maximum TTL for any cache entry
	MaxTTL time.Duration `yaml:"max_ttl"`

	// NegativeTTL is the TTL for negative cache entries
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

// MessageCacheConfig holds L1 message cache configuration.
type MessageCacheConfig struct {
	// MaxSizeMB is the maximum cache size in megabytes
	MaxSizeMB int `yaml:"max_size_mb"`

	// NumShards is the number of cache shards (should be power of 2)
	NumShards int `yaml:"num_shards"`
}

// RRsetCacheConfig holds L2 RRset cache configuration.
type RRsetCacheConfig struct {
	// MaxSizeMB is the maximum cache size in megabytes (typically 2x message cache)
	MaxSizeMB int `yaml:"max_size_mb"`

	// NumShards is the number of cache shards (should be power of 2)
	NumShards int `yaml:"num_shards"`
}

// PrefetchConfig holds prefetch configuration.
type PrefetchConfig struct {
	// Enabled enables background prefetching
	Enabled bool `yaml:"enabled"`

	// ThresholdHits is the hit count threshold for prefetch
	ThresholdHits int64 `yaml:"threshold_hits"`

	// ThresholdTTLPercent is the TTL percentage threshold for prefetch (e.g., 0.1 = 10%)
	ThresholdTTLPercent float64 `yaml:"threshold_ttl_percent"`
}

// ResolverConfig holds resolver-related configuration.
type ResolverConfig struct {
	// Mode is the resolution mode: "forwarding", "recursive", or "parallel"
	// - forwarding: Sequential queries to upstream servers with fallback
	// - recursive: True recursive resolution from root servers
	// - parallel: Parallel queries to multiple forwarders, fastest response wins,
	//             with fallback to recursive resolution if all fail
	Mode string `yaml:"mode"`

	// Upstreams is the list of upstream DNS servers (for forwarding/parallel mode)
	Upstreams []string `yaml:"upstreams"`

	// RootHintsFile is the path to the root hints file (for recursive mode)
	RootHintsFile string `yaml:"root_hints_file"`

	// MaxRecursionDepth is the maximum recursion depth
	MaxRecursionDepth int `yaml:"max_recursion_depth"`

	// QueryTimeout is the timeout for upstream queries
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// EnableCoalescing enables request coalescing
	EnableCoalescing bool `yaml:"enable_coalescing"`

	// ParallelConfig holds configuration for parallel forwarding mode
	ParallelConfig ParallelForwardingConfig `yaml:"parallel"`
}

// ParallelForwardingConfig holds configuration for parallel forwarding mode.
type ParallelForwardingConfig struct {
	// NumParallel is the number of upstreams to query in parallel (default: 3)
	// If more upstreams are configured, the best N are selected based on latency
	NumParallel int `yaml:"num_parallel"`

	// FallbackToRecursive enables fallback to recursive resolution
	// when all parallel forwarders fail (default: true)
	FallbackToRecursive bool `yaml:"fallback_to_recursive"`

	// SuccessRcodes defines which response codes are considered successful
	// Default: NOERROR (0) and NXDOMAIN (3) - these are valid answers
	// SERVFAIL, REFUSED, etc. trigger fallback to next response
	SuccessRcodes []int `yaml:"success_rcodes"`
}

// LoggingConfig holds logging-related configuration.
type LoggingConfig struct {
	// Level is the log level: "debug", "info", "warn", "error"
	Level string `yaml:"level"`

	// Format is the log format: "text" or "json"
	Format string `yaml:"format"`

	// EnableQueryLog enables logging of all DNS queries
	EnableQueryLog bool `yaml:"enable_query_log"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode: "standalone", // Default to standalone mode for backward compatibility
		Server: ServerConfig{
			ListenAddress:           ":8083",
			NumWorkers:              runtime.NumCPU(),
			EnableTCP:               true,
			PprofAddress:            ":6060",
			GracefulShutdownTimeout: 10 * time.Second,
			StatsReportInterval:     30 * time.Second,
		},
		Cache: CacheConfig{
			MessageCache: MessageCacheConfig{
				MaxSizeMB: 128,
				NumShards: 64,
			},
			RRsetCache: RRsetCacheConfig{
				MaxSizeMB: 256,
				NumShards: 128,
			},
			Prefetch: PrefetchConfig{
				Enabled:             true,
				ThresholdHits:       100,
				ThresholdTTLPercent: 0.1,
			},
			MinTTL:      60 * time.Second,
			MaxTTL:      24 * time.Hour,
			NegativeTTL: 1 * time.Hour,
		},
		Resolver: ResolverConfig{
			Mode: "parallel",
			Upstreams: []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
				"1.1.1.1:53",
				"1.0.0.1:53",
			},
			RootHintsFile:     "",
			MaxRecursionDepth: 30,
			QueryTimeout:      5 * time.Second,
			EnableCoalescing:  true,
			ParallelConfig: ParallelForwardingConfig{
				NumParallel:         3,
				FallbackToRecursive: true,
				SuccessRcodes:       []int{0, 3}, // NOERROR, NXDOMAIN
			},
		},
		Logging: LoggingConfig{
			Level:          "info",
			Format:         "text",
			EnableQueryLog: false,
		},
		API: APIConfig{
			Enabled:       true,
			ListenAddress: ":8080",
			CORSOrigins:   []string{"http://localhost:5173"}, // Vite dev server
			Auth: AuthConfig{
				Username:     "admin",
				PasswordHash: "", // Empty means use default password "admin" (will be hashed on first use)
				JWTSecret:    "", // Empty means generate random secret on startup
				TokenExpiry:  24 * time.Hour,
			},
		},
		ControlPlane: ControlPlaneConfig{
			GRPCAddress:      ":9090",
			HeartbeatTimeout: 30 * time.Second,
		},
		Worker: WorkerModeConfig{
			WorkerID:            "", // Auto-generated
			ControlPlaneAddress: "localhost:9090",
			HeartbeatInterval:   10 * time.Second,
			ReconnectDelay:      5 * time.Second,
		},
	}
}

// LoadFromFile loads configuration from a YAML file.
// If the file doesn't exist, returns default configuration.
func LoadFromFile(path string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// LoadFromFileOrDefault loads configuration from a YAML file.
// If the file doesn't exist, returns default configuration without error.
func LoadFromFileOrDefault(path string) (*Config, error) {
	cfg, err := LoadFromFile(path)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate deployment mode
	switch c.Mode {
	case "", "standalone", "control", "worker":
		// Valid modes (empty defaults to standalone)
		if c.Mode == "" {
			c.Mode = "standalone"
		}
	default:
		return fmt.Errorf("%w: deployment mode must be 'standalone', 'control', or 'worker', got '%s'", ErrInvalidConfig, c.Mode)
	}

	// Validate server config (only for standalone and worker modes)
	if c.Mode != "control" && c.Server.NumWorkers <= 0 {
		return fmt.Errorf("%w: %d", ErrInvalidWorkerCount, c.Server.NumWorkers)
	}

	// Validate cache shards (must be power of 2)
	if !isPowerOfTwo(c.Cache.MessageCache.NumShards) {
		return fmt.Errorf("%w: message cache shards=%d", ErrInvalidNumShards, c.Cache.MessageCache.NumShards)
	}
	if !isPowerOfTwo(c.Cache.RRsetCache.NumShards) {
		return fmt.Errorf("%w: rrset cache shards=%d", ErrInvalidNumShards, c.Cache.RRsetCache.NumShards)
	}

	// Validate resolver mode
	switch c.Resolver.Mode {
	case "forwarding", "recursive", "parallel":
		// Valid modes
	default:
		return fmt.Errorf("%w: %s", ErrInvalidMode, c.Resolver.Mode)
	}

	// Validate parallel config
	if c.Resolver.Mode == "parallel" {
		if c.Resolver.ParallelConfig.NumParallel <= 0 {
			c.Resolver.ParallelConfig.NumParallel = 3 // Default
		}
		if len(c.Resolver.ParallelConfig.SuccessRcodes) == 0 {
			c.Resolver.ParallelConfig.SuccessRcodes = []int{0, 3} // NOERROR, NXDOMAIN
		}
	}

	return nil
}

// SaveToFile saves the configuration to a YAML file.
func (c *Config) SaveToFile(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// isPowerOfTwo checks if n is a power of 2.
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}
