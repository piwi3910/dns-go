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
	Server   ServerConfig   `yaml:"server"`
	Cache    CacheConfig    `yaml:"cache"`
	Resolver ResolverConfig `yaml:"resolver"`
	Logging  LoggingConfig  `yaml:"logging"`
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
	// Mode is the resolution mode: "forwarding" or "recursive"
	Mode string `yaml:"mode"`

	// Upstreams is the list of upstream DNS servers (for forwarding mode)
	Upstreams []string `yaml:"upstreams"`

	// RootHintsFile is the path to the root hints file (for recursive mode)
	RootHintsFile string `yaml:"root_hints_file"`

	// MaxRecursionDepth is the maximum recursion depth
	MaxRecursionDepth int `yaml:"max_recursion_depth"`

	// QueryTimeout is the timeout for upstream queries
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// EnableCoalescing enables request coalescing
	EnableCoalescing bool `yaml:"enable_coalescing"`
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
			Mode: "forwarding",
			Upstreams: []string{
				"8.8.8.8:53",
				"1.1.1.1:53",
			},
			RootHintsFile:     "",
			MaxRecursionDepth: 30,
			QueryTimeout:      5 * time.Second,
			EnableCoalescing:  true,
		},
		Logging: LoggingConfig{
			Level:          "info",
			Format:         "text",
			EnableQueryLog: false,
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
	// Validate server config
	if c.Server.NumWorkers <= 0 {
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
	case "forwarding", "recursive":
		// Valid modes
	default:
		return fmt.Errorf("%w: %s", ErrInvalidMode, c.Resolver.Mode)
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
