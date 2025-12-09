// Package config provides configuration storage and distribution.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ConfigStore provides an abstraction for config persistence.
// Implementations can store config locally (file), in Kubernetes CRDs, or other backends.
type ConfigStore interface {
	// Load retrieves the current configuration.
	Load(ctx context.Context) (*Config, error)

	// Save persists the configuration.
	Save(ctx context.Context, cfg *Config) error

	// Watch returns a channel that receives config updates.
	// The channel is closed when the context is cancelled.
	Watch(ctx context.Context) (<-chan *Config, error)

	// Close releases any resources held by the store.
	Close() error
}

// ConfigUpdateCallback is called when configuration changes.
type ConfigUpdateCallback func(old, new *Config)

// FileConfigStore implements ConfigStore using a YAML file.
type FileConfigStore struct {
	mu           sync.RWMutex
	path         string
	config       *Config
	lastModified time.Time
	subscribers  []chan *Config
	subMu        sync.Mutex
	stopWatch    chan struct{}
}

// NewFileConfigStore creates a new file-based config store.
func NewFileConfigStore(path string) (*FileConfigStore, error) {
	store := &FileConfigStore{
		path:        path,
		subscribers: make([]chan *Config, 0),
		stopWatch:   make(chan struct{}),
	}

	// Load initial config
	cfg, err := store.Load(context.Background())
	if err != nil {
		// If file doesn't exist, create default config
		if os.IsNotExist(err) {
			cfg = DefaultConfig()
			store.config = cfg
		} else {
			return nil, err
		}
	} else {
		store.config = cfg
	}

	// Start file watcher
	go store.watchFile()

	return store, nil
}

// Load retrieves the current configuration from the file.
func (s *FileConfigStore) Load(ctx context.Context) (*Config, error) {
	s.mu.RLock()
	if s.config != nil {
		cfg := *s.config // Return a copy
		s.mu.RUnlock()
		return &cfg, nil
	}
	s.mu.RUnlock()

	// Load from file
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	s.mu.Lock()
	s.config = &cfg
	s.mu.Unlock()

	return &cfg, nil
}

// Save persists the configuration to the file.
func (s *FileConfigStore) Save(ctx context.Context, cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	s.config = cfg
	s.lastModified = time.Now()

	// Notify subscribers
	s.notifySubscribers(cfg)

	return nil
}

// Watch returns a channel that receives config updates.
func (s *FileConfigStore) Watch(ctx context.Context) (<-chan *Config, error) {
	ch := make(chan *Config, 1)

	s.subMu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.subMu.Unlock()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		s.subMu.Lock()
		for i, sub := range s.subscribers {
			if sub == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				close(ch)
				break
			}
		}
		s.subMu.Unlock()
	}()

	return ch, nil
}

// Close releases any resources held by the store.
func (s *FileConfigStore) Close() error {
	close(s.stopWatch)

	s.subMu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	s.subMu.Unlock()

	return nil
}

// watchFile monitors the config file for changes.
func (s *FileConfigStore) watchFile() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopWatch:
			return
		case <-ticker.C:
			info, err := os.Stat(s.path)
			if err != nil {
				continue
			}

			s.mu.RLock()
			lastMod := s.lastModified
			s.mu.RUnlock()

			if info.ModTime().After(lastMod) {
				// File was modified externally
				data, err := os.ReadFile(s.path)
				if err != nil {
					continue
				}

				var cfg Config
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					continue
				}

				s.mu.Lock()
				s.config = &cfg
				s.lastModified = info.ModTime()
				s.mu.Unlock()

				s.notifySubscribers(&cfg)
			}
		}
	}
}

// notifySubscribers sends config update to all subscribers.
func (s *FileConfigStore) notifySubscribers(cfg *Config) {
	s.subMu.Lock()
	defer s.subMu.Unlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- cfg:
		default:
			// Channel full, skip
		}
	}
}

// MemoryConfigStore implements ConfigStore using in-memory storage.
// Useful for testing and for standalone mode without persistence.
type MemoryConfigStore struct {
	mu          sync.RWMutex
	config      *Config
	subscribers []chan *Config
	subMu       sync.Mutex
}

// NewMemoryConfigStore creates a new memory-based config store.
func NewMemoryConfigStore(cfg *Config) *MemoryConfigStore {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &MemoryConfigStore{
		config:      cfg,
		subscribers: make([]chan *Config, 0),
	}
}

// Load retrieves the current configuration.
func (s *MemoryConfigStore) Load(ctx context.Context) (*Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config == nil {
		return nil, fmt.Errorf("no configuration loaded")
	}

	cfg := *s.config // Return a copy
	return &cfg, nil
}

// Save persists the configuration.
func (s *MemoryConfigStore) Save(ctx context.Context, cfg *Config) error {
	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()

	// Notify subscribers
	s.subMu.Lock()
	for _, ch := range s.subscribers {
		select {
		case ch <- cfg:
		default:
		}
	}
	s.subMu.Unlock()

	return nil
}

// Watch returns a channel that receives config updates.
func (s *MemoryConfigStore) Watch(ctx context.Context) (<-chan *Config, error) {
	ch := make(chan *Config, 1)

	s.subMu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.subMu.Unlock()

	go func() {
		<-ctx.Done()
		s.subMu.Lock()
		for i, sub := range s.subscribers {
			if sub == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				close(ch)
				break
			}
		}
		s.subMu.Unlock()
	}()

	return ch, nil
}

// Close releases any resources.
func (s *MemoryConfigStore) Close() error {
	s.subMu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	s.subMu.Unlock()
	return nil
}

// ConfigJSON represents the config in JSON format (for API responses).
type ConfigJSON struct {
	Server   ServerConfigJSON   `json:"server"`
	Cache    CacheConfigJSON    `json:"cache"`
	Resolver ResolverConfigJSON `json:"resolver"`
	Logging  LoggingConfigJSON  `json:"logging"`
	API      APIConfigJSON      `json:"api"`
}

// ServerConfigJSON is the JSON representation of ServerConfig.
type ServerConfigJSON struct {
	ListenAddress               string `json:"listen_address"`
	NumWorkers                  int    `json:"num_workers"`
	EnableTCP                   bool   `json:"enable_tcp"`
	PprofAddress                string `json:"pprof_address"`
	GracefulShutdownTimeoutSecs int    `json:"graceful_shutdown_timeout_seconds"`
	StatsReportIntervalSecs     int    `json:"stats_report_interval_seconds"`
}

// CacheConfigJSON is the JSON representation of CacheConfig.
type CacheConfigJSON struct {
	MessageCache MessageCacheConfigJSON `json:"message_cache"`
	RRsetCache   RRsetCacheConfigJSON   `json:"rrset_cache"`
	Prefetch     PrefetchConfigJSON     `json:"prefetch"`
	MinTTLSecs   int                    `json:"min_ttl_seconds"`
	MaxTTLSecs   int                    `json:"max_ttl_seconds"`
	NegTTLSecs   int                    `json:"negative_ttl_seconds"`
}

// MessageCacheConfigJSON is the JSON representation of MessageCacheConfig.
type MessageCacheConfigJSON struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// RRsetCacheConfigJSON is the JSON representation of RRsetCacheConfig.
type RRsetCacheConfigJSON struct {
	MaxSizeMB int `json:"max_size_mb"`
	NumShards int `json:"num_shards"`
}

// PrefetchConfigJSON is the JSON representation of PrefetchConfig.
type PrefetchConfigJSON struct {
	Enabled             bool    `json:"enabled"`
	ThresholdHits       int64   `json:"threshold_hits"`
	ThresholdTTLPercent float64 `json:"threshold_ttl_percent"`
}

// ResolverConfigJSON is the JSON representation of ResolverConfig.
type ResolverConfigJSON struct {
	Mode              string             `json:"mode"`
	Upstreams         []string           `json:"upstreams"`
	RootHintsFile     string             `json:"root_hints_file"`
	MaxRecursionDepth int                `json:"max_recursion_depth"`
	QueryTimeoutSecs  int                `json:"query_timeout_seconds"`
	EnableCoalescing  bool               `json:"enable_coalescing"`
	Parallel          ParallelConfigJSON `json:"parallel"`
}

// ParallelConfigJSON is the JSON representation of ParallelResolverConfig.
type ParallelConfigJSON struct {
	NumParallel         int   `json:"num_parallel"`
	FallbackToRecursive bool  `json:"fallback_to_recursive"`
	SuccessRcodes       []int `json:"success_rcodes"`
}

// LoggingConfigJSON is the JSON representation of LoggingConfig.
type LoggingConfigJSON struct {
	Level          string `json:"level"`
	Format         string `json:"format"`
	EnableQueryLog bool   `json:"enable_query_log"`
}

// APIConfigJSON is the JSON representation of APIConfig.
type APIConfigJSON struct {
	Enabled       bool     `json:"enabled"`
	ListenAddress string   `json:"listen_address"`
	CORSOrigins   []string `json:"cors_origins"`
}

// ToJSON converts Config to ConfigJSON for API responses.
func (c *Config) ToJSON() *ConfigJSON {
	return &ConfigJSON{
		Server: ServerConfigJSON{
			ListenAddress:               c.Server.ListenAddress,
			NumWorkers:                  c.Server.NumWorkers,
			EnableTCP:                   c.Server.EnableTCP,
			PprofAddress:                c.Server.PprofAddress,
			GracefulShutdownTimeoutSecs: int(c.Server.GracefulShutdownTimeout.Seconds()),
			StatsReportIntervalSecs:     int(c.Server.StatsReportInterval.Seconds()),
		},
		Cache: CacheConfigJSON{
			MessageCache: MessageCacheConfigJSON{
				MaxSizeMB: c.Cache.MessageCache.MaxSizeMB,
				NumShards: c.Cache.MessageCache.NumShards,
			},
			RRsetCache: RRsetCacheConfigJSON{
				MaxSizeMB: c.Cache.RRsetCache.MaxSizeMB,
				NumShards: c.Cache.RRsetCache.NumShards,
			},
			Prefetch: PrefetchConfigJSON{
				Enabled:             c.Cache.Prefetch.Enabled,
				ThresholdHits:       c.Cache.Prefetch.ThresholdHits,
				ThresholdTTLPercent: c.Cache.Prefetch.ThresholdTTLPercent,
			},
			MinTTLSecs: int(c.Cache.MinTTL.Seconds()),
			MaxTTLSecs: int(c.Cache.MaxTTL.Seconds()),
			NegTTLSecs: int(c.Cache.NegativeTTL.Seconds()),
		},
		Resolver: ResolverConfigJSON{
			Mode:              c.Resolver.Mode,
			Upstreams:         c.Resolver.Upstreams,
			RootHintsFile:     c.Resolver.RootHintsFile,
			MaxRecursionDepth: c.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  int(c.Resolver.QueryTimeout.Seconds()),
			EnableCoalescing:  c.Resolver.EnableCoalescing,
			Parallel: ParallelConfigJSON{
				NumParallel:         c.Resolver.ParallelConfig.NumParallel,
				FallbackToRecursive: c.Resolver.ParallelConfig.FallbackToRecursive,
				SuccessRcodes:       c.Resolver.ParallelConfig.SuccessRcodes,
			},
		},
		Logging: LoggingConfigJSON{
			Level:          c.Logging.Level,
			Format:         c.Logging.Format,
			EnableQueryLog: c.Logging.EnableQueryLog,
		},
		API: APIConfigJSON{
			Enabled:       c.API.Enabled,
			ListenAddress: c.API.ListenAddress,
			CORSOrigins:   c.API.CORSOrigins,
		},
	}
}

// MarshalJSON implements json.Marshaler for Config.
func (c *Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.ToJSON())
}
