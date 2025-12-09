// Package sync provides zone and configuration synchronization for the control plane.
package sync

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/piwi3910/dns-go/pkg/control"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// ConfigSyncManager manages configuration distribution to workers.
type ConfigSyncManager struct {
	mu sync.RWMutex

	// globalConfig is the base configuration for all workers
	globalConfig *pb.WorkerConfig

	// workerConfigs stores per-worker configuration overrides
	workerConfigs map[string]*pb.WorkerConfig

	// configVersion is atomically incremented on each update
	configVersion atomic.Uint64

	// subscribers maps workerID -> update channel
	subscribers map[string]chan *pb.ConfigUpdate

	// subscriberMu protects subscribers map
	subscriberMu sync.RWMutex
}

// NewConfigSyncManager creates a new configuration synchronization manager.
func NewConfigSyncManager() *ConfigSyncManager {
	return &ConfigSyncManager{
		workerConfigs: make(map[string]*pb.WorkerConfig),
		subscribers:   make(map[string]chan *pb.ConfigUpdate),
	}
}

// SetGlobalConfig sets the base configuration for all workers.
func (m *ConfigSyncManager) SetGlobalConfig(ctx context.Context, config *pb.WorkerConfig) error {
	m.mu.Lock()
	m.globalConfig = config
	version := m.configVersion.Add(1)
	config.ConfigVersion = fmt.Sprintf("v%d", version)
	m.mu.Unlock()

	// Notify all subscribers
	return m.broadcastConfigUpdate(ctx, config, false)
}

// GetConfig returns the configuration for a specific worker.
func (m *ConfigSyncManager) GetConfig(ctx context.Context, workerID string) (*pb.WorkerConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check for worker-specific config first
	if workerConfig, exists := m.workerConfigs[workerID]; exists {
		return workerConfig, nil
	}

	// Fall back to global config
	if m.globalConfig != nil {
		return m.globalConfig, nil
	}

	// Return default config if nothing set
	return m.defaultConfig(), nil
}

// SetWorkerConfig sets a worker-specific configuration override.
func (m *ConfigSyncManager) SetWorkerConfig(ctx context.Context, workerID string, config *pb.WorkerConfig) error {
	m.mu.Lock()
	version := m.configVersion.Add(1)
	config.ConfigVersion = fmt.Sprintf("v%d-worker-%s", version, workerID)
	m.workerConfigs[workerID] = config
	m.mu.Unlock()

	// Notify the specific worker
	return m.notifyWorker(ctx, workerID, config, false)
}

// NotifyConfigUpdate sends a configuration update to a specific worker.
func (m *ConfigSyncManager) NotifyConfigUpdate(ctx context.Context, workerID string, update *pb.ConfigUpdate) error {
	m.subscriberMu.RLock()
	defer m.subscriberMu.RUnlock()

	ch, exists := m.subscribers[workerID]
	if !exists {
		return fmt.Errorf("worker %s not subscribed to config updates", workerID)
	}

	select {
	case ch <- update:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("worker %s config update channel full", workerID)
	}
}

// Subscribe creates a subscription for configuration updates for a worker.
func (m *ConfigSyncManager) Subscribe(workerID string) (<-chan *pb.ConfigUpdate, error) {
	m.subscriberMu.Lock()
	defer m.subscriberMu.Unlock()

	if _, exists := m.subscribers[workerID]; exists {
		return nil, fmt.Errorf("worker %s already subscribed to config updates", workerID)
	}

	// Buffered channel to prevent blocking on slow consumers
	ch := make(chan *pb.ConfigUpdate, 10)
	m.subscribers[workerID] = ch

	return ch, nil
}

// Unsubscribe removes a worker's subscription and closes the channel.
func (m *ConfigSyncManager) Unsubscribe(workerID string) {
	m.subscriberMu.Lock()
	defer m.subscriberMu.Unlock()

	if ch, exists := m.subscribers[workerID]; exists {
		close(ch)
		delete(m.subscribers, workerID)
	}
}

// RemoveWorker removes worker-specific config and subscription.
func (m *ConfigSyncManager) RemoveWorker(workerID string) {
	m.mu.Lock()
	delete(m.workerConfigs, workerID)
	m.mu.Unlock()

	m.Unsubscribe(workerID)
}

// broadcastConfigUpdate sends a config update to all subscribers.
func (m *ConfigSyncManager) broadcastConfigUpdate(ctx context.Context, config *pb.WorkerConfig, fullReload bool) error {
	m.subscriberMu.RLock()
	defer m.subscriberMu.RUnlock()

	update := &pb.ConfigUpdate{
		Version:            config.ConfigVersion,
		Config:             config,
		FullReloadRequired: fullReload,
	}

	for workerID, ch := range m.subscribers {
		select {
		case ch <- update:
			// Successfully sent
		default:
			// Channel full, worker is slow
			_ = workerID
		}
	}

	return nil
}

// notifyWorker sends a config update to a specific worker.
func (m *ConfigSyncManager) notifyWorker(ctx context.Context, workerID string, config *pb.WorkerConfig, fullReload bool) error {
	update := &pb.ConfigUpdate{
		Version:            config.ConfigVersion,
		Config:             config,
		FullReloadRequired: fullReload,
	}

	return m.NotifyConfigUpdate(ctx, workerID, update)
}

// defaultConfig returns a default worker configuration.
func (m *ConfigSyncManager) defaultConfig() *pb.WorkerConfig {
	return &pb.WorkerConfig{
		ConfigVersion: "v0-default",
		Resolver: &pb.ResolverConfig{
			Mode:               "forwarding",
			MaxRecursionDepth:  30,
			QueryTimeoutMs:     5000,
			EnableCoalescing:   true,
		},
		Cache: &pb.CacheConfig{
			MessageCacheSizeMb:  64,
			MessageCacheShards:  16,
			RrsetCacheSizeMb:    128,
			RrsetCacheShards:    32,
			MinTtlSeconds:       60,
			MaxTtlSeconds:       86400,
			NegativeTtlSeconds:  3600,
			Prefetch: &pb.PrefetchConfig{
				Enabled:             true,
				ThresholdHits:       100,
				ThresholdTtlPercent: 10,
			},
		},
		Upstreams: []*pb.UpstreamServer{
			{Address: "8.8.8.8:53", Weight: 1, Enabled: true},
			{Address: "1.1.1.1:53", Weight: 1, Enabled: true},
		},
		Security: &pb.SecurityConfig{
			EnableRateLimiting: true,
			RateLimitQps:       10000,
		},
		Logging: &pb.LoggingConfig{
			Level:          "info",
			Format:         "json",
			EnableQueryLog: false,
		},
	}
}

// GetConfigVersion returns the current configuration version.
func (m *ConfigSyncManager) GetConfigVersion() string {
	return fmt.Sprintf("v%d", m.configVersion.Load())
}

// ReloadConfig triggers a full configuration reload for a worker.
func (m *ConfigSyncManager) ReloadConfig(ctx context.Context, workerID string) error {
	config, err := m.GetConfig(ctx, workerID)
	if err != nil {
		return err
	}

	return m.notifyWorker(ctx, workerID, config, true)
}

// ReloadAllConfigs triggers a full configuration reload for all workers.
func (m *ConfigSyncManager) ReloadAllConfigs(ctx context.Context) error {
	m.mu.RLock()
	config := m.globalConfig
	if config == nil {
		config = m.defaultConfig()
	}
	m.mu.RUnlock()

	return m.broadcastConfigUpdate(ctx, config, true)
}

// GetSubscribedWorkers returns the list of workers subscribed to config updates.
func (m *ConfigSyncManager) GetSubscribedWorkers() []string {
	m.subscriberMu.RLock()
	defer m.subscriberMu.RUnlock()

	workers := make([]string, 0, len(m.subscribers))
	for workerID := range m.subscribers {
		workers = append(workers, workerID)
	}
	return workers
}

// SetTimestamp is a helper to set the current timestamp on a ConfigUpdate.
func SetTimestamp(update *pb.ConfigUpdate) {
	// Note: This requires importing google.golang.org/protobuf/types/known/timestamppb
	// For now, we leave timestamp as nil and let the receiver set it
	_ = time.Now()
}

// Ensure ConfigSyncManager implements control.ConfigSyncManager
var _ control.ConfigSyncManager = (*ConfigSyncManager)(nil)
