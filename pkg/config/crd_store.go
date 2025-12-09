// Package config provides configuration management for the DNS server.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CRD Group, Version, Resource for DNSConfig.
const (
	CRDGroup    = "dns.piwi3910.io"
	CRDVersion  = "v1alpha1"
	CRDResource = "dnsconfigs"
)

// CRDConfigStoreConfig holds configuration for CRDConfigStore.
type CRDConfigStoreConfig struct {
	// Namespace is the Kubernetes namespace to watch for DNSConfig CRDs
	Namespace string

	// ConfigName is the name of the DNSConfig CRD to use
	ConfigName string

	// KubeconfigPath is the path to kubeconfig file (optional, uses in-cluster config if empty)
	KubeconfigPath string

	// ResyncInterval is how often to resync with the API server
	ResyncInterval time.Duration
}

// DefaultCRDConfigStoreConfig returns default configuration.
func DefaultCRDConfigStoreConfig() CRDConfigStoreConfig {
	return CRDConfigStoreConfig{
		Namespace:      "default",
		ConfigName:     "dns-server-config",
		ResyncInterval: 30 * time.Second,
	}
}

// CRDConfigStore implements ConfigStore backed by Kubernetes CRDs.
type CRDConfigStore struct {
	config       CRDConfigStoreConfig
	client       dynamic.Interface
	gvr          schema.GroupVersionResource
	mu           sync.RWMutex
	currentCfg   *Config
	subscribers  []chan *Config
	subMu        sync.Mutex
	stopCh       chan struct{}
	watchCancel  context.CancelFunc
	lastVersion  string
}

// NewCRDConfigStore creates a new CRDConfigStore.
func NewCRDConfigStore(cfg CRDConfigStoreConfig) (*CRDConfigStore, error) {
	var restConfig *rest.Config
	var err error

	if cfg.KubeconfigPath != "" {
		// Use kubeconfig file
		restConfig, err = clientcmd.BuildConfigFromFlags("", cfg.KubeconfigPath)
	} else {
		// Use in-cluster config
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes config: %w", err)
	}

	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	store := &CRDConfigStore{
		config: cfg,
		client: client,
		gvr: schema.GroupVersionResource{
			Group:    CRDGroup,
			Version:  CRDVersion,
			Resource: CRDResource,
		},
		subscribers: make([]chan *Config, 0),
		stopCh:      make(chan struct{}),
	}

	return store, nil
}

// NewCRDConfigStoreWithClient creates a CRDConfigStore with a provided client (for testing).
func NewCRDConfigStoreWithClient(cfg CRDConfigStoreConfig, client dynamic.Interface) *CRDConfigStore {
	return &CRDConfigStore{
		config: cfg,
		client: client,
		gvr: schema.GroupVersionResource{
			Group:    CRDGroup,
			Version:  CRDVersion,
			Resource: CRDResource,
		},
		subscribers: make([]chan *Config, 0),
		stopCh:      make(chan struct{}),
	}
}

// Load loads the configuration from the CRD.
func (s *CRDConfigStore) Load(ctx context.Context) (*Config, error) {
	unstructuredObj, err := s.client.Resource(s.gvr).Namespace(s.config.Namespace).Get(
		ctx, s.config.ConfigName, metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNSConfig CRD: %w", err)
	}

	cfg, err := s.unstructuredToConfig(unstructuredObj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert CRD to config: %w", err)
	}

	s.mu.Lock()
	s.currentCfg = cfg
	s.lastVersion = unstructuredObj.GetResourceVersion()
	s.mu.Unlock()

	return cfg, nil
}

// Save saves the configuration to the CRD.
func (s *CRDConfigStore) Save(ctx context.Context, cfg *Config) error {
	// Get current CRD to preserve metadata
	existing, err := s.client.Resource(s.gvr).Namespace(s.config.Namespace).Get(
		ctx, s.config.ConfigName, metav1.GetOptions{},
	)
	if err != nil {
		// CRD doesn't exist, create it
		return s.createCRD(ctx, cfg)
	}

	// Update existing CRD
	spec, err := s.configToSpec(cfg)
	if err != nil {
		return fmt.Errorf("failed to convert config to spec: %w", err)
	}

	if err := unstructured.SetNestedField(existing.Object, spec, "spec"); err != nil {
		return fmt.Errorf("failed to set spec field: %w", err)
	}

	_, err = s.client.Resource(s.gvr).Namespace(s.config.Namespace).Update(
		ctx, existing, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update DNSConfig CRD: %w", err)
	}

	s.mu.Lock()
	s.currentCfg = cfg
	s.mu.Unlock()

	return nil
}

// Watch starts watching for configuration changes.
func (s *CRDConfigStore) Watch(ctx context.Context) (<-chan *Config, error) {
	ch := make(chan *Config, 1)

	s.subMu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.subMu.Unlock()

	// Start watch loop if not already running
	s.startWatchLoop(ctx)

	return ch, nil
}

// Close closes the store and stops watching.
func (s *CRDConfigStore) Close() error {
	close(s.stopCh)
	if s.watchCancel != nil {
		s.watchCancel()
	}

	s.subMu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	s.subMu.Unlock()

	return nil
}

// UpdateStatus updates the status of the DNSConfig CRD.
func (s *CRDConfigStore) UpdateStatus(ctx context.Context, status DNSConfigStatus) error {
	existing, err := s.client.Resource(s.gvr).Namespace(s.config.Namespace).Get(
		ctx, s.config.ConfigName, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to get DNSConfig CRD: %w", err)
	}

	statusMap := map[string]interface{}{
		"lastApplied":  status.LastApplied.Format(time.RFC3339),
		"applied":      status.Applied,
		"message":      status.Message,
		"workersReady": int64(status.WorkersReady),
		"workersTotal": int64(status.WorkersTotal),
	}

	if err := unstructured.SetNestedField(existing.Object, statusMap, "status"); err != nil {
		return fmt.Errorf("failed to set status field: %w", err)
	}

	_, err = s.client.Resource(s.gvr).Namespace(s.config.Namespace).UpdateStatus(
		ctx, existing, metav1.UpdateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to update DNSConfig status: %w", err)
	}

	return nil
}

// startWatchLoop starts the watch loop in a goroutine.
func (s *CRDConfigStore) startWatchLoop(ctx context.Context) {
	watchCtx, cancel := context.WithCancel(ctx)
	s.watchCancel = cancel

	go func() {
		for {
			select {
			case <-s.stopCh:
				return
			case <-watchCtx.Done():
				return
			default:
				s.watchCRD(watchCtx)
			}
		}
	}()
}

// watchCRD watches for CRD changes.
func (s *CRDConfigStore) watchCRD(ctx context.Context) {
	s.mu.RLock()
	resourceVersion := s.lastVersion
	s.mu.RUnlock()

	watcher, err := s.client.Resource(s.gvr).Namespace(s.config.Namespace).Watch(
		ctx, metav1.ListOptions{
			FieldSelector:   fmt.Sprintf("metadata.name=%s", s.config.ConfigName),
			ResourceVersion: resourceVersion,
		},
	)
	if err != nil {
		// Log error and retry after interval
		time.Sleep(s.config.ResyncInterval)
		return
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				// Watch channel closed, will restart
				return
			}
			s.handleWatchEvent(event)
		}
	}
}

// handleWatchEvent handles a watch event.
func (s *CRDConfigStore) handleWatchEvent(event watch.Event) {
	switch event.Type {
	case watch.Added, watch.Modified:
		unstructuredObj, ok := event.Object.(*unstructured.Unstructured)
		if !ok {
			return
		}

		cfg, err := s.unstructuredToConfig(unstructuredObj)
		if err != nil {
			return
		}

		s.mu.Lock()
		s.currentCfg = cfg
		s.lastVersion = unstructuredObj.GetResourceVersion()
		s.mu.Unlock()

		// Notify subscribers
		s.notifySubscribers(cfg)

	case watch.Deleted:
		// Config was deleted - could reload defaults or take other action
		s.mu.Lock()
		s.currentCfg = nil
		s.mu.Unlock()
	}
}

// notifySubscribers sends config update to all subscribers.
func (s *CRDConfigStore) notifySubscribers(cfg *Config) {
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

// createCRD creates a new DNSConfig CRD.
func (s *CRDConfigStore) createCRD(ctx context.Context, cfg *Config) error {
	spec, err := s.configToSpec(cfg)
	if err != nil {
		return fmt.Errorf("failed to convert config to spec: %w", err)
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": fmt.Sprintf("%s/%s", CRDGroup, CRDVersion),
			"kind":       "DNSConfig",
			"metadata": map[string]interface{}{
				"name":      s.config.ConfigName,
				"namespace": s.config.Namespace,
			},
			"spec": spec,
		},
	}

	_, err = s.client.Resource(s.gvr).Namespace(s.config.Namespace).Create(
		ctx, obj, metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to create DNSConfig CRD: %w", err)
	}

	return nil
}

// unstructuredToConfig converts an unstructured CRD to Config.
func (s *CRDConfigStore) unstructuredToConfig(obj *unstructured.Unstructured) (*Config, error) {
	spec, found, err := unstructured.NestedMap(obj.Object, "spec")
	if err != nil || !found {
		return nil, fmt.Errorf("failed to get spec from CRD: %w", err)
	}

	// Convert to JSON then unmarshal to DNSConfigSpec
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal spec: %w", err)
	}

	var crdSpec DNSConfigSpec
	if err := json.Unmarshal(specJSON, &crdSpec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal spec: %w", err)
	}

	// Convert DNSConfigSpec to Config
	return s.specToConfig(&crdSpec), nil
}

// specToConfig converts DNSConfigSpec to Config.
func (s *CRDConfigStore) specToConfig(spec *DNSConfigSpec) *Config {
	cfg := DefaultConfig()

	// Server config
	if spec.Server.ListenAddress != "" {
		cfg.Server.ListenAddress = spec.Server.ListenAddress
	}
	if spec.Server.NumWorkers > 0 {
		cfg.Server.NumWorkers = spec.Server.NumWorkers
	}
	cfg.Server.EnableTCP = spec.Server.EnableTCP
	if spec.Server.PprofAddress != "" {
		cfg.Server.PprofAddress = spec.Server.PprofAddress
	}
	if spec.Server.GracefulShutdownTimeout > 0 {
		cfg.Server.GracefulShutdownTimeout = time.Duration(spec.Server.GracefulShutdownTimeout) * time.Second
	}
	if spec.Server.StatsReportInterval > 0 {
		cfg.Server.StatsReportInterval = time.Duration(spec.Server.StatsReportInterval) * time.Second
	}

	// Cache config
	if spec.Cache.MessageCache.MaxSizeMB > 0 {
		cfg.Cache.MessageCache.MaxSizeMB = spec.Cache.MessageCache.MaxSizeMB
	}
	if spec.Cache.MessageCache.NumShards > 0 {
		cfg.Cache.MessageCache.NumShards = spec.Cache.MessageCache.NumShards
	}
	if spec.Cache.RRsetCache.MaxSizeMB > 0 {
		cfg.Cache.RRsetCache.MaxSizeMB = spec.Cache.RRsetCache.MaxSizeMB
	}
	if spec.Cache.RRsetCache.NumShards > 0 {
		cfg.Cache.RRsetCache.NumShards = spec.Cache.RRsetCache.NumShards
	}
	cfg.Cache.Prefetch.Enabled = spec.Cache.Prefetch.Enabled
	if spec.Cache.Prefetch.ThresholdHits > 0 {
		cfg.Cache.Prefetch.ThresholdHits = int64(spec.Cache.Prefetch.ThresholdHits)
	}
	if spec.Cache.Prefetch.ThresholdTTLPercent > 0 {
		cfg.Cache.Prefetch.ThresholdTTLPercent = spec.Cache.Prefetch.ThresholdTTLPercent
	}
	if spec.Cache.MinTTLSecs > 0 {
		cfg.Cache.MinTTL = time.Duration(spec.Cache.MinTTLSecs) * time.Second
	}
	if spec.Cache.MaxTTLSecs > 0 {
		cfg.Cache.MaxTTL = time.Duration(spec.Cache.MaxTTLSecs) * time.Second
	}
	if spec.Cache.NegTTLSecs > 0 {
		cfg.Cache.NegativeTTL = time.Duration(spec.Cache.NegTTLSecs) * time.Second
	}

	// Resolver config
	if spec.Resolver.Mode != "" {
		cfg.Resolver.Mode = spec.Resolver.Mode
	}
	if len(spec.Resolver.Upstreams) > 0 {
		cfg.Resolver.Upstreams = spec.Resolver.Upstreams
	}
	if spec.Resolver.RootHintsFile != "" {
		cfg.Resolver.RootHintsFile = spec.Resolver.RootHintsFile
	}
	if spec.Resolver.MaxRecursionDepth > 0 {
		cfg.Resolver.MaxRecursionDepth = spec.Resolver.MaxRecursionDepth
	}
	if spec.Resolver.QueryTimeoutSecs > 0 {
		cfg.Resolver.QueryTimeout = time.Duration(spec.Resolver.QueryTimeoutSecs) * time.Second
	}
	cfg.Resolver.EnableCoalescing = spec.Resolver.EnableCoalescing
	if spec.Resolver.Parallel.NumParallel > 0 {
		cfg.Resolver.ParallelConfig.NumParallel = spec.Resolver.Parallel.NumParallel
	}
	cfg.Resolver.ParallelConfig.FallbackToRecursive = spec.Resolver.Parallel.FallbackToRecursive
	if len(spec.Resolver.Parallel.SuccessRcodes) > 0 {
		cfg.Resolver.ParallelConfig.SuccessRcodes = spec.Resolver.Parallel.SuccessRcodes
	}

	// Logging config
	if spec.Logging.Level != "" {
		cfg.Logging.Level = spec.Logging.Level
	}
	if spec.Logging.Format != "" {
		cfg.Logging.Format = spec.Logging.Format
	}
	cfg.Logging.EnableQueryLog = spec.Logging.EnableQueryLog

	// API config
	cfg.API.Enabled = spec.API.Enabled
	if spec.API.ListenAddress != "" {
		cfg.API.ListenAddress = spec.API.ListenAddress
	}
	if len(spec.API.CORSOrigins) > 0 {
		cfg.API.CORSOrigins = spec.API.CORSOrigins
	}

	return cfg
}

// configToSpec converts Config to a spec map for unstructured.
func (s *CRDConfigStore) configToSpec(cfg *Config) (map[string]interface{}, error) {
	spec := DNSConfigSpec{
		Server: ServerConfigSpec{
			ListenAddress:           cfg.Server.ListenAddress,
			NumWorkers:              cfg.Server.NumWorkers,
			EnableTCP:               cfg.Server.EnableTCP,
			PprofAddress:            cfg.Server.PprofAddress,
			GracefulShutdownTimeout: int(cfg.Server.GracefulShutdownTimeout.Seconds()),
			StatsReportInterval:     int(cfg.Server.StatsReportInterval.Seconds()),
		},
		Cache: CacheConfigSpec{
			MessageCache: MessageCacheSpec{
				MaxSizeMB: cfg.Cache.MessageCache.MaxSizeMB,
				NumShards: cfg.Cache.MessageCache.NumShards,
			},
			RRsetCache: RRsetCacheSpec{
				MaxSizeMB: cfg.Cache.RRsetCache.MaxSizeMB,
				NumShards: cfg.Cache.RRsetCache.NumShards,
			},
			Prefetch: PrefetchSpec{
				Enabled:             cfg.Cache.Prefetch.Enabled,
				ThresholdHits:       int(cfg.Cache.Prefetch.ThresholdHits),
				ThresholdTTLPercent: cfg.Cache.Prefetch.ThresholdTTLPercent,
			},
			MinTTLSecs: int(cfg.Cache.MinTTL.Seconds()),
			MaxTTLSecs: int(cfg.Cache.MaxTTL.Seconds()),
			NegTTLSecs: int(cfg.Cache.NegativeTTL.Seconds()),
		},
		Resolver: ResolverConfigSpec{
			Mode:              cfg.Resolver.Mode,
			Upstreams:         cfg.Resolver.Upstreams,
			RootHintsFile:     cfg.Resolver.RootHintsFile,
			MaxRecursionDepth: cfg.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  int(cfg.Resolver.QueryTimeout.Seconds()),
			EnableCoalescing:  cfg.Resolver.EnableCoalescing,
			Parallel: ParallelConfigSpec{
				NumParallel:         cfg.Resolver.ParallelConfig.NumParallel,
				FallbackToRecursive: cfg.Resolver.ParallelConfig.FallbackToRecursive,
				SuccessRcodes:       cfg.Resolver.ParallelConfig.SuccessRcodes,
			},
		},
		Logging: LoggingConfigSpec{
			Level:          cfg.Logging.Level,
			Format:         cfg.Logging.Format,
			EnableQueryLog: cfg.Logging.EnableQueryLog,
		},
		API: APIConfigSpec{
			Enabled:       cfg.API.Enabled,
			ListenAddress: cfg.API.ListenAddress,
			CORSOrigins:   cfg.API.CORSOrigins,
		},
	}

	// Convert to map via JSON
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}

	var specMap map[string]interface{}
	if err := json.Unmarshal(specJSON, &specMap); err != nil {
		return nil, err
	}

	return specMap, nil
}

// GetCurrentConfig returns the current cached configuration.
func (s *CRDConfigStore) GetCurrentConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentCfg
}
