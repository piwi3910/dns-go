package bridge

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/piwi3910/dns-go/pkg/config"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/server"
	"github.com/piwi3910/dns-go/pkg/zone"
)

// LocalService implements DNSService for in-process (standalone) mode.
// It wraps the existing Handler, ZoneManager, and UpstreamPool directly.
type LocalService struct {
	handler        *server.Handler
	zoneManager    *zone.Manager
	upstream       *resolver.UpstreamPool
	config         *config.Config
	startTime      time.Time
	configStore    config.ConfigStore
	watchCancel    context.CancelFunc
	restartManager *RestartManager
}

// LocalServiceConfig contains configuration for the local service.
type LocalServiceConfig struct {
	Handler     *server.Handler
	ZoneManager *zone.Manager
	Upstream    *resolver.UpstreamPool
	Config      *config.Config
	StartTime   time.Time
}

// NewLocalService creates a new LocalService wrapping the given components.
func NewLocalService(cfg LocalServiceConfig) *LocalService {
	return &LocalService{
		handler:        cfg.Handler,
		zoneManager:    cfg.ZoneManager,
		upstream:       cfg.Upstream,
		config:         cfg.Config,
		startTime:      cfg.StartTime,
		restartManager: DefaultRestartManager,
	}
}

// SetRestartManager sets a custom restart manager.
func (s *LocalService) SetRestartManager(rm *RestartManager) {
	s.restartManager = rm
}

// GetRestartManager returns the restart manager.
func (s *LocalService) GetRestartManager() *RestartManager {
	return s.restartManager
}

// Ensure LocalService implements DNSService
var _ DNSService = (*LocalService)(nil)

// GetStats returns current server statistics.
func (s *LocalService) GetStats(ctx context.Context) (*StatsResponse, error) {
	handlerStats := s.handler.GetStats()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Determine resolver mode string
	modeStr := "unknown"
	switch s.config.Resolver.Mode {
	case "forwarding":
		modeStr = "forwarding"
	case "recursive":
		modeStr = "recursive"
	case "parallel":
		modeStr = "parallel"
	}

	// Count zones
	zoneCount := 0
	totalRecords := 0
	if s.zoneManager != nil {
		origins := s.zoneManager.GetAllZones()
		zoneCount = len(origins)
		for _, origin := range origins {
			if z := s.zoneManager.GetZone(origin); z != nil {
				totalRecords += z.RecordCount()
			}
		}
	}

	return &StatsResponse{
		Server: ServerStats{
			Version:       "1.0.0",
			UptimeSeconds: time.Since(s.startTime).Seconds(),
			GoVersion:     runtime.Version(),
			NumCPU:        runtime.NumCPU(),
			NumGoroutines: runtime.NumGoroutine(),
			MemoryMB:      float64(memStats.Alloc) / 1024 / 1024,
		},
		Cache: CacheStats{
			MessageCache: CacheTypeStats{
				Hits:      handlerStats.MessageCache.Hits,
				Misses:    handlerStats.MessageCache.Misses,
				Evicts:    handlerStats.MessageCache.Evicts,
				HitRate:   handlerStats.MessageCache.HitRate,
				SizeBytes: handlerStats.MessageCache.Size,
			},
			RRsetCache: CacheTypeStats{
				Hits:      handlerStats.RRsetCache.Hits,
				Misses:    handlerStats.RRsetCache.Misses,
				Evicts:    handlerStats.RRsetCache.Evicts,
				HitRate:   handlerStats.RRsetCache.HitRate,
				SizeBytes: handlerStats.RRsetCache.Size,
			},
		},
		Resolver: ResolverStats{
			InFlightQueries: 0, // TODO: expose from resolver
			Mode:            modeStr,
		},
		Zones: ZonesStats{
			Count:        zoneCount,
			TotalRecords: totalRecords,
		},
	}, nil
}

// SubscribeStats returns a channel that receives stats updates.
func (s *LocalService) SubscribeStats(ctx context.Context) (<-chan *StatsResponse, error) {
	ch := make(chan *StatsResponse, 10)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		defer close(ch)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats, err := s.GetStats(ctx)
				if err != nil {
					continue
				}
				select {
				case ch <- stats:
				default:
					// Drop if buffer full
				}
			}
		}
	}()

	return ch, nil
}

// GetZones returns all configured zones.
func (s *LocalService) GetZones(ctx context.Context) ([]ZoneInfo, error) {
	if s.zoneManager == nil {
		return []ZoneInfo{}, nil
	}

	origins := s.zoneManager.GetAllZones()
	zones := make([]ZoneInfo, 0, len(origins))

	for _, origin := range origins {
		z := s.zoneManager.GetZone(origin)
		if z == nil {
			continue
		}

		zones = append(zones, ZoneInfo{
			Origin:       z.Origin,
			Serial:       z.GetSerial(),
			RecordCount:  z.RecordCount(),
			LastModified: z.LastModified,
			HasSOA:       z.SOA != nil,
		})
	}

	return zones, nil
}

// GetZone returns detailed information about a specific zone.
func (s *LocalService) GetZone(ctx context.Context, origin string) (*ZoneDetail, error) {
	if s.zoneManager == nil {
		return nil, fmt.Errorf("zone not found: %s", origin)
	}

	z := s.zoneManager.GetZone(origin)
	if z == nil {
		return nil, fmt.Errorf("zone not found: %s", origin)
	}

	detail := &ZoneDetail{
		Origin:      z.Origin,
		Serial:      z.GetSerial(),
		TransferACL: z.TransferACL,
		UpdateACL:   z.UpdateACL,
	}

	if z.SOA != nil {
		detail.SOA = &SOAInfo{
			PrimaryNS:  z.SOA.Ns,
			AdminEmail: z.SOA.Mbox,
			Serial:     z.SOA.Serial,
			Refresh:    z.SOA.Refresh,
			Retry:      z.SOA.Retry,
			Expire:     z.SOA.Expire,
			Minimum:    z.SOA.Minttl,
		}
	}

	// Get all records
	allRecords := z.GetAllRecordsOrdered()
	detail.Records = make([]RecordInfo, 0, len(allRecords))
	for _, rr := range allRecords {
		detail.Records = append(detail.Records, RecordInfo{
			Name: rr.Header().Name,
			Type: typeToString(rr.Header().Rrtype),
			TTL:  rr.Header().Ttl,
			Data: rr.String(),
		})
	}

	return detail, nil
}

// CreateZone creates a new zone.
func (s *LocalService) CreateZone(ctx context.Context, req CreateZoneRequest) (*ZoneDetail, error) {
	if s.zoneManager == nil {
		return nil, fmt.Errorf("zone manager not available")
	}

	if req.Origin == "" {
		return nil, fmt.Errorf("origin is required")
	}

	z := zone.NewZone(zone.Config{
		Origin:      req.Origin,
		TransferACL: req.TransferACL,
		UpdateACL:   req.UpdateACL,
	})

	s.zoneManager.AddZone(z)

	return &ZoneDetail{
		Origin:      z.Origin,
		Serial:      z.GetSerial(),
		TransferACL: z.TransferACL,
		UpdateACL:   z.UpdateACL,
		Records:     []RecordInfo{},
	}, nil
}

// DeleteZone removes a zone.
func (s *LocalService) DeleteZone(ctx context.Context, origin string) error {
	if s.zoneManager == nil {
		return fmt.Errorf("zone not found: %s", origin)
	}

	s.zoneManager.RemoveZone(origin)
	return nil
}

// GetUpstreams returns the list of configured upstream servers.
func (s *LocalService) GetUpstreams(ctx context.Context) ([]UpstreamInfo, error) {
	upstreams := s.upstream.GetUpstreams()
	stats := s.upstream.GetStats()

	upstreamInfos := make([]UpstreamInfo, 0, len(upstreams))
	for _, addr := range upstreams {
		upstreamInfos = append(upstreamInfos, UpstreamInfo{
			Address: addr,
			Healthy: true,
		})
	}

	// Enrich with stats from infra cache
	for i, stat := range stats {
		if i < len(upstreamInfos) {
			upstreamInfos[i].RTTMS = stat.RTT
			upstreamInfos[i].Failures = stat.Failures
			upstreamInfos[i].InFlight = stat.InFlight
			upstreamInfos[i].LastSuccess = stat.LastSuccess
			upstreamInfos[i].LastFailure = stat.LastFailure
			upstreamInfos[i].TotalQueries = stat.TotalQueries
			upstreamInfos[i].TotalFailures = stat.TotalFailures
			upstreamInfos[i].FailureRate = stat.FailureRate
			upstreamInfos[i].Score = stat.Score
			upstreamInfos[i].Healthy = stat.FailureRate < 0.5
		}
	}

	return upstreamInfos, nil
}

// SetUpstreams updates the list of upstream servers.
func (s *LocalService) SetUpstreams(ctx context.Context, upstreams []string) error {
	if len(upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	s.upstream.SetUpstreams(upstreams)
	return nil
}

// GetCacheStats returns cache statistics.
func (s *LocalService) GetCacheStats(ctx context.Context) (*CacheStatsResponse, error) {
	stats := s.handler.GetStats()

	return &CacheStatsResponse{
		MessageCache: CacheTypeStats{
			Hits:      stats.MessageCache.Hits,
			Misses:    stats.MessageCache.Misses,
			Evicts:    stats.MessageCache.Evicts,
			HitRate:   stats.MessageCache.HitRate,
			SizeBytes: stats.MessageCache.Size,
		},
		RRsetCache: CacheTypeStats{
			Hits:      stats.RRsetCache.Hits,
			Misses:    stats.RRsetCache.Misses,
			Evicts:    stats.RRsetCache.Evicts,
			HitRate:   stats.RRsetCache.HitRate,
			SizeBytes: stats.RRsetCache.Size,
		},
		InfraCache: InfraCacheInfo{
			ServerCount: len(s.upstream.GetUpstreams()),
		},
	}, nil
}

// ClearCache clears the specified cache type.
func (s *LocalService) ClearCache(ctx context.Context, cacheType string) ([]string, error) {
	var cleared []string

	switch cacheType {
	case "all":
		s.handler.ClearCaches()
		cleared = []string{"message", "rrset", "infra"}
	case "message":
		s.handler.ClearCaches() // TODO: Add individual cache clear methods
		cleared = []string{"message"}
	case "rrset":
		s.handler.ClearCaches()
		cleared = []string{"rrset"}
	case "infra":
		s.handler.ClearCaches()
		cleared = []string{"infra"}
	default:
		return nil, fmt.Errorf("invalid cache type: %s", cacheType)
	}

	return cleared, nil
}

// GetConfig returns the current configuration.
func (s *LocalService) GetConfig(ctx context.Context) (*ConfigResponse, error) {
	cfg := s.config

	return &ConfigResponse{
		Server: ServerConfig{
			ListenAddress:               cfg.Server.ListenAddress,
			NumWorkers:                  cfg.Server.NumWorkers,
			EnableTCP:                   cfg.Server.EnableTCP,
			PprofAddress:                cfg.Server.PprofAddress,
			GracefulShutdownTimeoutSecs: int(cfg.Server.GracefulShutdownTimeout.Seconds()),
			StatsReportIntervalSecs:     int(cfg.Server.StatsReportInterval.Seconds()),
		},
		Cache: CacheConfig{
			MessageCache: MessageCacheConfig{
				MaxSizeMB: cfg.Cache.MessageCache.MaxSizeMB,
				NumShards: cfg.Cache.MessageCache.NumShards,
			},
			RRsetCache: RRsetCacheConfig{
				MaxSizeMB: cfg.Cache.RRsetCache.MaxSizeMB,
				NumShards: cfg.Cache.RRsetCache.NumShards,
			},
			Prefetch: PrefetchConfig{
				Enabled:             cfg.Cache.Prefetch.Enabled,
				ThresholdHits:       cfg.Cache.Prefetch.ThresholdHits,
				ThresholdTTLPercent: cfg.Cache.Prefetch.ThresholdTTLPercent,
			},
			MinTTLSecs: int(cfg.Cache.MinTTL.Seconds()),
			MaxTTLSecs: int(cfg.Cache.MaxTTL.Seconds()),
			NegTTLSecs: int(cfg.Cache.NegativeTTL.Seconds()),
		},
		Resolver: ResolverConfig{
			Mode:              cfg.Resolver.Mode,
			Upstreams:         cfg.Resolver.Upstreams,
			RootHintsFile:     cfg.Resolver.RootHintsFile,
			MaxRecursionDepth: cfg.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  int(cfg.Resolver.QueryTimeout.Seconds()),
			EnableCoalescing:  cfg.Resolver.EnableCoalescing,
			Parallel: ParallelConfig{
				NumParallel:         cfg.Resolver.ParallelConfig.NumParallel,
				FallbackToRecursive: cfg.Resolver.ParallelConfig.FallbackToRecursive,
				SuccessRcodes:       cfg.Resolver.ParallelConfig.SuccessRcodes,
			},
		},
		Logging: LoggingConfig{
			Level:          cfg.Logging.Level,
			Format:         cfg.Logging.Format,
			EnableQueryLog: cfg.Logging.EnableQueryLog,
		},
		API: APIConfig{
			Enabled:       cfg.API.Enabled,
			ListenAddress: cfg.API.ListenAddress,
			CORSOrigins:   cfg.API.CORSOrigins,
		},
	}, nil
}

// UpdateConfig updates the configuration and propagates changes to components.
func (s *LocalService) UpdateConfig(ctx context.Context, req UpdateConfigRequest) (bool, error) {
	requiresRestart := false

	// Handle cache configuration updates
	if req.Cache != nil {
		if req.Cache.Prefetch != nil {
			if req.Cache.Prefetch.Enabled != nil {
				s.config.Cache.Prefetch.Enabled = *req.Cache.Prefetch.Enabled
			}
			if req.Cache.Prefetch.ThresholdHits != nil {
				s.config.Cache.Prefetch.ThresholdHits = *req.Cache.Prefetch.ThresholdHits
			}
			if req.Cache.Prefetch.ThresholdTTLPercent != nil {
				s.config.Cache.Prefetch.ThresholdTTLPercent = *req.Cache.Prefetch.ThresholdTTLPercent
			}
		}
		if req.Cache.MinTTLSecs != nil {
			s.config.Cache.MinTTL = time.Duration(*req.Cache.MinTTLSecs) * time.Second
		}
		if req.Cache.MaxTTLSecs != nil {
			s.config.Cache.MaxTTL = time.Duration(*req.Cache.MaxTTLSecs) * time.Second
		}
		if req.Cache.NegTTLSecs != nil {
			s.config.Cache.NegativeTTL = time.Duration(*req.Cache.NegTTLSecs) * time.Second
		}

		// Propagate TTL changes to the actual caches
		s.handler.UpdateCacheTTL(s.config.Cache.MinTTL, s.config.Cache.MaxTTL)
	}

	// Handle resolver configuration updates
	if req.Resolver != nil {
		if req.Resolver.Upstreams != nil {
			s.upstream.SetUpstreams(req.Resolver.Upstreams)
			s.config.Resolver.Upstreams = req.Resolver.Upstreams
		}
		if req.Resolver.Mode != nil {
			s.config.Resolver.Mode = *req.Resolver.Mode
			requiresRestart = true // Mode change requires restart
		}
		if req.Resolver.EnableCoalescing != nil {
			s.config.Resolver.EnableCoalescing = *req.Resolver.EnableCoalescing
			// Propagate coalescing setting to the resolver
			if r := s.handler.GetResolver(); r != nil {
				r.SetCoalescing(*req.Resolver.EnableCoalescing)
			}
		}
		if req.Resolver.Parallel != nil {
			if req.Resolver.Parallel.NumParallel != nil {
				s.config.Resolver.ParallelConfig.NumParallel = *req.Resolver.Parallel.NumParallel
			}
			if req.Resolver.Parallel.FallbackToRecursive != nil {
				s.config.Resolver.ParallelConfig.FallbackToRecursive = *req.Resolver.Parallel.FallbackToRecursive
			}
			// Propagate parallel config to the resolver
			if r := s.handler.GetResolver(); r != nil {
				r.SetParallelConfig(
					s.config.Resolver.ParallelConfig.NumParallel,
					s.config.Resolver.ParallelConfig.FallbackToRecursive,
				)
			}
		}
	}

	// Handle logging configuration updates
	if req.Logging != nil {
		if req.Logging.Level != nil {
			s.config.Logging.Level = *req.Logging.Level
		}
		if req.Logging.EnableQueryLog != nil {
			s.config.Logging.EnableQueryLog = *req.Logging.EnableQueryLog
		}
	}

	// Persist config changes to the config store if available
	if s.configStore != nil {
		if err := s.configStore.Save(ctx, s.config); err != nil {
			// Log error but don't fail - the in-memory config is already updated
			// The config will be persisted on next successful save
			fmt.Printf("Warning: failed to persist config: %v\n", err)
		}
	}

	// If restart is required, trigger it via the restart manager
	if requiresRestart && s.restartManager != nil {
		s.restartManager.RequestRestart("Configuration change requires restart (resolver mode changed)")
	}

	return requiresRestart, nil
}

// SetConfigStore sets the config store and starts watching for changes.
func (s *LocalService) SetConfigStore(store config.ConfigStore) {
	s.configStore = store
}

// StartConfigWatch starts watching the config store for changes.
// When changes are detected, they are automatically applied to the running service.
func (s *LocalService) StartConfigWatch(ctx context.Context) error {
	if s.configStore == nil {
		return fmt.Errorf("no config store set")
	}

	watchCh, err := s.configStore.Watch(ctx)
	if err != nil {
		return fmt.Errorf("failed to start config watch: %w", err)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	s.watchCancel = cancel

	go s.configWatchLoop(watchCtx, watchCh)
	return nil
}

// StopConfigWatch stops watching for config changes.
func (s *LocalService) StopConfigWatch() {
	if s.watchCancel != nil {
		s.watchCancel()
		s.watchCancel = nil
	}
}

// configWatchLoop handles config updates from the config store.
func (s *LocalService) configWatchLoop(ctx context.Context, watchCh <-chan *config.Config) {
	for {
		select {
		case <-ctx.Done():
			return
		case newCfg, ok := <-watchCh:
			if !ok {
				return
			}
			s.applyConfigUpdate(ctx, newCfg)
		}
	}
}

// applyConfigUpdate applies a new configuration to the running service.
func (s *LocalService) applyConfigUpdate(ctx context.Context, newCfg *config.Config) {
	if newCfg == nil {
		return
	}

	// Build update request from config diff
	req := s.buildUpdateRequest(newCfg)

	// Apply the update
	_, _ = s.UpdateConfig(ctx, req)

	// Update internal config reference
	s.config = newCfg
}

// buildUpdateRequest builds an UpdateConfigRequest from a new config.
func (s *LocalService) buildUpdateRequest(newCfg *config.Config) UpdateConfigRequest {
	req := UpdateConfigRequest{}

	// Cache updates
	minTTL := int(newCfg.Cache.MinTTL.Seconds())
	maxTTL := int(newCfg.Cache.MaxTTL.Seconds())
	negTTL := int(newCfg.Cache.NegativeTTL.Seconds())
	prefetchEnabled := newCfg.Cache.Prefetch.Enabled
	prefetchHits := newCfg.Cache.Prefetch.ThresholdHits
	prefetchTTL := newCfg.Cache.Prefetch.ThresholdTTLPercent

	req.Cache = &CacheConfigUpdate{
		MinTTLSecs: &minTTL,
		MaxTTLSecs: &maxTTL,
		NegTTLSecs: &negTTL,
		Prefetch: &PrefetchConfigUpdate{
			Enabled:             &prefetchEnabled,
			ThresholdHits:       &prefetchHits,
			ThresholdTTLPercent: &prefetchTTL,
		},
	}

	// Resolver updates
	mode := newCfg.Resolver.Mode
	coalescing := newCfg.Resolver.EnableCoalescing
	numParallel := newCfg.Resolver.ParallelConfig.NumParallel
	fallback := newCfg.Resolver.ParallelConfig.FallbackToRecursive

	req.Resolver = &ResolverConfigUpdate{
		Upstreams:        newCfg.Resolver.Upstreams,
		Mode:             &mode,
		EnableCoalescing: &coalescing,
		Parallel: &ParallelConfigUpdate{
			NumParallel:         &numParallel,
			FallbackToRecursive: &fallback,
		},
	}

	// Logging updates
	level := newCfg.Logging.Level
	queryLog := newCfg.Logging.EnableQueryLog

	req.Logging = &LoggingConfigUpdate{
		Level:          &level,
		EnableQueryLog: &queryLog,
	}

	return req
}

// typeToString converts DNS type to string
func typeToString(t uint16) string {
	types := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		257: "CAA",
	}
	if s, ok := types[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}
