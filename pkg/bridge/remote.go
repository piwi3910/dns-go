// Package bridge provides the abstraction layer between the API/management plane
// and the DNS worker/data plane.
package bridge

import (
	"context"
	"fmt"
	"time"

	"github.com/piwi3910/dns-go/pkg/control"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// RemoteService implements DNSService by connecting to a control plane
// that manages distributed DNS workers.
type RemoteService struct {
	conn       *grpc.ClientConn
	ctrlClient pb.ControlPlaneClient
	mgmtClient pb.WorkerManagementClient

	// Control plane components (when running embedded)
	registry       control.WorkerRegistry
	zoneSyncMgr    control.ZoneSyncManager
	configSyncMgr  control.ConfigSyncManager
	statsAggregator control.StatsAggregator
}

// RemoteServiceConfig contains configuration for the remote service.
type RemoteServiceConfig struct {
	// ControlPlaneAddress is the address of the control plane gRPC server.
	ControlPlaneAddress string

	// For embedded mode - use these instead of connecting remotely
	Registry       control.WorkerRegistry
	ZoneSyncMgr    control.ZoneSyncManager
	ConfigSyncMgr  control.ConfigSyncManager
	StatsAggregator control.StatsAggregator
}

// NewRemoteService creates a new remote DNS service.
func NewRemoteService(cfg RemoteServiceConfig) (*RemoteService, error) {
	service := &RemoteService{
		registry:        cfg.Registry,
		zoneSyncMgr:     cfg.ZoneSyncMgr,
		configSyncMgr:   cfg.ConfigSyncMgr,
		statsAggregator: cfg.StatsAggregator,
	}

	// If we have embedded components, use them directly
	if cfg.Registry != nil {
		return service, nil
	}

	// Otherwise, connect to remote control plane
	if cfg.ControlPlaneAddress == "" {
		return nil, fmt.Errorf("control plane address is required")
	}

	conn, err := grpc.Dial(
		cfg.ControlPlaneAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control plane: %w", err)
	}

	service.conn = conn
	service.ctrlClient = pb.NewControlPlaneClient(conn)
	service.mgmtClient = pb.NewWorkerManagementClient(conn)

	return service, nil
}

// Close closes the connection to the control plane.
func (s *RemoteService) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// GetStats returns aggregated statistics from all workers.
func (s *RemoteService) GetStats(ctx context.Context) (*StatsResponse, error) {
	if s.statsAggregator != nil {
		aggStats, err := s.statsAggregator.GetAggregatedStats(ctx)
		if err != nil {
			return nil, err
		}
		return convertAggregatedStats(aggStats), nil
	}

	// Remote mode - would need to call mgmtClient
	return nil, fmt.Errorf("remote stats not implemented")
}

// SubscribeStats returns a channel that receives stats updates.
func (s *RemoteService) SubscribeStats(ctx context.Context) (<-chan *StatsResponse, error) {
	if s.statsAggregator != nil {
		aggCh, err := s.statsAggregator.Subscribe("api-subscriber")
		if err != nil {
			return nil, err
		}

		statsCh := make(chan *StatsResponse, 10)
		go func() {
			defer close(statsCh)
			for {
				select {
				case <-ctx.Done():
					s.statsAggregator.Unsubscribe("api-subscriber")
					return
				case aggStats, ok := <-aggCh:
					if !ok {
						return
					}
					stats := convertAggregatedStats(aggStats)
					select {
					case statsCh <- stats:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
		return statsCh, nil
	}

	return nil, fmt.Errorf("remote stats subscription not implemented")
}

// GetZones returns all zones managed by workers.
func (s *RemoteService) GetZones(ctx context.Context) ([]ZoneInfo, error) {
	// In distributed mode, zones are managed by the control plane
	// For now, return empty list - would need zone storage in control plane
	return []ZoneInfo{}, nil
}

// GetZone returns detailed information about a specific zone.
func (s *RemoteService) GetZone(ctx context.Context, origin string) (*ZoneDetail, error) {
	if s.zoneSyncMgr != nil {
		zone, err := s.zoneSyncMgr.GetZone(ctx, origin)
		if err != nil {
			return nil, err
		}
		return convertZoneData(zone), nil
	}

	return nil, fmt.Errorf("zone not found")
}

// CreateZone creates a new zone.
func (s *RemoteService) CreateZone(ctx context.Context, req CreateZoneRequest) (*ZoneDetail, error) {
	// Would need to create zone in control plane and distribute to workers
	return nil, fmt.Errorf("create zone not implemented in distributed mode")
}

// DeleteZone removes a zone.
func (s *RemoteService) DeleteZone(ctx context.Context, origin string) error {
	// Would need to delete zone from control plane and notify workers
	return fmt.Errorf("delete zone not implemented in distributed mode")
}

// GetUpstreams returns upstream servers (from config).
func (s *RemoteService) GetUpstreams(ctx context.Context) ([]UpstreamInfo, error) {
	// In distributed mode, upstream config is per-worker
	return []UpstreamInfo{}, nil
}

// SetUpstreams updates upstream servers for all workers.
func (s *RemoteService) SetUpstreams(ctx context.Context, upstreams []string) error {
	// Would need to update config and push to all workers
	return fmt.Errorf("set upstreams not implemented in distributed mode")
}

// GetCacheStats returns cache statistics (aggregated from workers).
func (s *RemoteService) GetCacheStats(ctx context.Context) (*CacheStatsResponse, error) {
	stats, err := s.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	return &CacheStatsResponse{
		MessageCache: stats.Cache.MessageCache,
		RRsetCache:   stats.Cache.RRsetCache,
	}, nil
}

// ClearCache clears cache on all workers.
func (s *RemoteService) ClearCache(ctx context.Context, cacheType string) ([]string, error) {
	// Would need to send CLEAR_CACHE command to all workers
	return nil, fmt.Errorf("clear cache not implemented in distributed mode")
}

// GetConfig returns the global configuration.
func (s *RemoteService) GetConfig(ctx context.Context) (*ConfigResponse, error) {
	// Return default config for now
	return &ConfigResponse{
		Server: ServerConfig{
			ListenAddress: "distributed",
			NumWorkers:    0,
			EnableTCP:     true,
		},
		Resolver: ResolverConfig{
			Mode: "forwarding",
		},
	}, nil
}

// UpdateConfig updates the global configuration.
func (s *RemoteService) UpdateConfig(ctx context.Context, req UpdateConfigRequest) (bool, error) {
	// Would need to update config in control plane and push to workers
	return false, fmt.Errorf("update config not implemented in distributed mode")
}

// convertAggregatedStats converts control.AggregatedStats to bridge.StatsResponse.
func convertAggregatedStats(aggStats *control.AggregatedStats) *StatsResponse {
	if aggStats == nil {
		return &StatsResponse{}
	}

	return &StatsResponse{
		Server: ServerStats{
			Version:       "distributed",
			UptimeSeconds: time.Since(aggStats.Timestamp).Seconds(),
			NumGoroutines: aggStats.WorkerCount,
		},
		Cache: CacheStats{
			MessageCache: CacheTypeStats{
				Hits:    aggStats.TotalCacheHits,
				Misses:  aggStats.TotalCacheMisses,
				HitRate: aggStats.OverallCacheHitRate,
			},
		},
		Resolver: ResolverStats{
			Mode: "distributed",
		},
	}
}

// convertZoneData converts pb.ZoneData to bridge.ZoneDetail.
func convertZoneData(zone *pb.ZoneData) *ZoneDetail {
	if zone == nil {
		return nil
	}

	detail := &ZoneDetail{
		Origin:      zone.Origin,
		Serial:      zone.Serial,
		TransferACL: zone.TransferAcl,
		UpdateACL:   zone.UpdateAcl,
	}

	if zone.Soa != nil {
		detail.SOA = &SOAInfo{
			PrimaryNS:  zone.Soa.PrimaryNs,
			AdminEmail: zone.Soa.AdminEmail,
			Serial:     zone.Soa.Serial,
			Refresh:    zone.Soa.Refresh,
			Retry:      zone.Soa.Retry,
			Expire:     zone.Soa.Expire,
			Minimum:    zone.Soa.Minimum,
		}
	}

	for _, rec := range zone.Records {
		detail.Records = append(detail.Records, RecordInfo{
			Name: rec.Name,
			Type: rec.Type,
			TTL:  rec.Ttl,
			Data: rec.Rdata,
		})
	}

	return detail
}

// Ensure RemoteService implements DNSService
var _ DNSService = (*RemoteService)(nil)
