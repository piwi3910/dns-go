// Package control provides the control plane implementation for managing
// distributed DNS workers.
package control

import (
	"context"
	"time"

	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// WorkerRegistry manages worker registration and discovery.
type WorkerRegistry interface {
	// Register adds a new worker to the registry.
	Register(ctx context.Context, info *WorkerInfo) error

	// Deregister removes a worker from the registry.
	Deregister(ctx context.Context, workerID string) error

	// Get retrieves information about a specific worker.
	Get(ctx context.Context, workerID string) (*WorkerInfo, error)

	// List returns all registered workers, optionally filtered by labels.
	List(ctx context.Context, labelSelector map[string]string) ([]*WorkerInfo, error)

	// UpdateHeartbeat updates the last heartbeat time and stats for a worker.
	UpdateHeartbeat(ctx context.Context, workerID string, stats *pb.WorkerStats, health *pb.HealthStatus) error

	// GetStaleWorkers returns workers that haven't sent a heartbeat within the timeout.
	GetStaleWorkers(ctx context.Context, timeout time.Duration) ([]*WorkerInfo, error)
}

// ZoneSyncManager handles zone distribution to workers.
type ZoneSyncManager interface {
	// AssignZone assigns a zone to a worker.
	AssignZone(ctx context.Context, workerID, origin string, primary bool) error

	// UnassignZone removes a zone assignment from a worker.
	UnassignZone(ctx context.Context, workerID, origin string) error

	// GetAssignments returns all zone assignments for a worker.
	GetAssignments(ctx context.Context, workerID string) ([]*ZoneAssignment, error)

	// GetZone returns zone data for a specific zone.
	GetZone(ctx context.Context, origin string) (*pb.ZoneData, error)

	// GetWorkersForZone returns all workers that serve a zone.
	GetWorkersForZone(origin string) []string

	// NotifyZoneUpdate broadcasts a zone update to all subscribed workers.
	NotifyZoneUpdate(ctx context.Context, update *pb.ZoneUpdate) error

	// Subscribe registers a channel to receive zone updates for a worker.
	Subscribe(workerID string) (<-chan *pb.ZoneUpdate, error)

	// Unsubscribe removes a worker's subscription to zone updates.
	Unsubscribe(workerID string)
}

// ConfigSyncManager handles configuration distribution to workers.
type ConfigSyncManager interface {
	// GetConfig returns the current configuration for a worker.
	GetConfig(ctx context.Context, workerID string) (*pb.WorkerConfig, error)

	// SetGlobalConfig sets the base configuration for all workers.
	SetGlobalConfig(ctx context.Context, config *pb.WorkerConfig) error

	// SetWorkerConfig sets a worker-specific configuration override.
	SetWorkerConfig(ctx context.Context, workerID string, config *pb.WorkerConfig) error

	// ReloadConfig triggers a configuration reload for a worker.
	ReloadConfig(ctx context.Context, workerID string) error

	// NotifyConfigUpdate sends a config update to a specific worker.
	NotifyConfigUpdate(ctx context.Context, workerID string, update *pb.ConfigUpdate) error

	// Subscribe registers a channel to receive config updates for a worker.
	Subscribe(workerID string) (<-chan *pb.ConfigUpdate, error)

	// Unsubscribe removes a worker's subscription to config updates.
	Unsubscribe(workerID string)
}

// StatsAggregator collects and aggregates stats from workers.
type StatsAggregator interface {
	// RecordStats records stats from a worker.
	RecordStats(ctx context.Context, workerID string, stats *pb.WorkerStats, health *pb.HealthStatus) error

	// RecordZoneStats records zone-specific statistics.
	RecordZoneStats(ctx context.Context, workerID string, zoneStats []*pb.ZoneStats) error

	// RecordUpstreamStats records upstream server statistics.
	RecordUpstreamStats(ctx context.Context, workerID string, upstreamStats []*pb.UpstreamStats) error

	// GetAggregatedStats returns aggregated stats across all workers.
	GetAggregatedStats(ctx context.Context) (*AggregatedStats, error)

	// GetWorkerStats returns stats for a specific worker.
	GetWorkerStats(ctx context.Context, workerID string) (*pb.WorkerStats, error)

	// RemoveWorker removes a worker's stats from the aggregator.
	RemoveWorker(workerID string)

	// Subscribe creates a subscription for real-time stats updates.
	Subscribe(subscriberID string) (<-chan *AggregatedStats, error)

	// Unsubscribe removes a subscription.
	Unsubscribe(subscriberID string)
}

// WorkerInfo contains information about a registered worker.
type WorkerInfo struct {
	ID            string
	Hostname      string
	ListenAddress string
	Version       string
	Capabilities  []string
	Labels        map[string]string
	RegisteredAt  time.Time
	LastHeartbeat time.Time
	Health        *pb.HealthStatus
	Stats         *pb.WorkerStats
	AssignedZones []string
}

// ZoneAssignment represents a zone assigned to a worker.
type ZoneAssignment struct {
	Origin  string
	Serial  uint32
	Primary bool
}

// AggregatedStats contains stats aggregated across all workers.
type AggregatedStats struct {
	Timestamp           time.Time
	WorkerCount         int
	HealthyWorkers      int
	DegradedWorkers     int
	UnhealthyWorkers    int
	TotalQueries        int64
	TotalQPS            int64
	TotalCacheHits      int64
	TotalCacheMisses    int64
	OverallCacheHitRate float64
	PerZoneStats        map[string]*ZoneAggregatedStats
	PerUpstreamStats    map[string]*UpstreamAggregatedStats
}

// ZoneAggregatedStats contains aggregated stats for a zone.
type ZoneAggregatedStats struct {
	Origin        string
	TotalQueries  int64
	TotalNXDomain int64
	TotalServfail int64
}

// UpstreamAggregatedStats contains aggregated stats for an upstream.
type UpstreamAggregatedStats struct {
	Address       string
	TotalQueries  int64
	TotalFailures int64
	AverageRTTMs  float64
}
