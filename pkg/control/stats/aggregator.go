// Package stats provides statistics aggregation for the control plane.
package stats

import (
	"context"
	"sync"
	"time"

	"github.com/piwi3910/dns-go/pkg/control"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// Aggregator collects and aggregates statistics from all workers.
type Aggregator struct {
	mu sync.RWMutex

	// workerStats stores the latest stats per worker
	workerStats map[string]*workerStatsEntry

	// zoneStats stores aggregated zone statistics
	zoneStats map[string]*aggregatedZoneStats

	// upstreamStats stores aggregated upstream statistics
	upstreamStats map[string]*aggregatedUpstreamStats

	// statsHistory stores historical snapshots
	statsHistory []*control.AggregatedStats

	// maxHistorySize limits the number of historical snapshots
	maxHistorySize int

	// subscribers for real-time stats updates
	subscribers   map[string]chan *control.AggregatedStats
	subscriberMu  sync.RWMutex
}

type workerStatsEntry struct {
	workerID  string
	stats     *pb.WorkerStats
	health    *pb.HealthStatus
	timestamp time.Time
}

type aggregatedZoneStats struct {
	origin    string
	queries   int64
	nxdomain  int64
	servfail  int64
	timestamp time.Time
}

type aggregatedUpstreamStats struct {
	address   string
	queries   int64
	failures  int64
	avgRTTMs  float64
	timestamp time.Time
}

// NewAggregator creates a new statistics aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		workerStats:    make(map[string]*workerStatsEntry),
		zoneStats:      make(map[string]*aggregatedZoneStats),
		upstreamStats:  make(map[string]*aggregatedUpstreamStats),
		statsHistory:   make([]*control.AggregatedStats, 0),
		maxHistorySize: 100, // Keep last 100 snapshots
		subscribers:    make(map[string]chan *control.AggregatedStats),
	}
}

// RecordStats records statistics from a worker.
func (a *Aggregator) RecordStats(ctx context.Context, workerID string, stats *pb.WorkerStats, health *pb.HealthStatus) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.workerStats[workerID] = &workerStatsEntry{
		workerID:  workerID,
		stats:     stats,
		health:    health,
		timestamp: time.Now(),
	}

	return nil
}

// RecordZoneStats records zone-specific statistics.
func (a *Aggregator) RecordZoneStats(ctx context.Context, workerID string, zoneStats []*pb.ZoneStats) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, zs := range zoneStats {
		existing, exists := a.zoneStats[zs.Origin]
		if !exists {
			existing = &aggregatedZoneStats{origin: zs.Origin}
			a.zoneStats[zs.Origin] = existing
		}
		// Aggregate stats (these are cumulative from workers)
		existing.queries += zs.Queries
		existing.nxdomain += zs.Nxdomain
		existing.servfail += zs.Servfail
		existing.timestamp = time.Now()
	}

	return nil
}

// RecordUpstreamStats records upstream server statistics.
func (a *Aggregator) RecordUpstreamStats(ctx context.Context, workerID string, upstreamStats []*pb.UpstreamStats) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, us := range upstreamStats {
		existing, exists := a.upstreamStats[us.Address]
		if !exists {
			existing = &aggregatedUpstreamStats{address: us.Address}
			a.upstreamStats[us.Address] = existing
		}
		// Aggregate stats
		existing.queries += us.Queries
		existing.failures += us.Failures
		// Running average for RTT
		if existing.queries > 0 {
			existing.avgRTTMs = (existing.avgRTTMs + us.AvgRttMs) / 2
		} else {
			existing.avgRTTMs = us.AvgRttMs
		}
		existing.timestamp = time.Now()
	}

	return nil
}

// GetAggregatedStats returns current aggregated statistics.
func (a *Aggregator) GetAggregatedStats(ctx context.Context) (*control.AggregatedStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := &control.AggregatedStats{
		Timestamp:   time.Now(),
		WorkerCount: len(a.workerStats),
	}

	// Aggregate worker stats
	for _, entry := range a.workerStats {
		if entry.stats != nil {
			stats.TotalQueries += entry.stats.QueriesTotal
			stats.TotalCacheHits += int64(float64(entry.stats.QueriesTotal) * entry.stats.CacheHitRate)
			stats.TotalCacheMisses += int64(float64(entry.stats.QueriesTotal) * (1 - entry.stats.CacheHitRate))
			stats.TotalQPS += entry.stats.QueriesPerSecond
		}

		if entry.health != nil {
			switch entry.health.Status {
			case pb.HealthStatus_HEALTHY:
				stats.HealthyWorkers++
			case pb.HealthStatus_DEGRADED:
				stats.DegradedWorkers++
			case pb.HealthStatus_UNHEALTHY:
				stats.UnhealthyWorkers++
			}
		}
	}

	// Calculate overall cache hit rate
	totalCacheOps := stats.TotalCacheHits + stats.TotalCacheMisses
	if totalCacheOps > 0 {
		stats.OverallCacheHitRate = float64(stats.TotalCacheHits) / float64(totalCacheOps)
	}

	return stats, nil
}

// GetWorkerStats returns statistics for a specific worker.
func (a *Aggregator) GetWorkerStats(ctx context.Context, workerID string) (*pb.WorkerStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entry, exists := a.workerStats[workerID]
	if !exists {
		return nil, nil
	}

	return entry.stats, nil
}

// GetAllWorkerStats returns statistics for all workers.
func (a *Aggregator) GetAllWorkerStats(ctx context.Context) (map[string]*pb.WorkerStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]*pb.WorkerStats, len(a.workerStats))
	for workerID, entry := range a.workerStats {
		result[workerID] = entry.stats
	}

	return result, nil
}

// Subscribe creates a subscription for real-time stats updates.
func (a *Aggregator) Subscribe(subscriberID string) (<-chan *control.AggregatedStats, error) {
	a.subscriberMu.Lock()
	defer a.subscriberMu.Unlock()

	ch := make(chan *control.AggregatedStats, 10)
	a.subscribers[subscriberID] = ch

	return ch, nil
}

// Unsubscribe removes a subscription.
func (a *Aggregator) Unsubscribe(subscriberID string) {
	a.subscriberMu.Lock()
	defer a.subscriberMu.Unlock()

	if ch, exists := a.subscribers[subscriberID]; exists {
		close(ch)
		delete(a.subscribers, subscriberID)
	}
}

// BroadcastStats sends current stats to all subscribers.
func (a *Aggregator) BroadcastStats(ctx context.Context) error {
	stats, err := a.GetAggregatedStats(ctx)
	if err != nil {
		return err
	}

	a.subscriberMu.RLock()
	defer a.subscriberMu.RUnlock()

	for _, ch := range a.subscribers {
		select {
		case ch <- stats:
		default:
			// Channel full, skip this subscriber
		}
	}

	return nil
}

// TakeSnapshot takes a snapshot of current stats for history.
func (a *Aggregator) TakeSnapshot(ctx context.Context) error {
	stats, err := a.GetAggregatedStats(ctx)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.statsHistory = append(a.statsHistory, stats)

	// Trim history if too large
	if len(a.statsHistory) > a.maxHistorySize {
		a.statsHistory = a.statsHistory[1:]
	}

	return nil
}

// GetStatsHistory returns historical statistics snapshots.
func (a *Aggregator) GetStatsHistory(ctx context.Context, limit int) ([]*control.AggregatedStats, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if limit <= 0 || limit > len(a.statsHistory) {
		limit = len(a.statsHistory)
	}

	// Return most recent snapshots
	start := len(a.statsHistory) - limit
	if start < 0 {
		start = 0
	}

	result := make([]*control.AggregatedStats, limit)
	copy(result, a.statsHistory[start:])

	return result, nil
}

// RemoveWorker removes a worker's stats from the aggregator.
func (a *Aggregator) RemoveWorker(workerID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.workerStats, workerID)
}

// GetStaleWorkers returns workers that haven't reported stats within the timeout.
func (a *Aggregator) GetStaleWorkers(timeout time.Duration) []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cutoff := time.Now().Add(-timeout)
	var stale []string

	for workerID, entry := range a.workerStats {
		if entry.timestamp.Before(cutoff) {
			stale = append(stale, workerID)
		}
	}

	return stale
}

// StartPeriodicBroadcast starts a goroutine that broadcasts stats at regular intervals.
func (a *Aggregator) StartPeriodicBroadcast(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = a.BroadcastStats(ctx)
			}
		}
	}()
}

// StartPeriodicSnapshot starts a goroutine that takes snapshots at regular intervals.
func (a *Aggregator) StartPeriodicSnapshot(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = a.TakeSnapshot(ctx)
			}
		}
	}()
}

// Ensure Aggregator implements control.StatsAggregator
var _ control.StatsAggregator = (*Aggregator)(nil)
