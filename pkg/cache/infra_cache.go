package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// Constants for infrastructure cache scoring and health checks.
const (
	// DefaultRTTMs is the default round-trip time in milliseconds for new servers.
	DefaultRTTMs = 100.0

	// EMAWeightOld is the weight for the old RTT value in exponential moving average (0.8 = 80%).
	EMAWeightOld = 0.8

	// EMAWeightNew is the weight for the new RTT measurement in exponential moving average (0.2 = 20%).
	EMAWeightNew = 0.2

	// RTTPenaltyMultiplier is applied to RTT on failure (1.5 = 50% penalty).
	RTTPenaltyMultiplier = 1.5

	// MaxRTTMs is the maximum RTT cap in milliseconds (prevents infinite growth on failures).
	MaxRTTMs = 1000.0

	// MaxFailuresBeforeUnhealthy is the number of recent failures before a server is considered unhealthy.
	MaxFailuresBeforeUnhealthy = 3

	// InFlightWeightDivisor is used to weight in-flight queries in score calculation
	// score = RTT * (1 + inFlight/InFlightWeightDivisor).
	InFlightWeightDivisor = 10.0

	// InitialBestScore is the starting value for best score comparison (intentionally high).
	InitialBestScore = 999999999.0
)

// InfraCache stores infrastructure information about upstream DNS servers
// This is used for smart upstream selection based on:
// - Round-trip time (RTT)
// - Recent failure rates
// - Current in-flight query count
// - Last successful query timestamp.
type InfraCache struct {
	servers sync.Map // map[string]*UpstreamStats
}

// UpstreamStats tracks statistics for a single upstream server.
type UpstreamStats struct {
	// Server address (e.g., "8.8.8.8:53")
	Address string

	// RTT is the rolling average round-trip time in milliseconds
	// Use atomic.Value to allow lock-free reads
	rtt atomic.Value // float64

	// Failures is the count of recent failures
	failures atomic.Int32

	// LastSuccess is the Unix timestamp of the last successful query
	lastSuccess atomic.Int64

	// LastFailure is the Unix timestamp of the last failed query
	lastFailure atomic.Int64

	// InFlight is the current number of queries in flight to this server
	inFlight atomic.Int32

	// TotalQueries is the total number of queries sent to this server
	totalQueries atomic.Int64

	// TotalFailures is the total number of failed queries
	totalFailures atomic.Int64
}

// NewInfraCache creates a new infrastructure cache.
func NewInfraCache() *InfraCache {
	return &InfraCache{
		servers: sync.Map{},
	}
}

// GetOrCreate gets or creates stats for an upstream server.
func (ic *InfraCache) GetOrCreate(address string) *UpstreamStats {
	// Try to load existing stats
	if stats, ok := ic.servers.Load(address); ok {
		if upstreamStats, ok := stats.(*UpstreamStats); ok {
			return upstreamStats
		}
		// Type assertion failed - should never happen, but handle gracefully
		// Delete invalid entry and fall through to create new one
		ic.servers.Delete(address)
	}

	// Create new stats
	newStats := &UpstreamStats{
		Address:       address,
		rtt:           atomic.Value{},
		failures:      atomic.Int32{},
		lastSuccess:   atomic.Int64{},
		lastFailure:   atomic.Int64{},
		inFlight:      atomic.Int32{},
		totalQueries:  atomic.Int64{},
		totalFailures: atomic.Int64{},
	}
	newStats.rtt.Store(DefaultRTTMs)

	// Store and return (may race, but that's OK)
	actual, _ := ic.servers.LoadOrStore(address, newStats)

	if upstreamStats, ok := actual.(*UpstreamStats); ok {
		return upstreamStats
	}

	// Type assertion failed on LoadOrStore (should never happen)
	// Return the newly created stats as fallback
	return newStats
}

// Get retrieves stats for an upstream server
// Returns nil if not found.
func (ic *InfraCache) Get(address string) *UpstreamStats {
	if stats, ok := ic.servers.Load(address); ok {
		if upstreamStats, ok := stats.(*UpstreamStats); ok {
			return upstreamStats
		}
		// Type assertion failed - delete invalid entry and return nil
		ic.servers.Delete(address)
	}

	return nil
}

// RecordSuccess records a successful query to an upstream server
// Updates RTT with exponential moving average.
func (stats *UpstreamStats) RecordSuccess(rtt time.Duration) {
	// Update RTT with exponential moving average
	// newRTT = EMAWeightOld * oldRTT + EMAWeightNew * measuredRTT
	currentRTT := stats.GetRTT()
	measuredRTT := float64(rtt.Milliseconds())
	newRTT := EMAWeightOld*currentRTT + EMAWeightNew*measuredRTT
	stats.rtt.Store(newRTT)

	// Update timestamps
	stats.lastSuccess.Store(time.Now().Unix())

	// Reset failure counter on success
	stats.failures.Store(0)

	// Update totals
	stats.totalQueries.Add(1)
}

// RecordFailure records a failed query to an upstream server.
func (stats *UpstreamStats) RecordFailure() {
	stats.failures.Add(1)
	stats.lastFailure.Store(time.Now().Unix())
	stats.totalQueries.Add(1)
	stats.totalFailures.Add(1)

	// Increase RTT penalty on failure
	currentRTT := stats.GetRTT()
	penaltyRTT := currentRTT * RTTPenaltyMultiplier
	if penaltyRTT > MaxRTTMs {
		penaltyRTT = MaxRTTMs // Cap at maximum
	}
	stats.rtt.Store(penaltyRTT)
}

// RecordQueryStart increments the in-flight counter
// Returns the new in-flight count.
func (stats *UpstreamStats) RecordQueryStart() int32 {
	return stats.inFlight.Add(1)
}

// RecordQueryEnd decrements the in-flight counter.
func (stats *UpstreamStats) RecordQueryEnd() {
	stats.inFlight.Add(-1)
}

// GetRTT returns the current round-trip time in milliseconds.
func (stats *UpstreamStats) GetRTT() float64 {
	if rtt := stats.rtt.Load(); rtt != nil {
		if rttFloat, ok := rtt.(float64); ok {
			return rttFloat
		}
		// Type assertion failed - return default (should never happen with proper usage)
		return DefaultRTTMs
	}

	return DefaultRTTMs // Default RTT
}

// GetFailures returns the recent failure count.
func (stats *UpstreamStats) GetFailures() int32 {
	return stats.failures.Load()
}

// GetInFlight returns the current in-flight query count.
func (stats *UpstreamStats) GetInFlight() int32 {
	return stats.inFlight.Load()
}

// IsHealthy returns true if the server is considered healthy
// A server is unhealthy if it has MaxFailuresBeforeUnhealthy+ recent failures.
func (stats *UpstreamStats) IsHealthy() bool {
	return stats.failures.Load() < MaxFailuresBeforeUnhealthy
}

// GetScore calculates a score for upstream selection
// Lower score = better server to use
// Score = RTT * (1 + inFlight/InFlightWeightDivisor) * (1 + failures).
func (stats *UpstreamStats) GetScore() float64 {
	rtt := stats.GetRTT()
	inFlight := float64(stats.GetInFlight())
	failures := float64(stats.GetFailures())

	// Weight factors:
	// - In-flight queries increase score (avoid overloading one server)
	// - Failures dramatically increase score
	score := rtt * (1.0 + inFlight/InFlightWeightDivisor) * (1.0 + failures)

	return score
}

// GetStats returns a snapshot of current statistics.
type UpstreamSnapshot struct {
	Address       string
	RTT           float64
	Failures      int32
	InFlight      int32
	LastSuccess   time.Time
	LastFailure   time.Time
	TotalQueries  int64
	TotalFailures int64
	FailureRate   float64
	Score         float64
}

// GetSnapshot returns a snapshot of the current stats.
func (stats *UpstreamStats) GetSnapshot() UpstreamSnapshot {
	totalQueries := stats.totalQueries.Load()
	totalFailures := stats.totalFailures.Load()

	failureRate := 0.0
	if totalQueries > 0 {
		failureRate = float64(totalFailures) / float64(totalQueries)
	}

	lastSuccess := time.Unix(stats.lastSuccess.Load(), 0)
	lastFailure := time.Unix(stats.lastFailure.Load(), 0)

	return UpstreamSnapshot{
		Address:       stats.Address,
		RTT:           stats.GetRTT(),
		Failures:      stats.GetFailures(),
		InFlight:      stats.GetInFlight(),
		LastSuccess:   lastSuccess,
		LastFailure:   lastFailure,
		TotalQueries:  totalQueries,
		TotalFailures: totalFailures,
		FailureRate:   failureRate,
		Score:         stats.GetScore(),
	}
}

// SelectBest selects the best upstream server from a list
// Returns the address of the best server based on score.
func (ic *InfraCache) SelectBest(addresses []string) string {
	if len(addresses) == 0 {
		return ""
	}

	if len(addresses) == 1 {
		return addresses[0]
	}

	var bestAddr string
	bestScore := InitialBestScore // Start with very high score

	for _, addr := range addresses {
		stats := ic.GetOrCreate(addr)

		// Skip unhealthy servers if we have alternatives
		if !stats.IsHealthy() && len(addresses) > 1 {
			continue
		}

		score := stats.GetScore()
		if score < bestScore {
			bestScore = score
			bestAddr = addr
		}
	}

	// If all servers are unhealthy, return the first one
	if bestAddr == "" {
		return addresses[0]
	}

	return bestAddr
}

// GetAllStats returns snapshots for all tracked servers.
func (ic *InfraCache) GetAllStats() []UpstreamSnapshot {
	var snapshots []UpstreamSnapshot

	ic.servers.Range(func(key, value interface{}) bool {
		stats, ok := value.(*UpstreamStats)
		if !ok {
			// Type assertion failed - skip invalid entry
			return true
		}
		snapshots = append(snapshots, stats.GetSnapshot())

		return true
	})

	return snapshots
}

// Clear removes all entries from the infrastructure cache.
func (ic *InfraCache) Clear() {
	ic.servers.Range(func(key, value interface{}) bool {
		ic.servers.Delete(key)

		return true
	})
}

// Prune removes entries for servers that haven't been used recently
// This prevents unbounded memory growth.
func (ic *InfraCache) Prune(maxAge time.Duration) int {
	pruned := 0
	cutoff := time.Now().Add(-maxAge).Unix()

	ic.servers.Range(func(key, value interface{}) bool {
		stats, ok := value.(*UpstreamStats)
		if !ok {
			// Type assertion failed - delete invalid entry
			ic.servers.Delete(key)
			return true
		}

		lastUse := stats.lastSuccess.Load()
		if lastFailure := stats.lastFailure.Load(); lastFailure > lastUse {
			lastUse = lastFailure
		}

		if lastUse < cutoff {
			ic.servers.Delete(key)
			pruned++
		}

		return true
	})

	return pruned
}
