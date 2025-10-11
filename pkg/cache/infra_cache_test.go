package cache

import (
	"testing"
	"time"
)

// TestInfraCacheGetOrCreate tests getting or creating upstream stats.
func TestInfraCacheGetOrCreate(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	stats1 := ic.GetOrCreate("8.8.8.8:53")
	if stats1 == nil {
		t.Fatal("Expected stats to be created")
	}

	if stats1.Address != "8.8.8.8:53" {
		t.Errorf("Expected address '8.8.8.8:53', got '%s'", stats1.Address)
	}

	// Getting again should return same instance
	stats2 := ic.GetOrCreate("8.8.8.8:53")
	if stats1 != stats2 {
		t.Error("Expected same stats instance")
	}
}

// TestUpstreamStatsRecordSuccess tests recording successful queries.
func TestUpstreamStatsRecordSuccess(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	initialRTT := stats.GetRTT()

	// Record a fast query (50ms)
	stats.RecordSuccess(50 * time.Millisecond)

	// RTT should have decreased
	newRTT := stats.GetRTT()
	if newRTT >= initialRTT {
		t.Errorf("Expected RTT to decrease, got %f -> %f", initialRTT, newRTT)
	}

	// Failures should be reset
	if stats.GetFailures() != 0 {
		t.Error("Expected failures to be reset to 0")
	}

	// Total queries should be incremented
	if stats.totalQueries.Load() != 1 {
		t.Errorf("Expected total queries = 1, got %d", stats.totalQueries.Load())
	}
}

// TestUpstreamStatsRecordFailure tests recording failed queries.
func TestUpstreamStatsRecordFailure(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	initialRTT := stats.GetRTT()

	// Record failures
	stats.RecordFailure()
	stats.RecordFailure()

	// RTT should have increased (penalty)
	newRTT := stats.GetRTT()
	if newRTT <= initialRTT {
		t.Errorf("Expected RTT to increase on failure, got %f -> %f", initialRTT, newRTT)
	}

	// Failures should be tracked
	if stats.GetFailures() != 2 {
		t.Errorf("Expected 2 failures, got %d", stats.GetFailures())
	}

	// Total failures should be tracked
	if stats.totalFailures.Load() != 2 {
		t.Errorf("Expected total failures = 2, got %d", stats.totalFailures.Load())
	}
}

// TestUpstreamStatsInFlight tests in-flight query tracking.
func TestUpstreamStatsInFlight(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	// Start queries
	count1 := stats.RecordQueryStart()
	if count1 != 1 {
		t.Errorf("Expected in-flight = 1, got %d", count1)
	}

	count2 := stats.RecordQueryStart()
	if count2 != 2 {
		t.Errorf("Expected in-flight = 2, got %d", count2)
	}

	// End query
	stats.RecordQueryEnd()
	if stats.GetInFlight() != 1 {
		t.Errorf("Expected in-flight = 1, got %d", stats.GetInFlight())
	}
}

// TestUpstreamStatsIsHealthy tests health check.
func TestUpstreamStatsIsHealthy(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	// Should be healthy initially
	if !stats.IsHealthy() {
		t.Error("Expected server to be healthy initially")
	}

	// Record failures
	stats.RecordFailure()
	stats.RecordFailure()

	// Still healthy with 2 failures
	if !stats.IsHealthy() {
		t.Error("Expected server to be healthy with 2 failures")
	}

	// Record 3rd failure
	stats.RecordFailure()

	// Should be unhealthy now
	if stats.IsHealthy() {
		t.Error("Expected server to be unhealthy with 3 failures")
	}

	// Success should reset health
	stats.RecordSuccess(50 * time.Millisecond)
	if !stats.IsHealthy() {
		t.Error("Expected server to be healthy after success")
	}
}

// TestUpstreamStatsGetScore tests score calculation.
func TestUpstreamStatsGetScore(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	baseScore := stats.GetScore()

	// Add in-flight queries - should increase score
	stats.RecordQueryStart()
	stats.RecordQueryStart()
	scoreWithLoad := stats.GetScore()
	if scoreWithLoad <= baseScore {
		t.Error("Expected score to increase with in-flight queries")
	}

	// Add failures - should dramatically increase score
	stats.RecordFailure()
	scoreWithFailures := stats.GetScore()
	if scoreWithFailures <= scoreWithLoad {
		t.Error("Expected score to increase with failures")
	}
}

// TestInfraCacheSelectBest tests best server selection.
func TestInfraCacheSelectBest(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	servers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"9.9.9.9:53",
	}

	// Make 8.8.8.8 fast
	stats1 := ic.GetOrCreate("8.8.8.8:53")
	stats1.RecordSuccess(10 * time.Millisecond)

	// Make 1.1.1.1 slow
	stats2 := ic.GetOrCreate("1.1.1.1:53")
	stats2.RecordSuccess(200 * time.Millisecond)

	// Make 9.9.9.9 have failures
	stats3 := ic.GetOrCreate("9.9.9.9:53")
	stats3.RecordFailure()
	stats3.RecordFailure()

	// Should select the fast server
	best := ic.SelectBest(servers)
	if best != "8.8.8.8:53" {
		t.Errorf("Expected best server '8.8.8.8:53', got '%s'", best)
	}
}

// TestInfraCacheSelectBest_SingleServer tests selection with one server.
func TestInfraCacheSelectBest_SingleServer(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	servers := []string{"8.8.8.8:53"}
	best := ic.SelectBest(servers)

	if best != "8.8.8.8:53" {
		t.Errorf("Expected '8.8.8.8:53', got '%s'", best)
	}
}

// TestInfraCacheSelectBest_AllUnhealthy tests selection when all servers unhealthy.
func TestInfraCacheSelectBest_AllUnhealthy(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	servers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
	}

	// Make both unhealthy
	for _, server := range servers {
		stats := ic.GetOrCreate(server)
		stats.RecordFailure()
		stats.RecordFailure()
		stats.RecordFailure()
	}

	// Should still return a server (first one)
	best := ic.SelectBest(servers)
	if best == "" {
		t.Error("Expected a server to be selected even when all unhealthy")
	}
}

// TestUpstreamSnapshot tests snapshot creation.
func TestUpstreamSnapshot(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()
	stats := ic.GetOrCreate("8.8.8.8:53")

	stats.RecordSuccess(50 * time.Millisecond)
	stats.RecordFailure()
	stats.RecordQueryStart()

	snapshot := stats.GetSnapshot()

	if snapshot.Address != "8.8.8.8:53" {
		t.Errorf("Expected address '8.8.8.8:53', got '%s'", snapshot.Address)
	}

	if snapshot.TotalQueries != 2 {
		t.Errorf("Expected 2 total queries, got %d", snapshot.TotalQueries)
	}

	if snapshot.TotalFailures != 1 {
		t.Errorf("Expected 1 total failure, got %d", snapshot.TotalFailures)
	}

	if snapshot.InFlight != 1 {
		t.Errorf("Expected 1 in-flight query, got %d", snapshot.InFlight)
	}

	expectedRate := 1.0 / 2.0
	if snapshot.FailureRate < expectedRate-0.01 || snapshot.FailureRate > expectedRate+0.01 {
		t.Errorf("Expected failure rate ~%.2f, got %.2f", expectedRate, snapshot.FailureRate)
	}
}

// TestInfraCacheGetAllStats tests retrieving all stats.
func TestInfraCacheGetAllStats(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	// Create several server stats
	ic.GetOrCreate("8.8.8.8:53")
	ic.GetOrCreate("1.1.1.1:53")
	ic.GetOrCreate("9.9.9.9:53")

	stats := ic.GetAllStats()

	if len(stats) != 3 {
		t.Errorf("Expected 3 stats entries, got %d", len(stats))
	}
}

// TestInfraCacheClear tests clearing the cache.
func TestInfraCacheClear(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	ic.GetOrCreate("8.8.8.8:53")
	ic.GetOrCreate("1.1.1.1:53")

	ic.Clear()

	stats := ic.GetAllStats()
	if len(stats) != 0 {
		t.Errorf("Expected 0 stats after clear, got %d", len(stats))
	}
}

// TestInfraCachePrune tests pruning old entries.
func TestInfraCachePrune(t *testing.T) {
	t.Parallel()
	ic := NewInfraCache()

	// Create stats and mark as old
	stats1 := ic.GetOrCreate("8.8.8.8:53")
	stats1.lastSuccess.Store(time.Now().Add(-2 * time.Hour).Unix())

	// Create stats that's recent
	stats2 := ic.GetOrCreate("1.1.1.1:53")
	stats2.RecordSuccess(50 * time.Millisecond)

	// Prune entries older than 1 hour
	pruned := ic.Prune(1 * time.Hour)

	if pruned != 1 {
		t.Errorf("Expected 1 entry pruned, got %d", pruned)
	}

	// Old entry should be gone
	if ic.Get("8.8.8.8:53") != nil {
		t.Error("Expected old entry to be pruned")
	}

	// Recent entry should remain
	if ic.Get("1.1.1.1:53") == nil {
		t.Error("Expected recent entry to remain")
	}
}

// BenchmarkInfraCacheSelectBest benchmarks upstream selection.
func BenchmarkInfraCacheSelectBest(b *testing.B) {
	ic := NewInfraCache()

	servers := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
	}

	// Initialize stats
	for _, server := range servers {
		stats := ic.GetOrCreate(server)
		stats.RecordSuccess(50 * time.Millisecond)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = ic.SelectBest(servers)
	}
}
