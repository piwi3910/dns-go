package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
)

const (
	testGoogleDNS    = "8.8.8.8:53"
	testCloudflareDNS = "1.1.1.1:53"
)

func TestNewUpstreamPool(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS, testCloudflareDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	if pool == nil {
		t.Fatal("Expected upstream pool to be created")
	}

	if len(pool.upstreams) != 2 {
		t.Errorf("Expected 2 upstreams, got %d", len(pool.upstreams))
	}
}

func TestNewUpstreamPool_EmptyList(t *testing.T) {
	t.Parallel()
	config := UpstreamConfig{
		Upstreams:              []string{},
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	if pool == nil {
		t.Fatal("Expected pool to be created even with empty list")
	}

	if len(pool.upstreams) != 0 {
		t.Errorf("Expected 0 upstreams, got %d", len(pool.upstreams))
	}
}

func TestUpstreamPool_GetStats(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS, testCloudflareDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	// Record some stats via infraCache
	stats1 := pool.infraCache.GetOrCreate(testGoogleDNS)
	stats1.RecordSuccess(50 * time.Millisecond)

	stats2 := pool.infraCache.GetOrCreate(testCloudflareDNS)
	stats2.RecordFailure()

	allStats := pool.GetStats()

	// Should have at least the two we created
	if len(allStats) < 2 {
		t.Errorf("Expected at least 2 upstream stats, got %d", len(allStats))
	}

	// Find our specific stats
	var found8 bool
	var found1 bool
	for _, stat := range allStats {
		if stat.Address == testGoogleDNS {
			found8 = true
			if stat.TotalQueries == 0 {
				t.Error("Expected queries > 0 for 8.8.8.8")
			}
		}
		if stat.Address == testCloudflareDNS {
			found1 = true
			if stat.TotalQueries == 0 {
				t.Error("Expected queries > 0 for 1.1.1.1")
			}
		}
	}

	if !found8 || !found1 {
		t.Error("Expected to find both upstream addresses in stats")
	}
}

func TestQuery_Timeout(t *testing.T) {
	t.Parallel()
	upstreams := []string{"192.0.2.1:53"} // Non-existent IP
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                100 * time.Millisecond,
		MaxRetries:             1,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	query.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := pool.Query(ctx, query)

	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestQueryWithFallback_AllFail(t *testing.T) {
	t.Parallel()
	upstreams := []string{"192.0.2.1:53", "192.0.2.2:53"} // Non-existent IPs
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                100 * time.Millisecond,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	query.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := pool.QueryWithFallback(ctx, query, 2)

	if err == nil {
		t.Error("Expected error when all upstreams fail")
	}
}

func TestUpstreamPool_SetUpstreams(t *testing.T) {
	t.Parallel()
	config := UpstreamConfig{
		Upstreams:              []string{testGoogleDNS},
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	if len(pool.upstreams) != 1 {
		t.Fatalf("Expected 1 upstream, got %d", len(pool.upstreams))
	}

	// Update upstreams
	newUpstreams := []string{testCloudflareDNS, "9.9.9.9:53"}
	pool.SetUpstreams(newUpstreams)

	currentUpstreams := pool.GetUpstreams()
	if len(currentUpstreams) != 2 {
		t.Errorf("Expected 2 upstreams after update, got %d", len(currentUpstreams))
	}

	if currentUpstreams[0] != testCloudflareDNS || currentUpstreams[1] != "9.9.9.9:53" {
		t.Error("Upstreams not updated correctly")
	}
}

func TestUpstreamPool_GetUpstreams(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS, testCloudflareDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	retrieved := pool.GetUpstreams()

	if len(retrieved) != 2 {
		t.Errorf("Expected 2 upstreams, got %d", len(retrieved))
	}

	if retrieved[0] != testGoogleDNS || retrieved[1] != testCloudflareDNS {
		t.Error("Retrieved upstreams don't match expected")
	}
}

func TestUpstreamPool_Close(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	err := pool.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestDefaultUpstreamConfig(t *testing.T) {
	t.Parallel()
	config := DefaultUpstreamConfig()

	if len(config.Upstreams) == 0 {
		t.Error("Expected default upstreams to be configured")
	}

	if config.Timeout == 0 {
		t.Error("Expected default timeout to be set")
	}

	if config.MaxRetries == 0 {
		t.Error("Expected default max retries to be set")
	}

	if config.ConnectionsPerUpstream == 0 {
		t.Error("Expected default connections per upstream to be set")
	}
}

func TestUpstreamConfig_CustomValues(t *testing.T) {
	t.Parallel()
	config := UpstreamConfig{
		Upstreams:              []string{"custom.dns:53"},
		Timeout:                10 * time.Second,
		MaxRetries:             5,
		ConnectionsPerUpstream: 8,
	}

	if config.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", config.Timeout)
	}

	if config.MaxRetries != 5 {
		t.Errorf("Expected 5 retries, got %d", config.MaxRetries)
	}

	if config.ConnectionsPerUpstream != 8 {
		t.Errorf("Expected 8 connections, got %d", config.ConnectionsPerUpstream)
	}
}

func TestUpstreamPool_EmptyPoolQuery(t *testing.T) {
	t.Parallel()
	config := UpstreamConfig{
		Upstreams:              []string{},
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	_, err := pool.Query(ctx, query)

	if err == nil {
		t.Error("Expected error when querying with empty pool")
	}
}

func TestInfraCacheIntegration(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS}
	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	pool := NewUpstreamPool(config, infraCache)

	// Verify pool uses the provided infraCache
	if pool.infraCache != infraCache {
		t.Error("Pool should use the provided InfraCache")
	}

	// Record some stats
	stats := infraCache.GetOrCreate(testGoogleDNS)
	stats.RecordSuccess(25 * time.Millisecond)
	stats.RecordFailure()

	// Should be reflected in pool stats
	allStats := pool.GetStats()
	found := false
	for _, stat := range allStats {
		if stat.Address == testGoogleDNS {
			found = true
			if stat.TotalQueries == 0 {
				t.Error("Expected queries to be recorded")
			}
		}
	}

	if !found {
		t.Error("Expected to find upstream in stats")
	}
}

func TestUpstreamPool_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS, testCloudflareDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	// Test concurrent GetUpstreams calls
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			upstreams := pool.GetUpstreams()
			if len(upstreams) != 2 {
				t.Errorf("Expected 2 upstreams in concurrent access, got %d", len(upstreams))
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}
}

func TestConnectionPool_PerUpstream(t *testing.T) {
	t.Parallel()
	upstreams := []string{testGoogleDNS, testCloudflareDNS}
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()
	pool := NewUpstreamPool(config, infraCache)

	// Verify each upstream has its own connection pool
	if len(pool.udpPools) != 2 {
		t.Errorf("Expected 2 UDP pools, got %d", len(pool.udpPools))
	}

	if _, exists := pool.udpPools[testGoogleDNS]; !exists {
		t.Error("Expected UDP pool for 8.8.8.8:53")
	}

	if _, exists := pool.udpPools[testCloudflareDNS]; !exists {
		t.Error("Expected UDP pool for 1.1.1.1:53")
	}
}
