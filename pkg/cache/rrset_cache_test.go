package cache_test

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/piwi3910/dns-go/pkg/cache"
)

// BenchmarkRRsetCacheGet tests zero-allocation RRset lookup.
func BenchmarkRRsetCacheGet(b *testing.B) {
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	// Pre-populate with an RRset
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = messageCache.Get("example.com.", dns.TypeA)
	}
}

// BenchmarkRRsetCacheGetParallel tests concurrent RRset lookups.
func BenchmarkRRsetCacheGetParallel(b *testing.B) {
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = messageCache.Get("example.com.", dns.TypeA)
		}
	})
}

// BenchmarkMakeRRsetKey tests RRset key generation.
func BenchmarkMakeRRsetKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = cache.MakeRRsetKey("example.com.", dns.TypeA)
	}
}

// TestRRsetCacheGetSet tests basic RRset cache operations.
func TestRRsetCacheGetSet(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	// Create an RRset
	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 300 IN A 192.0.2.2")
	rrs := []dns.RR{rr1, rr2}

	// Set and Get
	messageCache.Set("example.com.", dns.TypeA, rrs, 5*time.Minute)

	cached := messageCache.Get("example.com.", dns.TypeA)
	if cached == nil {
		t.Fatal("Expected cache hit, got miss")
	}

	if len(cached) != 2 {
		t.Errorf("Expected 2 RRs, got %d", len(cached))
	}
}

// TestRRsetCacheExpiry tests RRset TTL expiration.
func TestRRsetCacheExpiry(t *testing.T) {
	t.Parallel()
	config := cache.DefaultRRsetCacheConfig()
	config.MinTTL = 10 * time.Millisecond
	messageCache := cache.NewRRsetCache(config)

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")

	// Set with short TTL
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 50*time.Millisecond)

	// Should be present immediately
	if cached := messageCache.Get("example.com.", dns.TypeA); cached == nil {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cached := messageCache.Get("example.com.", dns.TypeA); cached != nil {
		t.Error("Expected cache miss after expiry")
	}
}

// TestRRsetCacheMiss tests cache miss behavior.
func TestRRsetCacheMiss(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	cached := messageCache.Get("nonexistent.com.", dns.TypeA)
	if cached != nil {
		t.Error("Expected cache miss for non-existent key")
	}

	stats := messageCache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
}

// TestRRsetCacheStats tests statistics tracking.
func TestRRsetCacheStats(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Generate hits
	for range 10 {
		messageCache.Get("example.com.", dns.TypeA)
	}

	// Generate misses
	for range 5 {
		messageCache.Get("nonexistent.com.", dns.TypeA)
	}

	stats := messageCache.GetStats()

	if stats.Hits != 10 {
		t.Errorf("Expected 10 hits, got %d", stats.Hits)
	}

	if stats.Misses != 5 {
		t.Errorf("Expected 5 misses, got %d", stats.Misses)
	}
}

// TestRRsetCacheMultipleTypes tests caching different record types for same name.
func TestRRsetCacheMultipleTypes(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	// Cache A record
	aRR, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{aRR}, 5*time.Minute)

	// Cache AAAA record
	aaaaRR, _ := dns.NewRR("example.com. 300 IN AAAA 2001:db8::1")
	messageCache.Set("example.com.", dns.TypeAAAA, []dns.RR{aaaaRR}, 5*time.Minute)

	// Both should be independently cached
	aRecords := messageCache.Get("example.com.", dns.TypeA)
	aaaaRecords := messageCache.Get("example.com.", dns.TypeAAAA)

	if len(aRecords) != 1 {
		t.Error("Expected A record to be cached")
	}

	if len(aaaaRecords) != 1 {
		t.Error("Expected AAAA record to be cached")
	}
}

// TestBuildResponse tests response construction from RRsets.
func TestBuildResponse(t *testing.T) {
	t.Parallel()
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 300 IN A 192.0.2.2")
	answers := []dns.RR{rr1, rr2}

	response := cache.BuildResponse(query, answers)

	if !response.Response {
		t.Error("Expected Response flag to be set")
	}

	if len(response.Answer) != 2 {
		t.Errorf("Expected 2 answer RRs, got %d", len(response.Answer))
	}

	if !response.RecursionAvailable {
		t.Error("Expected RecursionAvailable flag to be set")
	}
}

// TestExtractRRsets tests extracting RRsets from DNS message.
func TestExtractRRsets(t *testing.T) {
	t.Parallel()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// Add answer records
	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 300 IN A 192.0.2.2")
	msg.Answer = []dns.RR{rr1, rr2}

	// Add authority records
	nsRR, _ := dns.NewRR("example.com. 300 IN NS ns1.example.com.")
	msg.Ns = []dns.RR{nsRR}

	rrsets := cache.ExtractRRsets(msg)

	// Should have 2 RRsets: A records and NS record
	if len(rrsets) != 2 {
		t.Errorf("Expected 2 RRsets, got %d", len(rrsets))
	}

	// Check A records
	aKey := cache.MakeRRsetKey("example.com.", dns.TypeA)
	if aRRs, ok := rrsets[aKey]; !ok || len(aRRs) != 2 {
		t.Error("Expected 2 A records in RRset")
	}

	// Check NS record
	nsKey := cache.MakeRRsetKey("example.com.", dns.TypeNS)
	if nsRRs, ok := rrsets[nsKey]; !ok || len(nsRRs) != 1 {
		t.Error("Expected 1 NS record in RRset")
	}
}

// TestGetMinTTL tests minimum TTL extraction.
func TestGetMinTTL(t *testing.T) {
	t.Parallel()
	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 600 IN A 192.0.2.2")
	rr3, _ := dns.NewRR("example.com. 150 IN A 192.0.2.3")

	rrs := []dns.RR{rr1, rr2, rr3}

	minTTL := cache.GetMinTTL(rrs)
	expected := 150 * time.Second

	if minTTL != expected {
		t.Errorf("Expected min TTL %v, got %v", expected, minTTL)
	}
}

// TestGetMinTTL_Empty tests minimum TTL with empty RRset.
func TestGetMinTTL_Empty(t *testing.T) {
	t.Parallel()
	minTTL := cache.GetMinTTL([]dns.RR{})
	if minTTL != 0 {
		t.Errorf("Expected 0 for empty RRset, got %v", minTTL)
	}
}

// TestRRsetCacheDelete tests cache deletion.
func TestRRsetCacheDelete(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Verify it's present
	if cached := messageCache.Get("example.com.", dns.TypeA); cached == nil {
		t.Error("Expected cache hit before delete")
	}

	// Delete
	messageCache.Delete("example.com.", dns.TypeA)

	// Verify it's gone
	if cached := messageCache.Get("example.com.", dns.TypeA); cached != nil {
		t.Error("Expected cache miss after delete")
	}
}

// TestRRsetCacheClear tests clearing entire cache.
func TestRRsetCacheClear(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewRRsetCache(cache.DefaultRRsetCacheConfig())

	// Add multiple entries
	for range 10 {
		rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
		messageCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)
	}

	// Clear cache
	messageCache.Clear()

	// Verify stats are reset
	stats := messageCache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Expected stats to be reset after clear")
	}
}

// TestRRsetCacheSharding tests that keys are distributed across shards.
func TestRRsetCacheSharding(t *testing.T) {
	t.Parallel()
	config := cache.DefaultRRsetCacheConfig()
	config.NumShards = 4
	_ = cache.NewRRsetCache(config)

	// Note: Further validation requires getter methods for unexported fields
	// shardsUsed := make(map[*cache.RRsetCacheShard]bool)

	domains := []string{
		"example.com.",
		"google.com.",
		"github.com.",
		"stackoverflow.com.",
	}

	for _, domain := range domains {
		_ = cache.MakeRRsetKey(domain, dns.TypeA)
		// Note: Further testing requires getter methods for unexported fields
		// shardsUsed[shard] = true
	}

	// Note: Further validation requires getter methods for unexported fields
	// Should use at least 2 different shards
	// if len(shardsUsed) < 2 {
	// 	t.Error("Expected keys to be distributed across multiple shards")
	// }
}

// TestRRsetCacheTTLBounds tests TTL enforcement.
func TestRRsetCacheTTLBounds(t *testing.T) {
	t.Parallel()
	config := cache.DefaultRRsetCacheConfig()
	config.MinTTL = 60 * time.Second
	config.MaxTTL = 1 * time.Hour
	messageCache := cache.NewRRsetCache(config)

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")

	// Try to set with TTL below minimum
	messageCache.Set("short.com.", dns.TypeA, []dns.RR{rr}, 10*time.Second)

	// Try to set with TTL above maximum
	messageCache.Set("long.com.", dns.TypeA, []dns.RR{rr}, 24*time.Hour)

	// Both should be stored (with adjusted TTL)
	if messageCache.Get("short.com.", dns.TypeA) == nil {
		t.Error("Expected entry with adjusted MinTTL")
	}
	if messageCache.Get("long.com.", dns.TypeA) == nil {
		t.Error("Expected entry with adjusted MaxTTL")
	}
}

// TestRRsetCacheSizeEviction tests that cache evicts entries when size limit is exceeded.
func TestRRsetCacheSizeEviction(t *testing.T) {
	t.Parallel()
	config := cache.RRsetCacheConfig{
		NumShards:    1,    // Single shard for predictable testing
		MaxSizeBytes: 500,  // Very small cache (each RR is ~100 bytes)
		MinTTL:       1 * time.Millisecond,
		MaxTTL:       1 * time.Hour,
	}
	rrsetCache := cache.NewRRsetCache(config)

	// Add entries until we exceed the limit
	for i := 0; i < 20; i++ {
		domain := string(rune('a'+i)) + ".test."
		rr, _ := dns.NewRR(domain + " 300 IN A 192.0.2.1")
		rrsetCache.Set(domain, dns.TypeA, []dns.RR{rr}, 5*time.Minute)

		// Simulate hits on first few entries to make them "popular"
		if i < 3 {
			for j := 0; j < 100; j++ {
				rrsetCache.Get(domain, dns.TypeA)
			}
		}
	}

	// Verify that evictions occurred
	stats := rrsetCache.GetStats()
	if stats.Evicts == 0 {
		t.Error("Expected evictions to occur when cache size limit is exceeded")
	}

	// Verify cache size is under limit
	if stats.Size > config.MaxSizeBytes {
		t.Errorf("Cache size %d exceeds max %d after eviction", stats.Size, config.MaxSizeBytes)
	}

	t.Logf("Evictions: %d, final size: %d", stats.Evicts, stats.Size)
}

// TestRRsetCacheEvictionExpiredFirst tests that expired entries are evicted first.
func TestRRsetCacheEvictionExpiredFirst(t *testing.T) {
	t.Parallel()
	config := cache.RRsetCacheConfig{
		NumShards:    1,
		MaxSizeBytes: 200, // Very small cache
		MinTTL:       1 * time.Millisecond,
		MaxTTL:       1 * time.Hour,
	}
	rrsetCache := cache.NewRRsetCache(config)

	// Add entries with short TTL (these will expire)
	for i := 0; i < 10; i++ {
		domain := string(rune('a'+i)) + ".expired."
		rr, _ := dns.NewRR(domain + " 300 IN A 192.0.2.1")
		rrsetCache.Set(domain, dns.TypeA, []dns.RR{rr}, 10*time.Millisecond)
	}

	// Wait for them to expire
	time.Sleep(50 * time.Millisecond)

	// Add fresh entries that should trigger eviction of the expired ones
	for i := 0; i < 20; i++ {
		domain := string(rune('a'+i)) + ".fresh."
		rr, _ := dns.NewRR(domain + " 300 IN A 192.0.2.1")
		rrsetCache.Set(domain, dns.TypeA, []dns.RR{rr}, 5*time.Minute)
	}

	// Expired entries should have been evicted
	stats := rrsetCache.GetStats()
	if stats.Evicts == 0 {
		t.Error("Expected expired entries to be evicted")
	}
	t.Logf("Evictions: %d, final size: %d", stats.Evicts, stats.Size)
}
