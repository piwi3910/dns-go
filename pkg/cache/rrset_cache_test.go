package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// BenchmarkRRsetCacheGet tests zero-allocation RRset lookup.
func BenchmarkRRsetCacheGet(b *testing.B) {
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	// Pre-populate with an RRset
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = cache.Get("example.com.", dns.TypeA)
	}
}

// BenchmarkRRsetCacheGetParallel tests concurrent RRset lookups.
func BenchmarkRRsetCacheGetParallel(b *testing.B) {
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.Get("example.com.", dns.TypeA)
		}
	})
}

// BenchmarkMakeRRsetKey tests RRset key generation.
func BenchmarkMakeRRsetKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = MakeRRsetKey("example.com.", dns.TypeA)
	}
}

// TestRRsetCacheGetSet tests basic RRset cache operations.
func TestRRsetCacheGetSet(t *testing.T) {
	t.Parallel()
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	// Create an RRset
	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 300 IN A 192.0.2.2")
	rrs := []dns.RR{rr1, rr2}

	// Set and Get
	cache.Set("example.com.", dns.TypeA, rrs, 5*time.Minute)

	cached := cache.Get("example.com.", dns.TypeA)
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
	config := DefaultRRsetCacheConfig()
	config.MinTTL = 10 * time.Millisecond
	cache := NewRRsetCache(config)

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")

	// Set with short TTL
	cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 50*time.Millisecond)

	// Should be present immediately
	if cached := cache.Get("example.com.", dns.TypeA); cached == nil {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cached := cache.Get("example.com.", dns.TypeA); cached != nil {
		t.Error("Expected cache miss after expiry")
	}
}

// TestRRsetCacheMiss tests cache miss behavior.
func TestRRsetCacheMiss(t *testing.T) {
	t.Parallel()
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	cached := cache.Get("nonexistent.com.", dns.TypeA)
	if cached != nil {
		t.Error("Expected cache miss for non-existent key")
	}

	stats := cache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
}

// TestRRsetCacheStats tests statistics tracking.
func TestRRsetCacheStats(t *testing.T) {
	t.Parallel()
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Generate hits
	for range 10 {
		cache.Get("example.com.", dns.TypeA)
	}

	// Generate misses
	for range 5 {
		cache.Get("nonexistent.com.", dns.TypeA)
	}

	stats := cache.GetStats()

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
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	// Cache A record
	aRR, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	cache.Set("example.com.", dns.TypeA, []dns.RR{aRR}, 5*time.Minute)

	// Cache AAAA record
	aaaaRR, _ := dns.NewRR("example.com. 300 IN AAAA 2001:db8::1")
	cache.Set("example.com.", dns.TypeAAAA, []dns.RR{aaaaRR}, 5*time.Minute)

	// Both should be independently cached
	aRecords := cache.Get("example.com.", dns.TypeA)
	aaaaRecords := cache.Get("example.com.", dns.TypeAAAA)

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

	response := BuildResponse(query, answers)

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

	rrsets := ExtractRRsets(msg)

	// Should have 2 RRsets: A records and NS record
	if len(rrsets) != 2 {
		t.Errorf("Expected 2 RRsets, got %d", len(rrsets))
	}

	// Check A records
	aKey := MakeRRsetKey("example.com.", dns.TypeA)
	if aRRs, ok := rrsets[aKey]; !ok || len(aRRs) != 2 {
		t.Error("Expected 2 A records in RRset")
	}

	// Check NS record
	nsKey := MakeRRsetKey("example.com.", dns.TypeNS)
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

	minTTL := GetMinTTL(rrs)
	expected := 150 * time.Second

	if minTTL != expected {
		t.Errorf("Expected min TTL %v, got %v", expected, minTTL)
	}
}

// TestGetMinTTL_Empty tests minimum TTL with empty RRset.
func TestGetMinTTL_Empty(t *testing.T) {
	t.Parallel()
	minTTL := GetMinTTL([]dns.RR{})
	if minTTL != 0 {
		t.Errorf("Expected 0 for empty RRset, got %v", minTTL)
	}
}

// TestRRsetCacheDelete tests cache deletion.
func TestRRsetCacheDelete(t *testing.T) {
	t.Parallel()
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Verify it's present
	if cached := cache.Get("example.com.", dns.TypeA); cached == nil {
		t.Error("Expected cache hit before delete")
	}

	// Delete
	cache.Delete("example.com.", dns.TypeA)

	// Verify it's gone
	if cached := cache.Get("example.com.", dns.TypeA); cached != nil {
		t.Error("Expected cache miss after delete")
	}
}

// TestRRsetCacheClear tests clearing entire cache.
func TestRRsetCacheClear(t *testing.T) {
	t.Parallel()
	cache := NewRRsetCache(DefaultRRsetCacheConfig())

	// Add multiple entries
	for range 10 {
		rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
		cache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)
	}

	// Clear cache
	cache.Clear()

	// Verify stats are reset
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Expected stats to be reset after clear")
	}
}

// TestRRsetCacheSharding tests that keys are distributed across shards.
func TestRRsetCacheSharding(t *testing.T) {
	t.Parallel()
	config := DefaultRRsetCacheConfig()
	config.NumShards = 4
	cache := NewRRsetCache(config)

	shardsUsed := make(map[*RRsetCacheShard]bool)

	domains := []string{
		"example.com.",
		"google.com.",
		"github.com.",
		"stackoverflow.com.",
	}

	for _, domain := range domains {
		key := MakeRRsetKey(domain, dns.TypeA)
		shard := cache.getShard(key)
		shardsUsed[shard] = true
	}

	// Should use at least 2 different shards
	if len(shardsUsed) < 2 {
		t.Error("Expected keys to be distributed across multiple shards")
	}
}

// TestRRsetCacheTTLBounds tests TTL enforcement.
func TestRRsetCacheTTLBounds(t *testing.T) {
	t.Parallel()
	config := DefaultRRsetCacheConfig()
	config.MinTTL = 60 * time.Second
	config.MaxTTL = 1 * time.Hour
	cache := NewRRsetCache(config)

	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")

	// Try to set with TTL below minimum
	cache.Set("short.com.", dns.TypeA, []dns.RR{rr}, 10*time.Second)

	// Try to set with TTL above maximum
	cache.Set("long.com.", dns.TypeA, []dns.RR{rr}, 24*time.Hour)

	// Both should be stored (with adjusted TTL)
	if cache.Get("short.com.", dns.TypeA) == nil {
		t.Error("Expected entry with adjusted MinTTL")
	}
	if cache.Get("long.com.", dns.TypeA) == nil {
		t.Error("Expected entry with adjusted MaxTTL")
	}
}
