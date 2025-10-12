package cache_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/piwi3910/dns-go/pkg/cache"
)

// BenchmarkMessageCacheGet tests zero-allocation cache lookup
// Target: 0 allocs/op.
func BenchmarkMessageCacheGet(b *testing.B) {
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	// Pre-populate cache
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()
	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = messageCache.Get(key)
	}
}

// BenchmarkMessageCacheGetParallel tests concurrent cache lookups.
func BenchmarkMessageCacheGetParallel(b *testing.B) {
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	// Pre-populate cache
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()
	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 5*time.Minute)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = messageCache.Get(key)
		}
	})
}

// BenchmarkMessageCacheSet tests cache insertion.
func BenchmarkMessageCacheSet(b *testing.B) {
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
		messageCache.Set(key, response, 5*time.Minute)
	}
}

// BenchmarkMakeKey tests cache key generation
// Target: < 100ns, minimal allocs.
func BenchmarkMakeKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	}
}

// TestMessageCacheGetSet tests basic cache operations.
func TestMessageCacheGetSet(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	// Create a response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	// Test Set and Get
	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 5*time.Minute)

	cached := messageCache.Get(key)
	if cached == nil {
		t.Error("Expected cache hit, got miss")
	}

	if len(cached) != len(response) {
		t.Errorf("Cached response length = %d, want %d", len(cached), len(response))
	}
}

// TestMessageCacheExpiry tests TTL expiration.
func TestMessageCacheExpiry(t *testing.T) {
	t.Parallel()
	// Create cache with very low MinTTL for testing
	config := cache.DefaultMessageCacheConfig()
	config.MinTTL = 10 * time.Millisecond
	messageCache := cache.NewMessageCache(config)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	// Set with very short TTL
	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 50*time.Millisecond)

	// Should be present immediately
	if cached := messageCache.Get(key); cached == nil {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	if cached := messageCache.Get(key); cached != nil {
		t.Error("Expected cache miss after expiry")
	}
}

// TestMessageCacheMiss tests cache miss behavior.
func TestMessageCacheMiss(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	key := cache.MakeKey("nonexistent.com.", dns.TypeA, dns.ClassINET)
	cached := messageCache.Get(key)

	if cached != nil {
		t.Error("Expected cache miss for non-existent key")
	}

	stats := messageCache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}
}

// TestMessageCacheStats tests statistics tracking.
func TestMessageCacheStats(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 5*time.Minute)

	// Generate hits
	for range 10 {
		messageCache.Get(key)
	}

	// Generate misses
	for range 5 {
		messageCache.Get("nonexistent")
	}

	stats := messageCache.GetStats()

	if stats.Hits != 10 {
		t.Errorf("Expected 10 hits, got %d", stats.Hits)
	}

	if stats.Misses != 5 {
		t.Errorf("Expected 5 misses, got %d", stats.Misses)
	}

	expectedHitRate := 10.0 / 15.0
	if stats.HitRate < expectedHitRate-0.01 || stats.HitRate > expectedHitRate+0.01 {
		t.Errorf("Expected hit rate ~%.2f, got %.2f", expectedHitRate, stats.HitRate)
	}
}

// TestMessageCacheSharding tests that cache can be created with multiple shards.
// Note: getShard() is unexported so we can't directly test shard distribution.
func TestMessageCacheSharding(t *testing.T) {
	t.Parallel()
	config := cache.DefaultMessageCacheConfig()
	config.NumShards = 4
	messageCache := cache.NewMessageCache(config)

	// Just verify cache works with multiple shards by doing basic operations
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	keys := []string{
		"example.com.",
		"google.com.",
		"github.com.",
		"stackoverflow.com.",
	}

	// Set entries
	for _, domain := range keys {
		key := cache.MakeKey(domain, dns.TypeA, dns.ClassINET)
		messageCache.Set(key, response, 5*time.Minute)
	}

	// Verify all can be retrieved
	for _, domain := range keys {
		key := cache.MakeKey(domain, dns.TypeA, dns.ClassINET)
		if messageCache.Get(key) == nil {
			t.Errorf("Expected cache hit for %s", domain)
		}
	}
}

// TestMessageCacheDelete tests cache deletion.
func TestMessageCacheDelete(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, response, 5*time.Minute)

	// Verify it's present
	if cached := messageCache.Get(key); cached == nil {
		t.Error("Expected cache hit before delete")
	}

	// Delete
	messageCache.Delete(key)

	// Verify it's gone
	if cached := messageCache.Get(key); cached != nil {
		t.Error("Expected cache miss after delete")
	}
}

// TestMessageCacheClear tests clearing entire cache.
func TestMessageCacheClear(t *testing.T) {
	t.Parallel()
	messageCache := cache.NewMessageCache(cache.DefaultMessageCacheConfig())

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	// Add multiple entries
	for range 10 {
		key := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
		messageCache.Set(key, response, 5*time.Minute)
	}

	// Clear cache
	messageCache.Clear()

	// Verify stats are reset
	stats := messageCache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Expected stats to be reset after clear")
	}
}

// TestMessageCacheTTLBounds tests TTL enforcement.
func TestMessageCacheTTLBounds(t *testing.T) {
	t.Parallel()
	config := cache.DefaultMessageCacheConfig()
	config.MinTTL = 60 * time.Second
	config.MaxTTL = 1 * time.Hour
	messageCache := cache.NewMessageCache(config)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	response, _ := msg.Pack()

	// Try to set with TTL below minimum
	key1 := cache.MakeKey("short.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key1, response, 10*time.Second) // Below MinTTL

	// Try to set with TTL above maximum
	key2 := cache.MakeKey("long.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key2, response, 24*time.Hour) // Above MaxTTL

	// Both should be stored (with adjusted TTL)
	if messageCache.Get(key1) == nil {
		t.Error("Expected entry with adjusted MinTTL")
	}
	if messageCache.Get(key2) == nil {
		t.Error("Expected entry with adjusted MaxTTL")
	}
}

// TestShouldPrefetch tests prefetch heuristic.
func TestShouldPrefetch(t *testing.T) {
	t.Parallel()
	// Create entry that expires in 1 second, was created 10 seconds ago
	// This simulates an entry with original TTL of 11 seconds, now with 1 second left
	// TTL remaining = 1/11 = ~9% which is below 10% threshold
	entry := &cache.MessageCacheEntry{
		ResponseBytes: []byte{1, 2, 3},
		Expiry:        time.Now().Add(1 * time.Second),
		HitCount:      atomic.Int64{},
		LastHit:       atomic.Int64{},
	}
	entry.HitCount.Store(200) // Popular entry
	entry.LastHit.Store(time.Now().Add(-10 * time.Second).Unix())

	// Should prefetch if hit count is high and TTL remaining is low (< 10%)
	if !entry.ShouldPrefetch(100, 0.1) {
		t.Error("Expected shouldPrefetch = true for popular, expiring entry")
	}

	// Should not prefetch if hit count is low
	entry.HitCount.Store(50)
	if entry.ShouldPrefetch(100, 0.1) {
		t.Error("Expected shouldPrefetch = false for unpopular entry")
	}

	// Should not prefetch if entry expired
	expiredEntry := &cache.MessageCacheEntry{
		ResponseBytes: []byte{1, 2, 3},
		Expiry:        time.Now().Add(-1 * time.Second),
		HitCount:      atomic.Int64{},
		LastHit:       atomic.Int64{},
	}
	expiredEntry.HitCount.Store(200)
	if expiredEntry.ShouldPrefetch(100, 0.1) {
		t.Error("Expected shouldPrefetch = false for expired entry")
	}
}
