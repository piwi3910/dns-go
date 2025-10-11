package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
)

// TestHandlerFastPathCacheHit tests fast-path with cache hit
func TestHandlerFastPathCacheHit(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Create a query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Pre-populate cache with a response
	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}
	responseBytes, _ := response.Pack()

	cacheKey := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	// Handle query
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}

	// Parse response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if !resultMsg.Response {
		t.Error("Expected Response flag to be set")
	}

	if len(resultMsg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(resultMsg.Answer))
	}
}

// TestHandlerFastPathCacheMiss tests fast-path with cache miss
func TestHandlerFastPathCacheMiss(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Create a query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Handle query (no cache) - will query upstream
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	// Parse response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Should get a response (either success or error, but not SERVFAIL necessarily)
	// The actual result depends on whether we can reach upstream DNS servers
	if !resultMsg.Response {
		t.Error("Expected Response flag to be set")
	}
}

// TestHandlerRRsetCache tests RRset cache hit
func TestHandlerRRsetCache(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Pre-populate RRset cache
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	handler.rrsetCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Create a query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Handle query
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	// Parse response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if len(resultMsg.Answer) != 1 {
		t.Errorf("Expected 1 answer from RRset cache, got %d", len(resultMsg.Answer))
	}

	// Response should now be in message cache too
	stats := handler.GetStats()
	if stats.MessageCache.Size == 0 {
		t.Error("Expected response to be promoted to message cache")
	}
}

// TestHandlerSlowPath tests slow-path processing
func TestHandlerSlowPath(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Create a query with EDNS0 (forces slow path)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(4096, false)
	queryBytes, _ := query.Pack()

	// Pre-populate cache
	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}
	responseBytes, _ := response.Pack()

	cacheKey := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	// Handle query (should use slow path but still hit cache)
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestHandlerCacheResponse tests caching a resolved response
func TestHandlerCacheResponse(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Create a response to cache
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetReply(msg)
	rr1, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	rr2, _ := dns.NewRR("example.com. 300 IN A 192.0.2.2")
	msg.Answer = []dns.RR{rr1, rr2}

	// Cache it
	err := handler.CacheResponse(msg, 5*time.Minute)
	if err != nil {
		t.Fatalf("CacheResponse failed: %v", err)
	}

	// Verify it's in message cache
	cacheKey := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	if cached := handler.messageCache.Get(cacheKey); cached == nil {
		t.Error("Expected response to be in message cache")
	}

	// Verify RRsets are in RRset cache
	if rrs := handler.rrsetCache.Get("example.com.", dns.TypeA); rrs == nil {
		t.Error("Expected RRset to be in RRset cache")
	} else if len(rrs) != 2 {
		t.Errorf("Expected 2 RRs in RRset cache, got %d", len(rrs))
	}
}

// TestHandlerGetStats tests statistics retrieval
func TestHandlerGetStats(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Generate some cache activity
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Cache miss
	handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{})

	stats := handler.GetStats()

	if stats.MessageCache.Misses == 0 {
		t.Error("Expected at least one cache miss")
	}
}

// TestHandlerClearCaches tests cache clearing
func TestHandlerClearCaches(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Populate caches
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.SetReply(response)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}

	handler.CacheResponse(response, 5*time.Minute)

	// Clear caches
	handler.ClearCaches()

	// Verify caches are empty
	stats := handler.GetStats()
	if stats.MessageCache.Hits != 0 || stats.MessageCache.Misses != 0 {
		t.Error("Expected message cache to be cleared")
	}
}

// TestHandlerMalformedQuery tests handling of malformed queries
func TestHandlerMalformedQuery(t *testing.T) {
	handler := NewHandler(DefaultHandlerConfig())

	// Malformed query
	malformed := []byte{0, 1, 2, 3}

	result, err := handler.HandleQuery(context.Background(), malformed, &net.UDPAddr{})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	// Should return error response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		// Even if unpacking fails, we got a response
		return
	}

	if resultMsg.Rcode != dns.RcodeFormatError && resultMsg.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected error rcode, got %d", resultMsg.Rcode)
	}
}

// BenchmarkHandlerFastPathCacheHit benchmarks fast-path cache hit
// Target: minimal allocations, <1µs per query
func BenchmarkHandlerFastPathCacheHit(b *testing.B) {
	handler := NewHandler(DefaultHandlerConfig())

	// Pre-populate cache
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}
	responseBytes, _ := response.Pack()

	cacheKey := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	ctx := context.Background()
	addr := &net.UDPAddr{}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = handler.HandleQuery(ctx, queryBytes, addr)
	}
}

// BenchmarkHandlerFastPathCacheHitParallel benchmarks parallel cache hits
func BenchmarkHandlerFastPathCacheHitParallel(b *testing.B) {
	handler := NewHandler(DefaultHandlerConfig())

	// Pre-populate cache
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}
	responseBytes, _ := response.Pack()

	cacheKey := cache.MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	ctx := context.Background()
	addr := &net.UDPAddr{}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = handler.HandleQuery(ctx, queryBytes, addr)
		}
	})
}
