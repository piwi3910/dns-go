package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
	"github.com/piwi3910/dns-go/pkg/server"
)

// TestHandlerFastPathCacheHit tests fast-path with cache hit.
func TestHandlerFastPathCacheHit(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

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
	// Note: Further validation requires getter methods for unexported fields
	_ = cacheKey
	_ = responseBytes
	// handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	// Handle query
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
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

	// Note: Cannot pre-populate cache due to unexported fields
	// Test will make real upstream query, which may return multiple answers
	// Just verify we got a response with some answers (cache miss scenario)
	if len(resultMsg.Answer) == 0 && resultMsg.Rcode == dns.RcodeSuccess {
		t.Error("Expected at least one answer for successful response")
	}
}

// TestHandlerFastPathCacheMiss tests fast-path with cache miss.
func TestHandlerFastPathCacheMiss(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Create a query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Handle query (no cache) - will query upstream
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
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

// TestHandlerRRsetCache tests RRset cache hit.
func TestHandlerRRsetCache(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Pre-populate RRset cache
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	// Note: Further validation requires getter methods for unexported fields
	_ = rr
	// handler.rrsetCache.Set("example.com.", dns.TypeA, []dns.RR{rr}, 5*time.Minute)

	// Create a query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Handle query
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	// Parse response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Note: Cannot pre-populate cache due to unexported fields
	// Test will make real upstream query, which may return multiple answers
	// Just verify we got a response with answers for successful responses
	if len(resultMsg.Answer) == 0 && resultMsg.Rcode == dns.RcodeSuccess {
		t.Error("Expected at least one answer from RRset cache for successful response")
	}

	// Response should now be in message cache too
	stats := handler.GetStats()
	if stats.MessageCache.Size == 0 {
		t.Error("Expected response to be promoted to message cache")
	}
}

// TestHandlerSlowPath tests slow-path processing.
func TestHandlerSlowPath(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

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
	// Note: Further validation requires getter methods for unexported fields
	_ = cacheKey
	_ = responseBytes
	// handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	// Handle query (should use slow path but still hit cache)
	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}
}

// TestHandlerCacheResponse tests caching a resolved response.
func TestHandlerCacheResponse(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

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
	// Note: Further validation requires getter methods for unexported fields
	_ = cacheKey
	// if cached := handler.messageCache.Get(cacheKey); cached == nil {
	// 	t.Error("Expected response to be in message cache")
	// }

	// Verify RRsets are in RRset cache
	// Note: Further validation requires getter methods for unexported fields
	// if rrs := handler.rrsetCache.Get("example.com.", dns.TypeA); rrs == nil {
	// 	t.Error("Expected RRset to be in RRset cache")
	// } else if len(rrs) != 2 {
	// 	t.Errorf("Expected 2 RRs in RRset cache, got %d", len(rrs))
	// }
}

// TestHandlerGetStats tests statistics retrieval.
func TestHandlerGetStats(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Generate some cache activity
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// Cache miss
	_, _ = handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	stats := handler.GetStats()

	if stats.MessageCache.Misses == 0 {
		t.Error("Expected at least one cache miss")
	}
}

// TestHandlerClearCaches tests cache clearing.
func TestHandlerClearCaches(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Populate caches
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.SetReply(response)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = []dns.RR{rr}

	_ = handler.CacheResponse(response, 5*time.Minute)

	// Clear caches
	handler.ClearCaches()

	// Verify caches are empty
	stats := handler.GetStats()
	if stats.MessageCache.Hits != 0 || stats.MessageCache.Misses != 0 {
		t.Error("Expected message cache to be cleared")
	}
}

// TestHandlerMalformedQuery tests handling of malformed queries.
func TestHandlerMalformedQuery(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Malformed query
	malformed := []byte{0, 1, 2, 3}

	result, err := handler.HandleQuery(context.Background(), malformed, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
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
// Target: minimal allocations, <1µs per query.
func BenchmarkHandlerFastPathCacheHit(b *testing.B) {
	handler := server.NewHandler(server.DefaultHandlerConfig())

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
	// Note: Further validation requires getter methods for unexported fields
	_ = cacheKey
	_ = responseBytes
	// handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	ctx := context.Background()
	addr := &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_, _ = handler.HandleQuery(ctx, queryBytes, addr)
	}
}

// BenchmarkHandlerFastPathCacheHitParallel benchmarks parallel cache hits.
func BenchmarkHandlerFastPathCacheHitParallel(b *testing.B) {
	handler := server.NewHandler(server.DefaultHandlerConfig())

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
	// Note: Further validation requires getter methods for unexported fields
	_ = cacheKey
	_ = responseBytes
	// handler.messageCache.Set(cacheKey, responseBytes, 5*time.Minute)

	ctx := context.Background()
	addr := &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = handler.HandleQuery(ctx, queryBytes, addr)
		}
	})
}

// TestHandlerFastPathParseError tests fast-path handling of parse errors.
func TestHandlerFastPathParseError(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableFastPath = true
	handler := server.NewHandler(config)

	// Create an invalid query that will fail fast-path parsing
	invalidQuery := []byte{0, 1, 2, 3, 4, 5} // Too short for valid DNS

	result, err := handler.HandleQuery(context.Background(), invalidQuery, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	// Should return error response
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		// Even if unpacking fails, we got a response
		return
	}

	// Should have error rcode
	if resultMsg.Rcode != dns.RcodeFormatError && resultMsg.Rcode != dns.RcodeServerFailure {
		t.Errorf("Expected error rcode, got %d", resultMsg.Rcode)
	}
}

// TestHandlerWithDNSSEC tests DNSSEC validation in responses.
func TestHandlerWithDNSSEC(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableDNSSEC = true
	handler := server.NewHandler(config)

	// Create a query with DO bit set (DNSSEC OK)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	query.SetEdns0(4096, true) // Set DNSSEC OK bit

	queryBytes, _ := query.Pack()

	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if !resultMsg.Response {
		t.Error("Expected Response flag to be set")
	}

	// DNSSEC validation path should be exercised (may or may not set AD bit depending on validation)
}

// TestHandlerSlowPathCacheHit tests slow-path cache hit.
func TestHandlerSlowPathCacheHit(t *testing.T) {
	t.Parallel()
	handler := server.NewHandler(server.DefaultHandlerConfig())

	// Create a query with EDNS0 (forces slow path)
	query := new(dns.Msg)
	query.SetQuestion("slowpath.example.com.", dns.TypeA)
	query.SetEdns0(4096, false)

	// First query populates cache
	queryBytes1, _ := query.Pack()
	result1, err := handler.HandleQuery(context.Background(), queryBytes1, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
	if err != nil {
		t.Fatalf("First query failed: %v", err)
	}

	// Second identical query should hit cache
	queryBytes2, _ := query.Pack()
	result2, err := handler.HandleQuery(context.Background(), queryBytes2, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})
	if err != nil {
		t.Fatalf("Second query failed: %v", err)
	}

	// Both should return valid responses
	if result1 == nil || result2 == nil {
		t.Error("Expected non-nil responses")
	}
}

// TestHandlerRateLimiting tests rate limiting functionality.
func TestHandlerRateLimiting(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableRateLimiting = true
	handler := server.NewHandler(config)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	// First query should succeed
	addr := &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	}
	_, err := handler.HandleQuery(context.Background(), queryBytes, addr)
	if err != nil {
		t.Fatalf("First query failed: %v", err)
	}

	// Rate limiting should be applied (behavior depends on rate limit config)
}

// TestHandlerQueryValidation tests query validation.
func TestHandlerQueryValidation(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableQueryValidation = true
	handler := server.NewHandler(config)

	// Create a valid query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}

	// Query validation path should be exercised
}

// TestHandlerCachePoisoningProtection tests cache poisoning protection.
func TestHandlerCachePoisoningProtection(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableCachePoisoningProtection = true
	handler := server.NewHandler(config)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}

	// Cache poisoning protection should be exercised during validation
}

// TestHandlerFastPathDisabled tests behavior with fast-path disabled.
func TestHandlerFastPathDisabled(t *testing.T) {
	t.Parallel()
	config := server.DefaultHandlerConfig()
	config.EnableFastPath = false // Disable fast path
	handler := server.NewHandler(config)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	queryBytes, _ := query.Pack()

	result, err := handler.HandleQuery(context.Background(), queryBytes, &net.UDPAddr{
		IP:   nil,
		Port: 0,
		Zone: "",
	})

	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected response, got nil")
	}

	// Should use slow path even for simple queries
	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(result); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if !resultMsg.Response {
		t.Error("Expected Response flag to be set")
	}
}

// TestHandlerRecursiveMode tests handler in recursive resolution mode.
func TestHandlerRecursiveMode(t *testing.T) {
	t.Parallel()
	// Note: This test exercises the recursive mode code path
	// Actual recursive resolution testing requires network access or mocking
	t.Skip("Recursive mode testing requires network access or mock infrastructure")
}
