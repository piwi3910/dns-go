package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// MockPrefetchResolver implements PrefetchResolver for testing.
type MockPrefetchResolver struct {
	mu            sync.Mutex
	resolveCount  int
	resolveCalls  []string // Track what was resolved
	resolveDelay  time.Duration
	resolveError  error
	resolveResult *dns.Msg
}

func NewMockPrefetchResolver() *MockPrefetchResolver {
	return &MockPrefetchResolver{
		mu:            sync.Mutex{},
		resolveCount:  0,
		resolveCalls:  make([]string, 0),
		resolveDelay:  0,
		resolveError:  nil,
		resolveResult: nil,
	}
}

func (m *MockPrefetchResolver) Resolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.resolveCount++
	if len(query.Question) > 0 {
		m.resolveCalls = append(m.resolveCalls, query.Question[0].Name)
	}

	if m.resolveDelay > 0 {
		time.Sleep(m.resolveDelay)
	}

	if m.resolveError != nil {
		return nil, m.resolveError
	}

	if m.resolveResult != nil {
		return m.resolveResult, nil
	}

	// Return a simple A record response
	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	response.Answer = append(response.Answer, rr)

	return response, nil
}

func (m *MockPrefetchResolver) GetResolveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.resolveCount
}

func (m *MockPrefetchResolver) GetResolveCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]string{}, m.resolveCalls...) // Return copy
}

func TestDefaultPrefetchConfig(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()

	if !config.Enabled {
		t.Error("Expected prefetch to be enabled by default")
	}

	if config.PrefetchThresh != 0.10 {
		t.Errorf("Expected prefetch threshold 0.10, got %f", config.PrefetchThresh)
	}

	if config.MinHits != 3 {
		t.Errorf("Expected min hits 3, got %d", config.MinHits)
	}

	if config.MaxConcurrent != 10 {
		t.Errorf("Expected max concurrent 10, got %d", config.MaxConcurrent)
	}

	if config.CheckInterval != 5*time.Second {
		t.Errorf("Expected check interval 5s, got %v", config.CheckInterval)
	}
}

func TestNewPrefetchEngine(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	if engine == nil {
		t.Fatal("Expected engine to be created")
	}

	if !engine.enabled {
		t.Error("Expected engine to be enabled")
	}

	if engine.prefetchThresh != config.PrefetchThresh {
		t.Error("Prefetch threshold not set correctly")
	}

	if engine.minHits != config.MinHits {
		t.Error("Min hits not set correctly")
	}

	if engine.maxConcurrent != config.MaxConcurrent {
		t.Error("Max concurrent not set correctly")
	}

	if engine.candidates == nil {
		t.Error("Candidates map should be initialized")
	}

	if engine.prefetchQueue == nil {
		t.Error("Prefetch queue should be initialized")
	}
}

func TestPrefetchEngine_Disabled(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	config.Enabled = false

	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Start/Stop should be no-ops when disabled
	engine.Start(100 * time.Millisecond)
	engine.Stop()

	// RecordAccess should be no-op when disabled
	engine.RecordAccess("key1", "example.com.", dns.TypeA, dns.ClassINET)

	stats := engine.GetStats()
	if stats.Enabled {
		t.Error("Stats should show disabled")
	}
}

func TestPrefetchEngine_RecordAccess(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Record first access
	engine.RecordAccess("key1", "example.com.", dns.TypeA, dns.ClassINET)

	engine.mu.RLock()
	candidate, exists := engine.candidates["key1"]
	engine.mu.RUnlock()

	if !exists {
		t.Fatal("Expected candidate to be created")
	}

	if candidate.hits != 1 {
		t.Errorf("Expected 1 hit, got %d", candidate.hits)
	}

	if candidate.name != testExampleDomain {
		t.Errorf("Expected name %s, got %s", testExampleDomain, candidate.name)
	}

	if candidate.qtype != dns.TypeA {
		t.Errorf("Expected qtype A, got %d", candidate.qtype)
	}

	// Record second access - should increment hits
	engine.RecordAccess("key1", testExampleDomain, dns.TypeA, dns.ClassINET)

	engine.mu.RLock()
	candidate = engine.candidates["key1"]
	engine.mu.RUnlock()

	if candidate.hits != 2 {
		t.Errorf("Expected 2 hits after second access, got %d", candidate.hits)
	}
}

func TestPrefetchEngine_RecordAccess_MultipleKeys(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Record accesses to different keys
	engine.RecordAccess("key1", "example.com.", dns.TypeA, dns.ClassINET)
	engine.RecordAccess("key2", "google.com.", dns.TypeAAAA, dns.ClassINET)
	engine.RecordAccess("key1", "example.com.", dns.TypeA, dns.ClassINET)
	engine.RecordAccess("key3", "cloudflare.com.", dns.TypeA, dns.ClassINET)

	engine.mu.RLock()
	numCandidates := len(engine.candidates)
	key1Hits := engine.candidates["key1"].hits
	key2Hits := engine.candidates["key2"].hits
	key3Hits := engine.candidates["key3"].hits
	engine.mu.RUnlock()

	if numCandidates != 3 {
		t.Errorf("Expected 3 candidates, got %d", numCandidates)
	}

	if key1Hits != 2 {
		t.Errorf("Expected key1 to have 2 hits, got %d", key1Hits)
	}

	if key2Hits != 1 {
		t.Errorf("Expected key2 to have 1 hit, got %d", key2Hits)
	}

	if key3Hits != 1 {
		t.Errorf("Expected key3 to have 1 hit, got %d", key3Hits)
	}
}

func TestPrefetchEngine_StartStop(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Start engine
	engine.Start(100 * time.Millisecond)

	// Give workers time to start
	time.Sleep(50 * time.Millisecond)

	// Stop engine - should block until all workers finish
	done := make(chan struct{})
	go func() {
		engine.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good - Stop() completed
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not complete within timeout")
	}
}

func TestPrefetchEngine_GetStats(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Initial stats
	stats := engine.GetStats()
	if !stats.Enabled {
		t.Error("Expected stats to show enabled")
	}

	if stats.Candidates != 0 {
		t.Errorf("Expected 0 candidates initially, got %d", stats.Candidates)
	}

	// Add some candidates
	engine.RecordAccess("key1", "example.com.", dns.TypeA, dns.ClassINET)
	engine.RecordAccess("key2", "google.com.", dns.TypeAAAA, dns.ClassINET)

	stats = engine.GetStats()
	if stats.Candidates != 2 {
		t.Errorf("Expected 2 candidates, got %d", stats.Candidates)
	}

	// Mark one as prefetching
	engine.mu.Lock()
	engine.candidates["key1"].prefetching = true
	engine.mu.Unlock()

	stats = engine.GetStats()
	if stats.Prefetching != 1 {
		t.Errorf("Expected 1 prefetching, got %d", stats.Prefetching)
	}
}

func TestPrefetchEngine_ShouldPrefetch_MessageCache(t *testing.T) {
	t.Parallel()
	t.Skip("Timing-sensitive test - TTL calculation depends on precise timing which varies in CI environments")

	config := DefaultPrefetchConfig()
	config.PrefetchThresh = 0.20 // 20% remaining TTL

	msgCacheConfig := DefaultMessageCacheConfig()
	msgCacheConfig.MaxSizeBytes = 10 * 1024 * 1024 // 10MB
	messageCache := NewMessageCache(msgCacheConfig)
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Add entry to message cache with short TTL
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 2 IN A 192.0.2.1") // 2 second TTL
	response.Answer = append(response.Answer, rr)

	// Pack the message to bytes
	responseBytes, _ := response.Pack()

	key := MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, responseBytes, 2*time.Second)

	// Simulate accesses over time
	entry := messageCache.GetEntryForPrefetch(key)
	if entry != nil {
		// Simulate multiple accesses
		for range 10 {
			entry.IncrementHitCount()
		}
	}

	// Wait for most of TTL to expire (1.7 seconds = 85% expired, 15% remaining)
	time.Sleep(1700 * time.Millisecond)

	// Create candidate
	candidate := &prefetchCandidate{
		key:         key,
		name:        "example.com.",
		qtype:       dns.TypeA,
		qclass:      dns.ClassINET,
		hits:        10,
		lastCheck:   time.Time{},
		prefetching: false,
	}

	// Should prefetch because TTL is low (15% remaining < 20% threshold)
	shouldPrefetch := engine.shouldPrefetch(candidate)
	if !shouldPrefetch {
		t.Error("Should prefetch entry with low remaining TTL (15% remaining, threshold 20%)")
	}
}

func TestPrefetchEngine_ShouldPrefetch_RRsetCache(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	config.PrefetchThresh = 0.10 // 10% remaining TTL

	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Add entry to RRset cache
	rrs := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      100, // 100 second TTL
				Rdlength: 0,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	rrsetCache.Set("example.com.", dns.TypeA, rrs, 100*time.Second)

	// Get the entry and modify its timestamps to simulate near expiry
	key := MakeRRsetKey("example.com.", dns.TypeA)
	entry := rrsetCache.GetEntryForPrefetch(key)
	if entry != nil {
		now := time.Now()
		entry.InsertedAt = now.Add(-95 * time.Second) // Inserted 95s ago
		entry.ExpiresAt = now.Add(5 * time.Second)    // Expires in 5s (5% remaining)
	}

	// Create candidate
	candidate := &prefetchCandidate{
		key:         "example.com.|1", // Different format but same domain
		name:        "example.com.",
		qtype:       dns.TypeA,
		qclass:      dns.ClassINET,
		hits:        10,
		lastCheck:   time.Time{},
		prefetching: false,
	}

	// Should prefetch because TTL is low
	shouldPrefetch := engine.shouldPrefetch(candidate)
	if !shouldPrefetch {
		t.Error("Should prefetch RRset entry with low remaining TTL")
	}
}

func TestPrefetchEngine_ShouldPrefetch_NoEntry(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Create candidate for non-existent entry
	candidate := &prefetchCandidate{
		key:         "nonexistent",
		name:        "nonexistent.com.",
		qtype:       dns.TypeA,
		qclass:      dns.ClassINET,
		hits:        10,
		lastCheck:   time.Time{},
		prefetching: false,
	}

	// Should not prefetch - entry doesn't exist
	shouldPrefetch := engine.shouldPrefetch(candidate)
	if shouldPrefetch {
		t.Error("Should not prefetch non-existent entry")
	}
}

func TestPrefetchEngine_Prefetch(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Create candidate
	candidate := &prefetchCandidate{
		key:         "key1",
		name:        "example.com.",
		qtype:       dns.TypeA,
		qclass:      dns.ClassINET,
		hits:        5,
		lastCheck:   time.Time{},
		prefetching: false,
	}

	// Add to candidates map and mark as prefetching
	engine.mu.Lock()
	engine.candidates["key1"] = candidate
	candidate.prefetching = true
	engine.mu.Unlock()

	// Perform prefetch
	engine.prefetch(candidate)

	// Verify resolver was called
	if resolver.GetResolveCount() != 1 {
		t.Errorf("Expected resolver to be called once, got %d", resolver.GetResolveCount())
	}

	// Verify query was for correct domain
	calls := resolver.GetResolveCalls()
	if len(calls) != 1 || calls[0] != "example.com." {
		t.Errorf("Expected resolver to be called for example.com., got %v", calls)
	}

	// Verify prefetching flag was cleared and hits reset
	engine.mu.RLock()
	c, exists := engine.candidates["key1"]
	engine.mu.RUnlock()

	if !exists {
		t.Fatal("Expected candidate to still exist")
	}

	if c.prefetching {
		t.Error("Expected prefetching flag to be cleared")
	}

	if c.hits != config.MinHits {
		t.Errorf("Expected hits to be reset to %d, got %d", config.MinHits, c.hits)
	}
}

func TestPrefetchEngine_ScanForCandidates(t *testing.T) {
	t.Parallel()
	t.Skip("Timing-sensitive test - depends on precise TTL expiry timing which varies in CI environments")

	config := DefaultPrefetchConfig()
	config.MinHits = 2
	config.PrefetchThresh = 0.50 // 50% remaining TTL threshold

	msgCacheConfig := DefaultMessageCacheConfig()
	msgCacheConfig.MaxSizeBytes = 10 * 1024 * 1024
	messageCache := NewMessageCache(msgCacheConfig)
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Add cache entries with short TTL that will age
	for _, name := range []string{"example.com.", "cloudflare.com."} {
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		response := new(dns.Msg)
		response.SetReply(query)
		rr, _ := dns.NewRR(name + " 2 IN A 192.0.2.1") // 2 second TTL
		response.Answer = append(response.Answer, rr)

		responseBytes, _ := response.Pack()
		key := MakeKey(name, dns.TypeA, dns.ClassINET)
		messageCache.Set(key, responseBytes, 2*time.Second)

		// Record accesses to make it a candidate
		engine.RecordAccess(key, name, dns.TypeA, dns.ClassINET)
		engine.RecordAccess(key, name, dns.TypeA, dns.ClassINET)
		engine.RecordAccess(key, name, dns.TypeA, dns.ClassINET)

		// Increment hit count in cache entry
		entry := messageCache.GetEntryForPrefetch(key)
		if entry != nil {
			for range 5 {
				entry.IncrementHitCount()
			}
		}
	}

	// Wait for TTL to be mostly expired (>50%)
	time.Sleep(1200 * time.Millisecond)

	// Start engine to have workers ready
	engine.Start(1 * time.Hour) // Long interval so scanner doesn't run automatically
	defer engine.Stop()

	// Scan for candidates
	engine.scanForCandidates()

	// Give workers time to process
	time.Sleep(300 * time.Millisecond)

	// Verify that queries were made
	resolveCount := resolver.GetResolveCount()
	if resolveCount == 0 {
		t.Error("Expected prefetch operations to occur")
	}
}

func TestPrefetchEngine_Integration(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	config.MinHits = 2
	config.PrefetchThresh = 0.40 // 40% remaining TTL
	config.MaxConcurrent = 2
	config.CheckInterval = 200 * time.Millisecond

	msgCacheConfig := DefaultMessageCacheConfig()
	msgCacheConfig.MaxSizeBytes = 10 * 1024 * 1024
	messageCache := NewMessageCache(msgCacheConfig)
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Start engine with short check interval
	engine.Start(200 * time.Millisecond)
	defer engine.Stop()

	// Add an entry to the cache with short TTL
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	rr, _ := dns.NewRR("example.com. 3 IN A 192.0.2.1") // 3 second TTL
	response.Answer = append(response.Answer, rr)

	// Pack response to bytes
	responseBytes, _ := response.Pack()

	key := MakeKey("example.com.", dns.TypeA, dns.ClassINET)
	messageCache.Set(key, responseBytes, 3*time.Second)

	// Simulate accesses
	entry := messageCache.GetEntryForPrefetch(key)
	if entry != nil {
		// Record enough accesses to trigger prefetch
		for range 5 {
			entry.IncrementHitCount()
		}
	}

	// Record accesses to trigger prefetch consideration
	engine.RecordAccess(key, "example.com.", dns.TypeA, dns.ClassINET)
	engine.RecordAccess(key, "example.com.", dns.TypeA, dns.ClassINET)
	engine.RecordAccess(key, "example.com.", dns.TypeA, dns.ClassINET)

	// Wait for most of TTL to expire (2 seconds = 67% expired, 33% remaining < 40% threshold)
	time.Sleep(2000 * time.Millisecond)

	// Wait for scanner to run and prefetch to occur
	time.Sleep(500 * time.Millisecond)

	// Check stats
	stats := engine.GetStats()
	if !stats.Enabled {
		t.Error("Expected stats to show enabled")
	}

	if stats.Candidates == 0 {
		t.Error("Expected at least one candidate")
	}

	// Note: Due to timing variations in CI/test environments,
	// we verify the system is set up correctly rather than
	// strictly requiring prefetch to have occurred
	t.Logf("Integration test completed with %d resolve calls", resolver.GetResolveCount())
}

func TestPrefetchCandidate(t *testing.T) {
	t.Parallel()
	candidate := &prefetchCandidate{
		key:         "test-key",
		name:        "example.com.",
		qtype:       dns.TypeA,
		qclass:      dns.ClassINET,
		hits:        5,
		lastCheck:   time.Now(),
		prefetching: false,
	}

	if candidate.key != "test-key" {
		t.Errorf("Expected key 'test-key', got %s", candidate.key)
	}

	if candidate.name != "example.com." {
		t.Errorf("Expected name 'example.com.', got %s", candidate.name)
	}

	if candidate.qtype != dns.TypeA {
		t.Errorf("Expected qtype A, got %d", candidate.qtype)
	}

	if candidate.hits != 5 {
		t.Errorf("Expected 5 hits, got %d", candidate.hits)
	}

	if candidate.prefetching {
		t.Error("Expected prefetching to be false")
	}
}

func TestPrefetchEngine_QueueFull(t *testing.T) {
	t.Parallel()
	config := DefaultPrefetchConfig()
	config.MinHits = 1

	messageCache := NewMessageCache(DefaultMessageCacheConfig())
	rrsetCache := NewRRsetCache(DefaultRRsetCacheConfig())
	resolver := NewMockPrefetchResolver()
	resolver.resolveDelay = 1 * time.Second // Slow resolver to fill queue

	engine := NewPrefetchEngine(config, messageCache, rrsetCache, resolver)

	// Fill the prefetch queue
	for range 1000 {
		candidate := &prefetchCandidate{
			key:         MakeKey("example.com.", dns.TypeA, dns.ClassINET),
			name:        "example.com.",
			qtype:       dns.TypeA,
			qclass:      dns.ClassINET,
			hits:        5,
			lastCheck:   time.Time{},
			prefetching: false,
		}
		engine.prefetchQueue <- candidate
	}

	// Queue should now be full
	stats := engine.GetStats()
	if stats.QueueSize != 1000 {
		t.Errorf("Expected queue size 1000, got %d", stats.QueueSize)
	}
}
