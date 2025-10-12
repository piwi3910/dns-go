package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
	"github.com/piwi3910/dns-go/pkg/dnssec"
)

func TestDefaultResolverConfig(t *testing.T) {
	t.Parallel()
	config := DefaultResolverConfig()

	if config.Mode != RecursiveMode {
		t.Errorf("Expected RecursiveMode, got %v", config.Mode)
	}

	if config.WorkerPoolSize != 1000 {
		t.Errorf("Expected worker pool size 1000, got %d", config.WorkerPoolSize)
	}

	if config.MaxRetries != 2 {
		t.Errorf("Expected 2 retries, got %d", config.MaxRetries)
	}

	if config.QueryTimeout != 5*time.Second {
		t.Errorf("Expected 5s timeout, got %v", config.QueryTimeout)
	}

	if !config.EnableCoalescing {
		t.Error("Expected coalescing to be enabled")
	}

	if !config.EnableDNSSEC {
		t.Error("Expected DNSSEC to be enabled")
	}
}

func TestDefaultForwardingConfig(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()

	if config.Mode != ForwardingMode {
		t.Errorf("Expected ForwardingMode, got %v", config.Mode)
	}
}

// Helper function to create test upstream pool.
func createTestUpstreamPool(upstreams []string) *UpstreamPool {
	config := UpstreamConfig{
		Upstreams:              upstreams,
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: 4,
	}
	infraCache := cache.NewInfraCache()

	return NewUpstreamPool(config, infraCache)
}

func TestNewResolver(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})

	resolver := NewResolver(config, upstream)

	if resolver == nil {
		t.Fatal("Expected resolver to be created")
	}

	if resolver.upstream != upstream {
		t.Error("Upstream pool not set correctly")
	}

	if resolver.config.Mode != ForwardingMode {
		t.Error("Config not set correctly")
	}

	if !resolver.dnssecEnabled {
		t.Error("DNSSEC should be enabled by default")
	}

	if resolver.dnssecValidator == nil {
		t.Error("DNSSEC validator should be initialized")
	}
}

func TestNewResolver_RecursiveMode(t *testing.T) {
	t.Parallel()
	config := DefaultResolverConfig()
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})

	resolver := NewResolver(config, upstream)

	if resolver.iterative == nil {
		t.Error("Iterative resolver should be initialized in recursive mode")
	}
}

func TestNewResolver_DNSSECDisabled(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	config.EnableDNSSEC = false
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})

	resolver := NewResolver(config, upstream)

	if resolver.dnssecEnabled {
		t.Error("DNSSEC should be disabled")
	}

	if resolver.dnssecValidator != nil {
		t.Error("DNSSEC validator should not be initialized")
	}
}

func TestResolve_NoQuestions(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	query := &dns.Msg{}
	// No questions

	ctx := context.Background()
	_, err := resolver.Resolve(ctx, query)

	if err == nil {
		t.Error("Expected error for query with no questions")
	}
}

func TestMakeQueryKey(t *testing.T) {
	t.Parallel()
	key1 := makeQueryKey("example.com.", dns.TypeA, dns.ClassINET)
	key2 := makeQueryKey("example.com.", dns.TypeA, dns.ClassINET)
	key3 := makeQueryKey("example.com.", dns.TypeAAAA, dns.ClassINET)

	if key1 != key2 {
		t.Error("Same query should generate same key")
	}

	if key1 == key3 {
		t.Error("Different query types should generate different keys")
	}
}

func TestGetStats(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	// Record some upstream stats so they appear in GetStats()
	upstreamStats := resolver.upstream.infraCache.GetOrCreate("8.8.8.8:53")
	upstreamStats.RecordSuccess(25 * time.Millisecond)

	stats := resolver.GetStats()

	if stats.InFlightQueries != 0 {
		t.Errorf("Expected 0 in-flight queries, got %d", stats.InFlightQueries)
	}

	if len(stats.Upstreams) == 0 {
		t.Error("Expected upstream stats")
	}
}

func TestResolveWithCoalescing_SameQuery(t *testing.T) {
	t.Parallel()
	query1 := &dns.Msg{}
	query1.SetQuestion("example.com.", dns.TypeA)

	query2 := &dns.Msg{}
	query2.SetQuestion("example.com.", dns.TypeA)

	// Both should use the same query key
	key1 := makeQueryKey(query1.Question[0].Name, query1.Question[0].Qtype, query1.Question[0].Qclass)
	key2 := makeQueryKey(query2.Question[0].Name, query2.Question[0].Qtype, query2.Question[0].Qclass)

	if key1 != key2 {
		t.Error("Same queries should have same key for coalescing")
	}
}

func TestDoResolve_UnknownMode(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	config.Mode = RecursionMode(999) // Invalid mode
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	_, err := resolver.Resolve(ctx, query)

	if err == nil {
		t.Error("Expected error for unknown recursion mode")
	}
}

func TestResolveWithCoalescing_Disabled(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	config.EnableCoalescing = false
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)

	// With coalescing disabled, should go directly to doResolve
	// We can't easily test the actual resolution without mocking,
	// but we can verify the path is taken
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This will timeout or fail to resolve, but verifies the code path
	_, _ = resolver.Resolve(ctx, query)
}

func TestDoRecursiveResolve_NoIterativeResolver(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig() // ForwardingMode
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	// Manually set mode to recursive but don't initialize iterative resolver
	resolver.config.Mode = RecursiveMode
	resolver.iterative = nil

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	_, err := resolver.Resolve(ctx, query)

	if err == nil {
		t.Error("Expected error when iterative resolver not initialized")
	}
}

func TestDoRecursiveResolve_NoQuestions(t *testing.T) {
	t.Parallel()
	config := DefaultResolverConfig()
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	query := &dns.Msg{}
	// No questions

	ctx := context.Background()
	_, err := resolver.doRecursiveResolve(ctx, query)

	if err == nil {
		t.Error("Expected error for query with no questions")
	}
}

func TestInflightRequest(t *testing.T) {
	t.Parallel()
	inflight := &inflightRequest{
		done: make(chan struct{}),
	}

	// Test waiters count
	inflight.mu.Lock()
	inflight.waiters++
	inflight.mu.Unlock()

	if inflight.waiters != 1 {
		t.Errorf("Expected 1 waiter, got %d", inflight.waiters)
	}

	// Test done channel
	select {
	case <-inflight.done:
		t.Error("Done channel should not be closed yet")
	default:
		// Expected
	}

	close(inflight.done)

	select {
	case <-inflight.done:
		// Expected
	default:
		t.Error("Done channel should be closed")
	}
}

func TestResolverConfig_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		modify func(*ResolverConfig)
		valid  bool
	}{
		{
			name:   "Default config valid",
			modify: func(c *ResolverConfig) {},
			valid:  true,
		},
		{
			name: "Zero worker pool size",
			modify: func(c *ResolverConfig) {
				c.WorkerPoolSize = 0
			},
			valid: true, // No validation currently, but should work
		},
		{
			name: "Negative retries",
			modify: func(c *ResolverConfig) {
				c.MaxRetries = -1
			},
			valid: true, // No validation currently
		},
		{
			name: "Zero timeout",
			modify: func(c *ResolverConfig) {
				c.QueryTimeout = 0
			},
			valid: true, // Will use default behavior
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			config := DefaultResolverConfig()
			tt.modify(&config)

			upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
			resolver := NewResolver(config, upstream)

			if resolver == nil && tt.valid {
				t.Error("Expected resolver to be created for valid config")
			}
		})
	}
}

func TestResolverStats(t *testing.T) {
	t.Parallel()
	stats := ResolverStats{
		InFlightQueries: 5,
		Upstreams:       []cache.UpstreamSnapshot{{Address: "8.8.8.8:53", TotalQueries: 100}},
	}

	if stats.InFlightQueries != 5 {
		t.Errorf("Expected 5 in-flight queries, got %d", stats.InFlightQueries)
	}

	if len(stats.Upstreams) != 1 {
		t.Errorf("Expected 1 upstream, got %d", len(stats.Upstreams))
	}
}

func TestDNSSECIntegration(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	config.EnableDNSSEC = true
	config.DNSSECConfig = dnssec.DefaultValidatorConfig()

	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	if !resolver.dnssecEnabled {
		t.Error("DNSSEC should be enabled")
	}

	if resolver.dnssecValidator == nil {
		t.Error("DNSSEC validator should be initialized")
	}
}

func TestCoalescingInFlightMap(t *testing.T) {
	t.Parallel()
	config := DefaultForwardingConfig()
	config.EnableCoalescing = true
	upstream := createTestUpstreamPool([]string{"8.8.8.8:53"})
	resolver := NewResolver(config, upstream)

	if resolver.inFlight == nil {
		t.Error("In-flight map should be initialized")
	}

	if len(resolver.inFlight) != 0 {
		t.Error("In-flight map should be empty initially")
	}
}
