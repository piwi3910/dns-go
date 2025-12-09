package resolver

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
)

// mockUpstreamServer simulates an upstream DNS server for testing.
type mockUpstreamServer struct {
	addr     string
	listener net.PacketConn
	response *dns.Msg
	delay    time.Duration
	rcode    int
	closed   atomic.Bool
}

func newMockUpstreamServer(t *testing.T, delay time.Duration, rcode int) *mockUpstreamServer {
	t.Helper()

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	server := &mockUpstreamServer{
		addr:     listener.LocalAddr().String(),
		listener: listener,
		delay:    delay,
		rcode:    rcode,
	}

	go server.serve(t)

	return server
}

func (s *mockUpstreamServer) serve(t *testing.T) {
	t.Helper()

	buf := make([]byte, 512)
	for {
		if s.closed.Load() {
			return
		}

		_ = s.listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := s.listener.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// Parse query
		query := new(dns.Msg)
		if err := query.Unpack(buf[:n]); err != nil {
			continue
		}

		// Simulate delay
		if s.delay > 0 {
			time.Sleep(s.delay)
		}

		// Build response
		response := new(dns.Msg)
		response.SetReply(query)
		response.Rcode = s.rcode

		if s.rcode == dns.RcodeSuccess && len(query.Question) > 0 {
			// Add a dummy A record
			rr, _ := dns.NewRR(query.Question[0].Name + " 300 IN A 192.0.2.1")
			response.Answer = append(response.Answer, rr)
		}

		respBytes, _ := response.Pack()
		_, _ = s.listener.WriteTo(respBytes, addr)
	}
}

func (s *mockUpstreamServer) close() {
	s.closed.Store(true)
	_ = s.listener.Close()
}

func TestQueryParallel_FastestWins(t *testing.T) {
	// Create three mock servers with different delays
	slowServer := newMockUpstreamServer(t, 500*time.Millisecond, dns.RcodeSuccess)
	mediumServer := newMockUpstreamServer(t, 100*time.Millisecond, dns.RcodeSuccess)
	fastServer := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeSuccess)

	defer slowServer.close()
	defer mediumServer.close()
	defer fastServer.close()

	// Create upstream pool with these servers
	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams: []string{
			slowServer.addr,
			mediumServer.addr,
			fastServer.addr,
		},
		Timeout:                2 * time.Second,
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	// Create query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Query in parallel
	ctx := context.Background()
	start := time.Now()
	response, err := pool.QueryParallel(ctx, query, 3, []int{dns.RcodeSuccess, dns.RcodeNameError})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("QueryParallel failed: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got rcode %d", response.Rcode)
	}

	// Should complete faster than slowest server
	if elapsed > 400*time.Millisecond {
		t.Errorf("Expected fast response, got %v (should be < 400ms)", elapsed)
	}

	t.Logf("Parallel query completed in %v", elapsed)
}

func TestQueryParallel_SkipsBadResponses(t *testing.T) {
	// Create servers: two return SERVFAIL, one returns success (but slower)
	badServer1 := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeServerFailure)
	badServer2 := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeRefused)
	goodServer := newMockUpstreamServer(t, 50*time.Millisecond, dns.RcodeSuccess)

	defer badServer1.close()
	defer badServer2.close()
	defer goodServer.close()

	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams: []string{
			badServer1.addr,
			badServer2.addr,
			goodServer.addr,
		},
		Timeout:                2 * time.Second,
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	response, err := pool.QueryParallel(ctx, query, 3, []int{dns.RcodeSuccess, dns.RcodeNameError})

	if err != nil {
		t.Fatalf("QueryParallel failed: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	// Should get success response despite bad servers responding first
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got rcode %d", response.Rcode)
	}
}

func TestQueryParallel_NXDOMAINIsValid(t *testing.T) {
	// NXDOMAIN should be considered a valid response
	nxdomainServer := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeNameError)
	defer nxdomainServer.close()

	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams:              []string{nxdomainServer.addr},
		Timeout:                2 * time.Second,
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	query := new(dns.Msg)
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)

	ctx := context.Background()
	response, err := pool.QueryParallel(ctx, query, 1, []int{dns.RcodeSuccess, dns.RcodeNameError})

	if err != nil {
		t.Fatalf("QueryParallel failed: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got rcode %d", response.Rcode)
	}
}

func TestQueryParallel_AllFail(t *testing.T) {
	// All servers return SERVFAIL
	badServer1 := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeServerFailure)
	badServer2 := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeServerFailure)

	defer badServer1.close()
	defer badServer2.close()

	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams: []string{
			badServer1.addr,
			badServer2.addr,
		},
		Timeout:                2 * time.Second,
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	_, err := pool.QueryParallel(ctx, query, 2, []int{dns.RcodeSuccess, dns.RcodeNameError})

	if err == nil {
		t.Error("Expected error when all upstreams fail")
	}
}

func TestQueryParallel_Timeout(t *testing.T) {
	// Server that never responds (very long delay)
	slowServer := newMockUpstreamServer(t, 10*time.Second, dns.RcodeSuccess)
	defer slowServer.close()

	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams:              []string{slowServer.addr},
		Timeout:                100 * time.Millisecond, // Short timeout
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := pool.QueryParallel(ctx, query, 1, []int{dns.RcodeSuccess})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error")
	}

	// Should timeout quickly, not wait for the full server delay
	if elapsed > 500*time.Millisecond {
		t.Errorf("Expected fast timeout, got %v", elapsed)
	}
}

func TestSelectBestUpstreams(t *testing.T) {
	infraCache := cache.NewInfraCache()
	config := UpstreamConfig{
		Upstreams: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"9.9.9.9:53",
			"208.67.222.222:53",
		},
		Timeout:                time.Second,
		ConnectionsPerUpstream: 2,
	}
	pool := NewUpstreamPool(config, infraCache)
	defer pool.Close()

	// Simulate different RTT stats
	stats1 := infraCache.GetOrCreate("8.8.8.8:53")
	stats1.RecordSuccess(50 * time.Millisecond) // Fast

	stats2 := infraCache.GetOrCreate("1.1.1.1:53")
	stats2.RecordSuccess(20 * time.Millisecond) // Fastest

	stats3 := infraCache.GetOrCreate("9.9.9.9:53")
	stats3.RecordSuccess(100 * time.Millisecond) // Slow

	stats4 := infraCache.GetOrCreate("208.67.222.222:53")
	stats4.RecordFailure() // Worst - has failure

	// Select best 2
	selected := pool.selectBestUpstreams(pool.upstreams, 2)

	if len(selected) != 2 {
		t.Fatalf("Expected 2 upstreams, got %d", len(selected))
	}

	// Best should be 1.1.1.1 (fastest RTT)
	if selected[0] != "1.1.1.1:53" {
		t.Errorf("Expected 1.1.1.1:53 as best, got %s", selected[0])
	}

	// Second should be 8.8.8.8 (second fastest)
	if selected[1] != "8.8.8.8:53" {
		t.Errorf("Expected 8.8.8.8:53 as second, got %s", selected[1])
	}
}

func TestParallelModeResolver(t *testing.T) {
	// Create mock servers
	server1 := newMockUpstreamServer(t, 50*time.Millisecond, dns.RcodeSuccess)
	server2 := newMockUpstreamServer(t, 10*time.Millisecond, dns.RcodeSuccess)

	defer server1.close()
	defer server2.close()

	// Create resolver in parallel mode
	infraCache := cache.NewInfraCache()
	upstreamConfig := UpstreamConfig{
		Upstreams: []string{
			server1.addr,
			server2.addr,
		},
		Timeout:                2 * time.Second,
		ConnectionsPerUpstream: 2,
	}
	upstreamPool := NewUpstreamPool(upstreamConfig, infraCache)
	defer upstreamPool.Close()

	resolverConfig := Config{
		Mode:         ParallelMode,
		QueryTimeout: 5 * time.Second,
		ParallelConfig: ParallelConfig{
			NumParallel:         2,
			FallbackToRecursive: false, // Don't fallback for this test
			SuccessRcodes:       []int{0, 3},
		},
	}

	resolver := NewResolver(resolverConfig, upstreamPool)

	// Create query
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	ctx := context.Background()
	response, err := resolver.Resolve(ctx, query)

	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got rcode %d", response.Rcode)
	}
}
