package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
)

// Package-level errors.
var (
	ErrNilResponse      = errors.New("nil response from upstream")
	ErrAllUpstreamsFailed = errors.New("all upstreams failed")
	ErrNilUDPConnection = errors.New("nil UDP connection")
)

// Upstream configuration defaults.
const (
	defaultUpstreamTimeoutSec = 5 // Default upstream query timeout in seconds
	defaultUpstreamMaxRetries = 2 // Default maximum retry attempts
)

// UpstreamPool manages connections to upstream DNS servers
// Uses client pooling for efficient query handling.
type UpstreamPool struct {
	// infraCache tracks server statistics for smart selection
	infraCache *cache.InfraCache

	// timeout is the query timeout
	timeout time.Duration

	// upstreams is the list of upstream server addresses
	upstreams []string

	// mu protects the upstreams list
	mu sync.RWMutex

	// udpPools holds persistent UDP connection pools per upstream
	udpPools map[string]*udpConnPool

	// poolMu protects udpPools
	poolMu sync.RWMutex

	// maxConnsPerUpstream controls pool sizing
	maxConnsPerUpstream int
}

// UpstreamConfig holds configuration for the upstream pool.
type UpstreamConfig struct {
	// Upstreams is the list of upstream DNS servers
	Upstreams []string

	// Timeout is the query timeout
	Timeout time.Duration

	// MaxRetries is the maximum number of retries per query
	MaxRetries int

	// ConnectionsPerUpstream is the max number of persistent UDP sockets per upstream
	ConnectionsPerUpstream int
}

// DefaultUpstreamConfig returns configuration with sensible defaults.
func DefaultUpstreamConfig() UpstreamConfig {
	return UpstreamConfig{
		Upstreams: []string{
			"8.8.8.8:53", // Google DNS
			"8.8.4.4:53", // Google DNS
			"1.1.1.1:53", // Cloudflare DNS
			"1.0.0.1:53", // Cloudflare DNS
		},
		Timeout:                defaultUpstreamTimeoutSec * time.Second, // 5 second timeout
		MaxRetries:             defaultUpstreamMaxRetries,               // 2 retry attempts
		ConnectionsPerUpstream: runtime.NumCPU(),                        // One connection per CPU core
	}
}

// NewUpstreamPool creates a new upstream connection pool.
func NewUpstreamPool(config UpstreamConfig, infraCache *cache.InfraCache) *UpstreamPool {
	timeout := config.Timeout

	maxConns := config.ConnectionsPerUpstream
	if maxConns <= 0 {
		maxConns = runtime.NumCPU()
	}

	pool := &UpstreamPool{
		infraCache:          infraCache,
		timeout:             timeout,
		upstreams:           config.Upstreams,
		mu:                  sync.RWMutex{},
		udpPools:            make(map[string]*udpConnPool),
		poolMu:              sync.RWMutex{},
		maxConnsPerUpstream: maxConns,
	}

	for _, addr := range config.Upstreams {
		pool.udpPools[addr] = newUDPConnPool(addr, maxConns, timeout)
	}

	return pool
}

// Query sends a DNS query to an upstream server
// Automatically selects the best upstream based on statistics.
func (up *UpstreamPool) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	up.mu.RLock()
	upstreams := up.upstreams
	up.mu.RUnlock()

	if len(upstreams) == 0 {
		return nil, &net.OpError{
			Op:     "query",
			Net:    "",
			Source: nil,
			Addr:   nil,
			Err:    net.ErrClosed,
		}
	}

	// Select best upstream server
	addr := up.infraCache.SelectBest(upstreams)
	stats := up.infraCache.GetOrCreate(addr)

	// Record query start
	stats.RecordQueryStart()
	defer stats.RecordQueryEnd()

	queryCtx, cancel := context.WithTimeout(ctx, up.timeout)
	defer cancel()

	pool := up.getPool(addr)
	conn, err := pool.Get(queryCtx)
	if err != nil {
		stats.RecordFailure()

		return nil, err
	}

	response, rtt, err := up.exchangeWithConn(queryCtx, conn, msg)
	if err != nil {
		pool.Discard(conn)
		stats.RecordFailure()

		return nil, err
	}

	pool.Put(conn)

	if response == nil {
		stats.RecordFailure()

		return nil, ErrNilResponse
	}

	stats.RecordSuccess(rtt)

	// Check for truncated response - retry with TCP
	if response.Truncated {
		return up.queryTCP(ctx, msg, addr, stats)
	}

	return response, nil
}

// Close closes the upstream pool
// dns.Client doesn't need explicit closing.
func (up *UpstreamPool) Close() error {
	up.poolMu.Lock()
	defer up.poolMu.Unlock()

	for addr, pool := range up.udpPools {
		pool.Close()
		delete(up.udpPools, addr)
	}

	return nil
}

// QueryParallel queries multiple upstreams simultaneously and returns the fastest good response.
// numParallel specifies how many upstreams to query at once.
// successRcodes defines which response codes are considered successful (e.g., [0, 3] for NOERROR, NXDOMAIN).
func (up *UpstreamPool) QueryParallel(ctx context.Context, msg *dns.Msg, numParallel int, successRcodes []int) (*dns.Msg, error) {
	up.mu.RLock()
	upstreams := up.upstreams
	up.mu.RUnlock()

	if len(upstreams) == 0 {
		return nil, &net.OpError{
			Op:   "query",
			Err:  net.ErrClosed,
		}
	}

	// Select best N upstreams based on infrastructure cache stats
	selectedUpstreams := up.selectBestUpstreams(upstreams, numParallel)

	// Create result channel - buffered to avoid goroutine leaks
	type result struct {
		response *dns.Msg
		err      error
		upstream string
		rtt      time.Duration
	}
	results := make(chan result, len(selectedUpstreams))

	// Create a context that we can cancel once we get a good response
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Launch parallel queries
	for _, addr := range selectedUpstreams {
		go func(upstream string) {
			stats := up.infraCache.GetOrCreate(upstream)
			stats.RecordQueryStart()
			defer stats.RecordQueryEnd()

			attemptCtx, attemptCancel := context.WithTimeout(queryCtx, up.timeout)
			defer attemptCancel()

			response, rtt, err := up.executeQueryAttempt(attemptCtx, msg, upstream, stats)
			if err != nil {
				results <- result{nil, err, upstream, 0}
				return
			}

			// Check for truncated response - retry with TCP
			if response.Truncated {
				tcpResponse, tcpErr := up.queryTCP(attemptCtx, msg, upstream, stats)
				if tcpErr != nil {
					results <- result{nil, tcpErr, upstream, rtt}
					return
				}
				response = tcpResponse
			}

			stats.RecordSuccess(rtt)
			results <- result{response, nil, upstream, rtt}
		}(addr)
	}

	// Build success rcode map for fast lookup
	successMap := make(map[int]bool, len(successRcodes))
	for _, rc := range successRcodes {
		successMap[rc] = true
	}

	// Collect responses, return first good one
	var lastErr error
	responsesReceived := 0

	for responsesReceived < len(selectedUpstreams) {
		select {
		case res := <-results:
			responsesReceived++

			if res.err != nil {
				lastErr = res.err
				continue
			}

			// Check if response code is considered successful
			if successMap[res.response.Rcode] {
				// Got a good response - cancel other queries and return
				cancel()
				return res.response, nil
			}

			// Response received but not a success code (e.g., SERVFAIL, REFUSED)
			lastErr = fmt.Errorf("upstream %s returned rcode %d", res.upstream, res.response.Rcode)

		case <-ctx.Done():
			return nil, fmt.Errorf("parallel query cancelled: %w", ctx.Err())
		}
	}

	// All queries failed or returned non-success codes
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrAllUpstreamsFailed
}

// selectBestUpstreams selects the best N upstreams based on infrastructure cache stats.
func (up *UpstreamPool) selectBestUpstreams(upstreams []string, n int) []string {
	if len(upstreams) <= n {
		return upstreams
	}

	// Get stats for all upstreams and sort by performance
	type upstreamScore struct {
		addr  string
		score float64
	}

	scores := make([]upstreamScore, len(upstreams))
	for i, addr := range upstreams {
		stats := up.infraCache.GetOrCreate(addr)
		snapshot := stats.GetSnapshot()
		// Lower score is better: weight RTT heavily, penalize failures
		// Score = RTT_ms + (failureRate * 1000)
		// RTT is already in milliseconds as float64
		score := snapshot.RTT + (snapshot.FailureRate * 1000)
		scores[i] = upstreamScore{addr, score}
	}

	// Simple selection sort for small N (typically 3-4)
	for i := 0; i < n && i < len(scores)-1; i++ {
		minIdx := i
		for j := i + 1; j < len(scores); j++ {
			if scores[j].score < scores[minIdx].score {
				minIdx = j
			}
		}
		scores[i], scores[minIdx] = scores[minIdx], scores[i]
	}

	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = scores[i].addr
	}

	return result
}

// QueryWithFallback queries upstream with automatic fallback to other servers on failure.
func (up *UpstreamPool) QueryWithFallback(ctx context.Context, msg *dns.Msg, maxRetries int) (*dns.Msg, error) {
	up.mu.RLock()
	upstreams := up.upstreams
	up.mu.RUnlock()

	if len(upstreams) == 0 {
		return nil, &net.OpError{
			Op:     "query",
			Net:    "",
			Source: nil,
			Addr:   nil,
			Err:    net.ErrClosed,
		}
	}

	var lastErr error

	for range maxRetries {
		response, err := up.attemptQueryWithFallback(ctx, msg, upstreams)
		if err != nil {
			lastErr = err

			continue
		}

		return response, nil
	}

	// All attempts failed
	if lastErr == nil {
		lastErr = ErrAllUpstreamsFailed
	}

	return nil, lastErr
}

// SetUpstreams updates the list of upstream servers.
func (up *UpstreamPool) SetUpstreams(upstreams []string) {
	up.mu.Lock()
	defer up.mu.Unlock()
	up.upstreams = upstreams

	up.poolMu.Lock()
	defer up.poolMu.Unlock()

	active := make(map[string]struct{}, len(upstreams))
	for _, addr := range upstreams {
		active[addr] = struct{}{}
		if _, exists := up.udpPools[addr]; !exists {
			up.udpPools[addr] = newUDPConnPool(addr, up.maxConnsPerUpstream, up.timeout)
		}
	}

	for addr, pool := range up.udpPools {
		if _, keep := active[addr]; !keep {
			pool.Close()
			delete(up.udpPools, addr)
		}
	}
}

// GetUpstreams returns the current list of upstream servers.
func (up *UpstreamPool) GetUpstreams() []string {
	up.mu.RLock()
	defer up.mu.RUnlock()

	result := make([]string, len(up.upstreams))
	copy(result, up.upstreams)

	return result
}

// GetStats returns statistics for all upstream servers.
func (up *UpstreamPool) GetStats() []cache.UpstreamSnapshot {
	return up.infraCache.GetAllStats()
}

// attemptQueryWithFallback performs a single query attempt with automatic failover.
func (up *UpstreamPool) attemptQueryWithFallback(
	ctx context.Context,
	msg *dns.Msg,
	upstreams []string,
) (*dns.Msg, error) {
	// Select best upstream (may be different after failures)
	addr := up.infraCache.SelectBest(upstreams)
	stats := up.infraCache.GetOrCreate(addr)

	stats.RecordQueryStart()
	defer stats.RecordQueryEnd()

	attemptCtx, cancelAttempt := context.WithTimeout(ctx, up.timeout)
	defer cancelAttempt()

	// Get connection and execute query
	response, rtt, err := up.executeQueryAttempt(attemptCtx, msg, addr, stats)
	if err != nil {
		return nil, err
	}

	stats.RecordSuccess(rtt)

	// Check for truncated response - retry with TCP
	if response.Truncated {
		return up.queryTCP(ctx, msg, addr, stats)
	}

	return response, nil
}

// executeQueryAttempt executes a single query attempt on a specific upstream.
func (up *UpstreamPool) executeQueryAttempt(
	ctx context.Context,
	msg *dns.Msg,
	addr string,
	stats *cache.UpstreamStats,
) (*dns.Msg, time.Duration, error) {
	pool := up.getPool(addr)
	conn, err := pool.Get(ctx)
	if err != nil {
		stats.RecordFailure()

		return nil, 0, err
	}

	response, rtt, err := up.exchangeWithConn(ctx, conn, msg)
	if err != nil {
		pool.Discard(conn)
		stats.RecordFailure()

		return nil, 0, err
	}

	pool.Put(conn)

	if response == nil {
		stats.RecordFailure()

		return nil, 0, ErrNilResponse
	}

	return response, rtt, nil
}

// queryTCP performs a query over TCP (for truncated responses).
func (up *UpstreamPool) queryTCP(
	ctx context.Context,
	msg *dns.Msg,
	addr string,
	stats *cache.UpstreamStats,
) (*dns.Msg, error) {
	tcpClient := &dns.Client{
		Net:            "tcp",
		UDPSize:        0,
		TLSConfig:      nil,
		Dialer:         nil,
		Timeout:        up.timeout,
		DialTimeout:    0,
		ReadTimeout:    0,
		WriteTimeout:   0,
		TsigSecret:     nil,
		TsigProvider:   nil,
		SingleInflight: false,
	}

	start := time.Now()
	response, rtt, err := tcpClient.ExchangeContext(ctx, msg, addr)

	if err != nil {
		stats.RecordFailure()

		return nil, fmt.Errorf("TCP query to upstream failed: %w", err)
	}

	stats.RecordSuccess(rtt)
	_ = start // For future logging

	return response, nil
}

// exchangeWithConn performs a single query over an existing UDP connection.
func (up *UpstreamPool) exchangeWithConn(
	ctx context.Context,
	conn *dns.Conn,
	msg *dns.Msg,
) (*dns.Msg, time.Duration, error) {
	if conn == nil {
		return nil, 0, ErrNilUDPConnection
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(up.timeout)
	}

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	start := time.Now()
	if err := conn.WriteMsg(msg); err != nil {
		return nil, 0, fmt.Errorf("failed to write DNS message: %w", err)
	}

	response, err := conn.ReadMsg()
	rtt := time.Since(start)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read DNS response: %w", err)
	}

	return response, rtt, nil
}

// getPool returns (creating if needed) the UDP connection pool for an address.
func (up *UpstreamPool) getPool(addr string) *udpConnPool {
	up.poolMu.RLock()
	pool := up.udpPools[addr]
	up.poolMu.RUnlock()

	if pool != nil {
		return pool
	}

	up.poolMu.Lock()
	defer up.poolMu.Unlock()

	if pool, ok := up.udpPools[addr]; ok {
		return pool
	}

	pool = newUDPConnPool(addr, up.maxConnsPerUpstream, up.timeout)
	up.udpPools[addr] = pool

	return pool
}

type udpConnPool struct {
	addr    string
	timeout time.Duration
	size    int

	conns chan *dns.Conn

	mu    sync.Mutex
	total int
}

func newUDPConnPool(addr string, size int, timeout time.Duration) *udpConnPool {
	if size <= 0 {
		size = runtime.NumCPU()
	}

	return &udpConnPool{
		addr:    addr,
		timeout: timeout,
		size:    size,
		conns:   make(chan *dns.Conn, size),
		mu:      sync.Mutex{},
		total:   0,
	}
}

func (p *udpConnPool) Get(ctx context.Context) (*dns.Conn, error) {
	select {
	case conn := <-p.conns:
		return conn, nil
	default:
	}

	if p.incrementTotal() {
		conn, err := p.dial(ctx)
		if err != nil {
			p.decrementTotal()

			return nil, err
		}

		return conn, nil
	}

	select {
	case conn := <-p.conns:
		return conn, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("connection pool get cancelled: %w", ctx.Err())
	}
}

func (p *udpConnPool) Put(conn *dns.Conn) {
	if conn == nil {
		return
	}

	_ = conn.SetDeadline(time.Time{})

	select {
	case p.conns <- conn:
	default:
		_ = conn.Close()
		p.decrementTotal()
	}
}

func (p *udpConnPool) Discard(conn *dns.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
	p.decrementTotal()
}

func (p *udpConnPool) Close() {
	for {
		select {
		case conn := <-p.conns:
			_ = conn.Close()
			p.decrementTotal()
		default:
			return
		}
	}
}

func (p *udpConnPool) incrementTotal() bool {
	if p.size <= 0 {
		return true
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.total >= p.size {
		return false
	}

	p.total++

	return true
}

func (p *udpConnPool) decrementTotal() {
	if p.size <= 0 {
		return
	}

	p.mu.Lock()
	if p.total > 0 {
		p.total--
	}
	p.mu.Unlock()
}

func (p *udpConnPool) dial(ctx context.Context) (*dns.Conn, error) {
	timeout := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && (timeout == 0 || remaining < timeout) {
			timeout = remaining
		}
	}

	dialer := &net.Dialer{
		Timeout:       timeout,
		Deadline:      time.Time{},
		LocalAddr:     nil,
		DualStack:     false,
		FallbackDelay: 0,
		KeepAlive:     0,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   false,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
		Resolver:       nil,
		Cancel:         nil,
		Control:        nil,
		ControlContext: nil,
	}

	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	client := &dns.Client{
		Net:            "udp",
		UDPSize:        0,
		TLSConfig:      nil,
		Dialer:         dialer,
		Timeout:        timeout,
		DialTimeout:    timeout,
		ReadTimeout:    0,
		WriteTimeout:   0,
		TsigSecret:     nil,
		TsigProvider:   nil,
		SingleInflight: false,
	}

	conn, err := client.DialContext(ctx, p.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial upstream %s: %w", p.addr, err)
	}

	return conn, nil
}
