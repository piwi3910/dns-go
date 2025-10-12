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
		Timeout:                5 * time.Second,
		MaxRetries:             2,
		ConnectionsPerUpstream: runtime.NumCPU(),
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

		return nil, errors.New("nil response from upstream")
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
		// Select best upstream (may be different after failures)
		addr := up.infraCache.SelectBest(upstreams)
		stats := up.infraCache.GetOrCreate(addr)

		stats.RecordQueryStart()
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, up.timeout)

		pool := up.getPool(addr)
		conn, err := pool.Get(attemptCtx)
		if err != nil {
			cancelAttempt()
			stats.RecordFailure()
			stats.RecordQueryEnd()
			lastErr = err

			continue
		}

		response, rtt, err := up.exchangeWithConn(attemptCtx, conn, msg)
		cancelAttempt()
		if err != nil {
			pool.Discard(conn)
			stats.RecordFailure()
			stats.RecordQueryEnd()
			lastErr = err

			continue
		}

		pool.Put(conn)
		stats.RecordQueryEnd()

		if response == nil {
			stats.RecordFailure()
			lastErr = errors.New("nil response from upstream")

			continue
		}

		stats.RecordSuccess(rtt)

		// Check for truncated response - retry with TCP
		if response.Truncated {
			tcpResponse, tcpErr := up.queryTCP(ctx, msg, addr, stats)
			if tcpErr == nil {
				return tcpResponse, nil
			}
			lastErr = tcpErr

			continue
		}

		return response, nil
	}

	// All attempts failed
	if lastErr == nil {
		lastErr = errors.New("all upstreams failed")
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
		return nil, 0, errors.New("nil UDP connection")
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
