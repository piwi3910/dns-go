package security

import (
	"net"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting per client IP
// This prevents DNS amplification attacks and abuse.
type RateLimiter struct {
	buckets  map[string]*TokenBucket
	mu       sync.RWMutex
	config   RateLimitConfig
	cleanupT *time.Ticker
	stopCh   chan struct{}
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	// QueriesPerSecond is the maximum queries per second per IP
	QueriesPerSecond int

	// BurstSize is the maximum burst size (tokens in bucket)
	BurstSize int

	// CleanupInterval is how often to clean up old buckets
	CleanupInterval time.Duration

	// BucketTTL is how long to keep inactive buckets
	BucketTTL time.Duration

	// Enabled enables rate limiting
	Enabled bool

	// WhitelistedIPs are IPs exempt from rate limiting
	WhitelistedIPs []string
}

// DefaultRateLimitConfig returns sensible defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		QueriesPerSecond: 100,             // 100 QPS per IP
		BurstSize:        200,             // Allow burst of 200
		CleanupInterval:  1 * time.Minute, // Clean up every minute
		BucketTTL:        5 * time.Minute, // Keep buckets for 5 minutes
		Enabled:          true,            // Enabled by default
		WhitelistedIPs:   []string{},      // No whitelist by default
	}
}

// TokenBucket implements the token bucket algorithm.
type TokenBucket struct {
	tokens       float64
	maxTokens    float64
	refillRate   float64 // tokens per nanosecond
	lastRefill   time.Time
	lastActivity time.Time
	mu           sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*TokenBucket),
		mu:       sync.RWMutex{},
		config:   config,
		cleanupT: nil,
		stopCh:   make(chan struct{}),
	}

	if config.Enabled {
		// Start cleanup goroutine
		rl.cleanupT = time.NewTicker(config.CleanupInterval)
		go rl.cleanup()
	}

	return rl
}

// Allow checks if a request from the given address should be allowed.
func (rl *RateLimiter) Allow(addr net.Addr) bool {
	if !rl.config.Enabled {
		return true
	}

	// Extract IP from address
	ip := extractIP(addr)
	if ip == "" {
		return true // Allow if we can't extract IP
	}

	// Check whitelist
	if rl.isWhitelisted(ip) {
		return true
	}

	// Get or create bucket for this IP
	bucket := rl.getBucket(ip)

	// Try to consume a token
	return bucket.consume()
}

// getBucket gets or creates a token bucket for an IP.
func (rl *RateLimiter) getBucket(ip string) *TokenBucket {
	rl.mu.RLock()
	bucket, exists := rl.buckets[ip]
	rl.mu.RUnlock()

	if exists {
		return bucket
	}

	// Create new bucket
	rl.mu.Lock()
	// Double-check after acquiring write lock
	bucket, exists = rl.buckets[ip]
	if !exists {
		bucket = &TokenBucket{
			tokens:       float64(rl.config.BurstSize),
			maxTokens:    float64(rl.config.BurstSize),
			refillRate:   float64(rl.config.QueriesPerSecond) / float64(time.Second),
			lastRefill:   time.Now(),
			lastActivity: time.Now(),
			mu:           sync.Mutex{},
		}
		rl.buckets[ip] = bucket
	}
	rl.mu.Unlock()

	return bucket
}

// consume tries to consume one token from the bucket.
func (tb *TokenBucket) consume() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := float64(elapsed) * tb.refillRate

	tb.tokens += tokensToAdd
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	// Try to consume a token
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		tb.lastActivity = now

		return true
	}

	return false
}

// cleanup periodically removes old buckets.
func (rl *RateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupT.C:
			rl.doCleanup()
		case <-rl.stopCh:
			return
		}
	}
}

// doCleanup removes buckets that haven't been used recently.
func (rl *RateLimiter) doCleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-rl.config.BucketTTL)

	for ip, bucket := range rl.buckets {
		bucket.mu.Lock()
		lastActivity := bucket.lastActivity
		bucket.mu.Unlock()

		if lastActivity.Before(threshold) {
			delete(rl.buckets, ip)
		}
	}
}

// Stop stops the rate limiter cleanup goroutine.
func (rl *RateLimiter) Stop() {
	if rl.cleanupT != nil {
		rl.cleanupT.Stop()
	}
	close(rl.stopCh)
}

// isWhitelisted checks if an IP is whitelisted.
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	for _, whitelistedIP := range rl.config.WhitelistedIPs {
		if ip == whitelistedIP {
			return true
		}
		// Note: CIDR range support not yet implemented. See issue #2
	}

	return false
}

// extractIP extracts the IP address from a net.Addr.
func extractIP(addr net.Addr) string {
	if addr == nil {
		return "" // No address, allow through
	}

	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.TCPAddr:
		return v.IP.String()
	default:
		// Try to parse as string
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}

		return host
	}
}

// GetStats returns rate limiting statistics.
type RateLimitStats struct {
	ActiveBuckets int
	TotalIPs      int
}

// GetStats returns current rate limiting statistics.
func (rl *RateLimiter) GetStats() RateLimitStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return RateLimitStats{
		ActiveBuckets: len(rl.buckets),
		TotalIPs:      len(rl.buckets),
	}
}
