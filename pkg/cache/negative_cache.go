package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// NegativeCacheEntry represents a cached negative response
// Per RFC 2308, negative responses (NXDOMAIN and NODATA) should be cached.
type NegativeCacheEntry struct {
	// Type of negative response
	Type NegativeType

	// Expiry is when this cache entry expires
	Expiry time.Time

	// TTL used for this entry (from SOA)
	TTL time.Duration

	// HitCount tracks cache hits for statistics
	HitCount atomic.Int64

	// SOA record from the negative response (optional)
	SOA *dns.SOA
}

// NegativeType represents the type of negative response.
type NegativeType int

const (
	// NegativeNXDOMAIN indicates the domain name does not exist.
	NegativeNXDOMAIN NegativeType = iota

	// NegativeNODATA indicates the domain exists but has no records of the requested type.
	NegativeNODATA
)

// IsExpired checks if the cache entry has expired.
func (e *NegativeCacheEntry) IsExpired() bool {
	return time.Now().After(e.Expiry)
}

// IncrementHitCount atomically increments the hit counter.
func (e *NegativeCacheEntry) IncrementHitCount() {
	e.HitCount.Add(1)
}

// NegativeCacheShard is a single shard of the negative cache.
type NegativeCacheShard struct {
	data sync.Map // Lock-free map for reads
}

// NegativeCache caches negative DNS responses (NXDOMAIN and NODATA).
type NegativeCache struct {
	shards []*NegativeCacheShard
	config NegativeCacheConfig

	// Stats
	hits   atomic.Int64
	misses atomic.Int64
}

// NegativeCacheConfig holds configuration for negative caching.
type NegativeCacheConfig struct {
	// NumShards is the number of shards (should be power of 2)
	NumShards int

	// Enable enables negative caching
	Enable bool

	// MinTTL is the minimum TTL for negative cache entries (RFC 2308 recommends 300s)
	MinTTL time.Duration

	// MaxTTL is the maximum TTL for negative cache entries (RFC 2308 recommends 3 hours)
	MaxTTL time.Duration

	// DefaultTTL is used if SOA is not present
	DefaultTTL time.Duration
}

// DefaultNegativeCacheConfig returns configuration with RFC 2308 recommendations.
func DefaultNegativeCacheConfig() NegativeCacheConfig {
	return NegativeCacheConfig{
		NumShards:  32, // Smaller than message cache
		Enable:     true,
		MinTTL:     5 * time.Minute,  // RFC 2308 Section 5
		MaxTTL:     3 * time.Hour,    // RFC 2308 Section 5
		DefaultTTL: 10 * time.Minute, // Fallback if no SOA
	}
}

// NewNegativeCache creates a new negative cache.
func NewNegativeCache(config NegativeCacheConfig) *NegativeCache {
	shards := make([]*NegativeCacheShard, config.NumShards)
	for i := range config.NumShards {
		shards[i] = &NegativeCacheShard{
			data: sync.Map{},
		}
	}

	return &NegativeCache{
		shards: shards,
		config: config,
		hits:   atomic.Int64{},
		misses: atomic.Int64{},
	}
}

// Get retrieves a negative cache entry.
func (nc *NegativeCache) Get(key string) *NegativeCacheEntry {
	if !nc.config.Enable {
		return nil
	}

	shard := nc.getShard(key)

	value, ok := shard.data.Load(key)
	if !ok {
		nc.misses.Add(1)

		return nil
	}

	entry := value.(*NegativeCacheEntry)

	// Check expiry
	if entry.IsExpired() {
		// Lazy eviction
		shard.data.Delete(key)
		nc.misses.Add(1)

		return nil
	}

	// Update hit stats
	entry.IncrementHitCount()
	nc.hits.Add(1)

	return entry
}

// Set stores a negative response in the cache.
func (nc *NegativeCache) Set(key string, negType NegativeType, soa *dns.SOA) {
	if !nc.config.Enable {
		return
	}

	// Calculate TTL from SOA record per RFC 2308 Section 5
	ttl := nc.calculateNegativeTTL(soa)

	entry := &NegativeCacheEntry{
		Type:     negType,
		Expiry:   time.Now().Add(ttl),
		TTL:      ttl,
		HitCount: atomic.Int64{},
		SOA:      soa,
	}

	shard := nc.getShard(key)
	shard.data.Store(key, entry)
}

// calculateNegativeTTL calculates the TTL for a negative response per RFC 2308
// Uses the minimum of SOA TTL and SOA MINIMUM field.
func (nc *NegativeCache) calculateNegativeTTL(soa *dns.SOA) time.Duration {
	var ttl time.Duration

	if soa != nil {
		// RFC 2308 Section 5: Use minimum of SOA TTL and SOA MINIMUM
		soaTTL := time.Duration(soa.Hdr.Ttl) * time.Second
		soaMinimum := time.Duration(soa.Minttl) * time.Second

		if soaTTL < soaMinimum {
			ttl = soaTTL
		} else {
			ttl = soaMinimum
		}
	} else {
		// No SOA - use default
		ttl = nc.config.DefaultTTL
	}

	// Enforce bounds per RFC 2308 recommendations
	if ttl < nc.config.MinTTL {
		ttl = nc.config.MinTTL
	}
	if ttl > nc.config.MaxTTL {
		ttl = nc.config.MaxTTL
	}

	return ttl
}

// getShard returns the shard for a given key.
func (nc *NegativeCache) getShard(key string) *NegativeCacheShard {
	hash := fnvHash(key)
	shardIdx := hash & uint64(len(nc.shards)-1)

	return nc.shards[shardIdx]
}

// Delete removes an entry from the negative cache.
func (nc *NegativeCache) Delete(key string) {
	shard := nc.getShard(key)
	shard.data.Delete(key)
}

// Stats returns negative cache statistics.
type NegativeCacheStats struct {
	Hits    int64
	Misses  int64
	HitRate float64
}

// GetStats returns cache statistics.
func (nc *NegativeCache) GetStats() NegativeCacheStats {
	hits := nc.hits.Load()
	misses := nc.misses.Load()
	total := hits + misses

	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return NegativeCacheStats{
		Hits:    hits,
		Misses:  misses,
		HitRate: hitRate,
	}
}

// ExtractSOA extracts the SOA record from a DNS message's authority section
// Per RFC 2308, negative responses should have an SOA in the authority section.
func ExtractSOA(msg *dns.Msg) *dns.SOA {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}

	return nil
}

// IsNegativeResponse checks if a DNS response is a negative response
// Returns (isNegative, negType, soa).
func IsNegativeResponse(msg *dns.Msg) (bool, NegativeType, *dns.SOA) {
	// Must be a response
	if !msg.Response {
		return false, 0, nil
	}

	// Extract SOA from authority section
	soa := ExtractSOA(msg)

	// NXDOMAIN - RFC 2308 Section 2.1
	if msg.Rcode == dns.RcodeNameError {
		return true, NegativeNXDOMAIN, soa
	}

	// NODATA - RFC 2308 Section 2.2
	// - RCODE is NOERROR
	// - Answer section is empty
	// - Authority section has SOA
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && soa != nil {
		return true, NegativeNODATA, soa
	}

	return false, 0, nil
}

// CreateNegativeResponse creates a negative response message
// Used for serving from negative cache.
func CreateNegativeResponse(query *dns.Msg, negType NegativeType, soa *dns.SOA) *dns.Msg {
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	response.SetReply(query)
	response.Authoritative = false // Cached response, not authoritative
	response.RecursionAvailable = true

	switch negType {
	case NegativeNXDOMAIN:
		response.Rcode = dns.RcodeNameError

	case NegativeNODATA:
		response.Rcode = dns.RcodeSuccess
		// Answer section is empty
	}

	// Add SOA to authority section if available
	if soa != nil {
		// Clone SOA to avoid modifying the cached version
		soaCopy := dns.Copy(soa).(*dns.SOA)
		response.Ns = append(response.Ns, soaCopy)
	}

	return response
}

// fnvHash is a helper for FNV-1a hashing.
func fnvHash(key string) uint64 {
	hash := uint64(14695981039346656037)
	for i := range len(key) {
		hash ^= uint64(key[i])
		hash *= 1099511628211
	}

	return hash
}
