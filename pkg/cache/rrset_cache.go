package cache

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// RRset cache configuration constants.
const (
	defaultRRsetCacheShards    = 128 // More shards due to higher contention
	defaultRRsetCacheSizeMB    = 256 // 256 MB (2x message cache per Unbound recommendation)
	defaultRRsetCacheMinTTLSec = 60  // 60 seconds
	defaultRRsetCacheMaxTTLHr  = 24  // 24 hours
	rrsetKeyBufferSize         = 128 // Buffer size for RRset cache key generation
	estimatedBytesPerRR        = 100 // Estimated bytes per resource record
)

// RRsetCacheEntry represents a cached resource record set
// Unlike MessageCache which stores complete responses, RRset cache stores
// individual resource records that can be assembled into responses.
type RRsetCacheEntry struct {
	// RRs are the resource records for this RRset
	RRs []dns.RR

	// Expiry is when this RRset expires
	Expiry time.Time

	// InsertedAt is when this entry was added to the cache
	InsertedAt time.Time

	// ExpiresAt is an alias for Expiry (for consistency with prefetch code)
	ExpiresAt time.Time

	// HitCount tracks accesses for prefetch decisions
	HitCount atomic.Int64

	// LastHit timestamp
	LastHit atomic.Int64
}

// IsExpired checks if the RRset has expired.
func (e *RRsetCacheEntry) IsExpired() bool {
	return time.Now().After(e.Expiry)
}

// IncrementHitCount atomically increments the hit counter.
func (e *RRsetCacheEntry) IncrementHitCount() {
	e.HitCount.Add(1)
	e.LastHit.Store(time.Now().Unix())
}

// RRsetCacheShard is a single shard of the RRset cache.
type RRsetCacheShard struct {
	data sync.Map // Lock-free map for reads
	size atomic.Int64
}

// RRsetCache is a sharded cache for DNS resource record sets
// This provides more flexibility than MessageCache:
// - Can answer queries with different flags from same data
// - Can construct responses for DNSSEC vs non-DNSSEC queries
// - Better cache utilization (same records used for multiple queries).
type RRsetCache struct {
	shards []*RRsetCacheShard
	config RRsetCacheConfig

	// Stats
	hits   atomic.Int64
	misses atomic.Int64
	evicts atomic.Int64
}

// RRsetCacheConfig holds configuration for the RRset cache.
type RRsetCacheConfig struct {
	// NumShards should be power of 2, typically NumCPU * 8
	// (more than message cache due to higher contention)
	NumShards int

	// MaxSizeBytes is the maximum total cache size
	MaxSizeBytes int64

	// MinTTL is the minimum TTL for any cache entry
	MinTTL time.Duration

	// MaxTTL is the maximum TTL for any cache entry
	MaxTTL time.Duration
}

// DefaultRRsetCacheConfig returns configuration with sensible defaults
// Note: RRset cache is typically 2x size of message cache (Unbound recommendation).
func DefaultRRsetCacheConfig() RRsetCacheConfig {
	return RRsetCacheConfig{
		NumShards:    defaultRRsetCacheShards,
		MaxSizeBytes: defaultRRsetCacheSizeMB * bytesPerMegabyte,
		MinTTL:       defaultRRsetCacheMinTTLSec * time.Second,
		MaxTTL:       defaultRRsetCacheMaxTTLHr * time.Hour,
	}
}

// NewRRsetCache creates a new sharded RRset cache.
func NewRRsetCache(config RRsetCacheConfig) *RRsetCache {
	shards := make([]*RRsetCacheShard, config.NumShards)
	for i := range config.NumShards {
		shards[i] = &RRsetCacheShard{
			data: sync.Map{},
			size: atomic.Int64{},
		}
	}

	return &RRsetCache{
		shards: shards,
		config: config,
		hits:   atomic.Int64{},
		misses: atomic.Int64{},
		evicts: atomic.Int64{},
	}
}

// Get retrieves a cached RRset
// Returns nil if not found or expired.
func (rc *RRsetCache) Get(name string, qtype uint16) []dns.RR {
	key := MakeRRsetKey(name, qtype)
	shard := rc.getShard(key)

	value, ok := shard.data.Load(key)
	if !ok {
		rc.misses.Add(1)

		return nil
	}

	entry, ok := value.(*RRsetCacheEntry)
	if !ok {
		// Type assertion failed - invalid cache entry, remove it
		shard.data.Delete(key)
		rc.misses.Add(1)

		return nil
	}

	// Check expiry
	if entry.IsExpired() {
		// Lazy eviction
		shard.data.Delete(key)
		shard.size.Add(-int64(estimateRRsetSize(entry.RRs)))
		rc.evicts.Add(1)
		rc.misses.Add(1)

		return nil
	}

	// Update hit stats
	entry.IncrementHitCount()
	rc.hits.Add(1)

	return entry.RRs
}

// GetEntryForPrefetch retrieves a cache entry for prefetch checking
// Returns nil if not found.
func (rc *RRsetCache) GetEntryForPrefetch(key string) *RRsetCacheEntry {
	shard := rc.getShard(key)

	value, ok := shard.data.Load(key)
	if !ok {
		return nil
	}

	entry, ok := value.(*RRsetCacheEntry)
	if !ok {
		// Type assertion failed - invalid cache entry
		return nil
	}

	return entry
}

// Set stores an RRset in the cache.
func (rc *RRsetCache) Set(name string, qtype uint16, rrs []dns.RR, ttl time.Duration) {
	if len(rrs) == 0 {
		return
	}

	// Enforce TTL bounds
	if ttl < rc.config.MinTTL {
		ttl = rc.config.MinTTL
	}
	if ttl > rc.config.MaxTTL {
		ttl = rc.config.MaxTTL
	}

	now := time.Now()
	entry := &RRsetCacheEntry{
		RRs:        rrs,
		Expiry:     now.Add(ttl),
		InsertedAt: now,
		ExpiresAt:  now.Add(ttl),
		HitCount:   atomic.Int64{},
		LastHit:    atomic.Int64{},
	}
	entry.LastHit.Store(now.Unix())

	key := MakeRRsetKey(name, qtype)
	shard := rc.getShard(key)

	// Calculate size
	newSize := int64(estimateRRsetSize(rrs))

	// Check if we need to account for old entry
	if oldValue, loaded := shard.data.LoadOrStore(key, entry); loaded {
		if oldEntry, ok := oldValue.(*RRsetCacheEntry); ok {
			oldSize := int64(estimateRRsetSize(oldEntry.RRs))
			shard.size.Add(newSize - oldSize)
		} else {
			// Type assertion failed - just add new size
			shard.size.Add(newSize)
		}
	} else {
		shard.size.Add(newSize)
	}
}

// Delete removes an RRset from the cache.
func (rc *RRsetCache) Delete(name string, qtype uint16) {
	key := MakeRRsetKey(name, qtype)
	shard := rc.getShard(key)

	if value, ok := shard.data.LoadAndDelete(key); ok {
		if entry, ok := value.(*RRsetCacheEntry); ok {
			shard.size.Add(-int64(estimateRRsetSize(entry.RRs)))
		}
		rc.evicts.Add(1)
	}
}

// RRsetCacheStats holds RRset cache statistics.
type RRsetCacheStats struct {
	Hits    int64
	Misses  int64
	Evicts  int64
	HitRate float64
	Size    int64
}

// GetStats returns cache statistics.
func (rc *RRsetCache) GetStats() RRsetCacheStats {
	hits := rc.hits.Load()
	misses := rc.misses.Load()
	total := hits + misses

	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	var totalSize int64
	for _, shard := range rc.shards {
		totalSize += shard.size.Load()
	}

	return RRsetCacheStats{
		Hits:    hits,
		Misses:  misses,
		Evicts:  rc.evicts.Load(),
		HitRate: hitRate,
		Size:    totalSize,
	}
}

// Clear removes all entries from the cache.
func (rc *RRsetCache) Clear() {
	for _, shard := range rc.shards {
		shard.data.Range(func(key, _ interface{}) bool {
			shard.data.Delete(key)

			return true
		})
		shard.size.Store(0)
	}

	rc.hits.Store(0)
	rc.misses.Store(0)
	rc.evicts.Store(0)
}

// hashKey generates a hash for the cache key.
func (rc *RRsetCache) hashKey(key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key)) // hash.Hash.Write never returns an error

	return h.Sum64()
}

// getShard returns the shard for a given key.
func (rc *RRsetCache) getShard(key string) *RRsetCacheShard {
	hash := rc.hashKey(key)
	//nolint:gosec // G115: len(shards) is bounded by config (max 256), safe for uint64 conversion
	shardIdx := hash & uint64(len(rc.shards)-1)

	return rc.shards[shardIdx]
}

// MakeRRsetKey generates a cache key for an RRset
// Format: "name:type".
func MakeRRsetKey(name string, qtype uint16) string {
	// Pre-allocate buffer
	buf := make([]byte, 0, rrsetKeyBufferSize)
	buf = append(buf, name...)
	buf = append(buf, ':')
	buf = appendUint16(buf, qtype)

	return string(buf)
}

// estimateRRsetSize estimates the memory size of an RRset in bytes
// This is approximate but good enough for cache size management.
func estimateRRsetSize(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return 0
	}

	// Rough estimate: header + average data size per RR
	// This is conservative but avoids the cost of serializing every RR
	return len(rrs) * estimatedBytesPerRR
}

// BuildResponse constructs a DNS response from cached RRsets
// This is used when we have RRset cache hits but not message cache hits.
func BuildResponse(query *dns.Msg, answers []dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Answer = answers
	response.RecursionAvailable = true
	response.Authoritative = false

	return response
}

// ExtractRRsets extracts RRsets from a DNS message for caching
// Groups records by name and type.
func ExtractRRsets(msg *dns.Msg) map[string][]dns.RR {
	rrsets := make(map[string][]dns.RR)

	// Extract from answer section
	for _, rr := range msg.Answer {
		hdr := rr.Header()
		key := MakeRRsetKey(hdr.Name, hdr.Rrtype)
		rrsets[key] = append(rrsets[key], rr)
	}

	// Extract from authority section (for NS records, SOA, etc.)
	for _, rr := range msg.Ns {
		hdr := rr.Header()
		key := MakeRRsetKey(hdr.Name, hdr.Rrtype)
		rrsets[key] = append(rrsets[key], rr)
	}

	// Note: We don't cache additional section as it's typically glue records
	// that are specific to the query context

	return rrsets
}

// GetMinTTL returns the minimum TTL from a set of resource records.
func GetMinTTL(rrs []dns.RR) time.Duration {
	if len(rrs) == 0 {
		return 0
	}

	minTTL := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}

	return time.Duration(minTTL) * time.Second
}
