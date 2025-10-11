package cache

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// MessageCacheEntry represents a cached DNS message
type MessageCacheEntry struct {
	// ResponseBytes is the complete DNS response ready to send
	// This enables zero-copy serving
	ResponseBytes []byte

	// Expiry is when this cache entry expires
	Expiry time.Time

	// HitCount tracks how many times this entry has been accessed
	// Used for prefetch decision making
	HitCount atomic.Int64

	// LastHit is the timestamp of the last cache hit
	// Used for prefetch decision making
	LastHit atomic.Int64
}

// IsExpired checks if the cache entry has expired
func (e *MessageCacheEntry) IsExpired() bool {
	return time.Now().After(e.Expiry)
}

// IncrementHitCount atomically increments the hit counter
func (e *MessageCacheEntry) IncrementHitCount() {
	e.HitCount.Add(1)
	e.LastHit.Store(time.Now().Unix())
}

// ShouldPrefetch determines if this entry should be prefetched
// based on popularity and time until expiry
func (e *MessageCacheEntry) ShouldPrefetch(hitThreshold int64, ttlPercentThreshold float64) bool {
	if e.HitCount.Load() < hitThreshold {
		return false
	}

	// Calculate how much time is left as percentage of original TTL
	now := time.Now()
	if now.After(e.Expiry) {
		return false // Already expired
	}

	timeUntilExpiry := e.Expiry.Sub(now)
	// Estimate original TTL (this is approximate)
	lastHit := time.Unix(e.LastHit.Load(), 0)
	timeSinceHit := now.Sub(lastHit)
	estimatedOriginalTTL := timeUntilExpiry + timeSinceHit

	ttlRemaining := float64(timeUntilExpiry) / float64(estimatedOriginalTTL)

	return ttlRemaining < ttlPercentThreshold
}

// MessageCacheShard is a single shard of the message cache
type MessageCacheShard struct {
	data sync.Map // Lock-free map for reads
	size atomic.Int64
}

// MessageCache is a sharded cache for complete DNS responses
// Sharding eliminates lock contention across cores
type MessageCache struct {
	shards []*MessageCacheShard
	config MessageCacheConfig

	// Stats
	hits   atomic.Int64
	misses atomic.Int64
	evicts atomic.Int64
}

// MessageCacheConfig holds configuration for the message cache
type MessageCacheConfig struct {
	// NumShards is the number of shards (should be power of 2, typically NumCPU * 4)
	NumShards int

	// MaxSizeBytes is the maximum total cache size in bytes
	MaxSizeBytes int64

	// DefaultTTL is the default TTL for cache entries (if not specified in DNS response)
	DefaultTTL time.Duration

	// MinTTL is the minimum TTL for any cache entry
	MinTTL time.Duration

	// MaxTTL is the maximum TTL for any cache entry
	MaxTTL time.Duration
}

// DefaultMessageCacheConfig returns a configuration with sensible defaults
func DefaultMessageCacheConfig() MessageCacheConfig {
	return MessageCacheConfig{
		NumShards:    64,                    // Good for up to 16 cores
		MaxSizeBytes: 128 * 1024 * 1024,     // 128 MB
		DefaultTTL:   5 * time.Minute,
		MinTTL:       60 * time.Second,
		MaxTTL:       24 * time.Hour,
	}
}

// NewMessageCache creates a new sharded message cache
func NewMessageCache(config MessageCacheConfig) *MessageCache {
	shards := make([]*MessageCacheShard, config.NumShards)
	for i := 0; i < config.NumShards; i++ {
		shards[i] = &MessageCacheShard{}
	}

	return &MessageCache{
		shards: shards,
		config: config,
	}
}

// hashKey generates a hash for the cache key
// Uses FNV-1a hash which is fast and has good distribution
func (mc *MessageCache) hashKey(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

// getShard returns the shard for a given key
func (mc *MessageCache) getShard(key string) *MessageCacheShard {
	hash := mc.hashKey(key)
	// Use bitwise AND for modulo (works because NumShards is power of 2)
	shardIdx := hash & uint64(len(mc.shards)-1)
	return mc.shards[shardIdx]
}

// Get retrieves a cached response
// This is the HOT PATH and must be allocation-free
func (mc *MessageCache) Get(key string) []byte {
	shard := mc.getShard(key)

	value, ok := shard.data.Load(key)
	if !ok {
		mc.misses.Add(1)
		return nil
	}

	entry := value.(*MessageCacheEntry)

	// Check expiry
	if entry.IsExpired() {
		// Lazy eviction
		shard.data.Delete(key)
		shard.size.Add(-int64(len(entry.ResponseBytes)))
		mc.evicts.Add(1)
		mc.misses.Add(1)
		return nil
	}

	// Update hit stats
	entry.IncrementHitCount()
	mc.hits.Add(1)

	return entry.ResponseBytes
}

// GetEntryForPrefetch retrieves a cache entry for prefetch checking
// Returns nil if not found
func (mc *MessageCache) GetEntryForPrefetch(key string) *MessageCacheEntry {
	shard := mc.getShard(key)

	value, ok := shard.data.Load(key)
	if !ok {
		return nil
	}

	return value.(*MessageCacheEntry)
}

// Set stores a response in the cache
func (mc *MessageCache) Set(key string, response []byte, ttl time.Duration) {
	// Enforce TTL bounds
	if ttl < mc.config.MinTTL {
		ttl = mc.config.MinTTL
	}
	if ttl > mc.config.MaxTTL {
		ttl = mc.config.MaxTTL
	}

	entry := &MessageCacheEntry{
		ResponseBytes: response,
		Expiry:        time.Now().Add(ttl),
	}
	entry.LastHit.Store(time.Now().Unix())

	shard := mc.getShard(key)

	// Check if we need to evict old entry
	if oldValue, loaded := shard.data.LoadOrStore(key, entry); loaded {
		oldEntry := oldValue.(*MessageCacheEntry)
		shard.size.Add(int64(len(response) - len(oldEntry.ResponseBytes)))
	} else {
		shard.size.Add(int64(len(response)))
	}

	// TODO: Implement size-based eviction if total size exceeds MaxSizeBytes
	// This requires tracking total size across shards and LRU/LFU eviction
}

// Delete removes an entry from the cache
func (mc *MessageCache) Delete(key string) {
	shard := mc.getShard(key)

	if value, ok := shard.data.LoadAndDelete(key); ok {
		entry := value.(*MessageCacheEntry)
		shard.size.Add(-int64(len(entry.ResponseBytes)))
		mc.evicts.Add(1)
	}
}

// Stats returns cache statistics
type MessageCacheStats struct {
	Hits    int64
	Misses  int64
	Evicts  int64
	HitRate float64
	Size    int64 // Approximate total size in bytes
}

// GetStats returns cache statistics
func (mc *MessageCache) GetStats() MessageCacheStats {
	hits := mc.hits.Load()
	misses := mc.misses.Load()
	total := hits + misses

	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	// Calculate total size across all shards
	var totalSize int64
	for _, shard := range mc.shards {
		totalSize += shard.size.Load()
	}

	return MessageCacheStats{
		Hits:    hits,
		Misses:  misses,
		Evicts:  mc.evicts.Load(),
		HitRate: hitRate,
		Size:    totalSize,
	}
}

// Clear removes all entries from the cache
func (mc *MessageCache) Clear() {
	for _, shard := range mc.shards {
		shard.data.Range(func(key, value interface{}) bool {
			shard.data.Delete(key)
			return true
		})
		shard.size.Store(0)
	}

	mc.hits.Store(0)
	mc.misses.Store(0)
	mc.evicts.Store(0)
}

// MakeKey generates a cache key from DNS query components
// Format: "name:type:class"
func MakeKey(name string, qtype uint16, qclass uint16) string {
	// Pre-allocate buffer to avoid allocations
	// Most domain names are < 100 chars
	buf := make([]byte, 0, 128)
	buf = append(buf, name...)
	buf = append(buf, ':')
	buf = appendUint16(buf, qtype)
	buf = append(buf, ':')
	buf = appendUint16(buf, qclass)
	return string(buf)
}

// appendUint16 appends a uint16 as string to buffer
func appendUint16(buf []byte, n uint16) []byte {
	// Fast path for common values
	if n < 10 {
		return append(buf, byte('0'+n))
	}

	// General case
	var tmp [5]byte
	i := len(tmp)
	for n >= 10 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	i--
	tmp[i] = byte('0' + n)
	return append(buf, tmp[i:]...)
}
