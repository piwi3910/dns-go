package cache

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// PrefetchEngine automatically refreshes popular cache entries before they expire
// This keeps the cache warm and ensures low latency for frequently accessed domains.
type PrefetchEngine struct {
	messageCache *MessageCache
	rrsetCache   *RRsetCache
	resolver     PrefetchResolver

	// Configuration
	enabled        bool
	prefetchThresh float64 // Prefetch when TTL < this fraction (e.g., 0.1 = 10% remaining)
	minHits        int     // Minimum hits before prefetching
	maxConcurrent  int     // Maximum concurrent prefetch operations

	// State
	mu            sync.RWMutex
	candidates    map[string]*prefetchCandidate // Cache key → candidate
	prefetchQueue chan *prefetchCandidate
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// PrefetchResolver is the interface for resolving queries during prefetch.
type PrefetchResolver interface {
	Resolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
}

// prefetchCandidate represents an entry that may need prefetching.
type prefetchCandidate struct {
	key         string
	name        string
	qtype       uint16
	qclass      uint16
	hits        int
	lastCheck   time.Time
	prefetching bool
}

// PrefetchConfig holds configuration for the prefetch engine.
type PrefetchConfig struct {
	Enabled        bool
	PrefetchThresh float64       // When to prefetch (0.1 = at 10% TTL remaining)
	MinHits        int           // Minimum hits before considering prefetch
	MaxConcurrent  int           // Max concurrent prefetch operations
	CheckInterval  time.Duration // How often to check for candidates
}

// DefaultPrefetchConfig returns sensible defaults.
func DefaultPrefetchConfig() PrefetchConfig {
	return PrefetchConfig{
		Enabled:        true,
		PrefetchThresh: 0.10, // Prefetch at 10% TTL remaining
		MinHits:        3,    // Need at least 3 hits to be considered "popular"
		MaxConcurrent:  10,   // Up to 10 concurrent prefetches
		CheckInterval:  5 * time.Second,
	}
}

// NewPrefetchEngine creates a new prefetch engine.
func NewPrefetchEngine(config PrefetchConfig, messageCache *MessageCache, rrsetCache *RRsetCache, resolver PrefetchResolver) *PrefetchEngine {
	return &PrefetchEngine{
		messageCache:   messageCache,
		rrsetCache:     rrsetCache,
		resolver:       resolver,
		enabled:        config.Enabled,
		prefetchThresh: config.PrefetchThresh,
		minHits:        config.MinHits,
		maxConcurrent:  config.MaxConcurrent,
		mu:             sync.RWMutex{},
		candidates:     make(map[string]*prefetchCandidate),
		prefetchQueue:  make(chan *prefetchCandidate, 1000),
		stopCh:         make(chan struct{}),
		wg:             sync.WaitGroup{},
	}
}

// Start starts the prefetch engine.
func (pe *PrefetchEngine) Start(checkInterval time.Duration) {
	if !pe.enabled {
		return
	}

	// Start prefetch workers
	for range pe.maxConcurrent {
		pe.wg.Add(1)
		go pe.prefetchWorker()
	}

	// Start scanner that checks for candidates
	pe.wg.Add(1)
	go pe.scanner(checkInterval)
}

// Stop stops the prefetch engine.
func (pe *PrefetchEngine) Stop() {
	if !pe.enabled {
		return
	}

	close(pe.stopCh)
	pe.wg.Wait()
}

// RecordAccess records a cache access for prefetch consideration.
func (pe *PrefetchEngine) RecordAccess(key string, name string, qtype uint16, qclass uint16) {
	if !pe.enabled {
		return
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()

	if candidate, exists := pe.candidates[key]; exists {
		candidate.hits++
		candidate.lastCheck = time.Now()
	} else {
		pe.candidates[key] = &prefetchCandidate{
			key:         key,
			name:        name,
			qtype:       qtype,
			qclass:      qclass,
			hits:        1,
			lastCheck:   time.Now(),
			prefetching: false,
		}
	}
}

// scanner periodically scans cache entries to find prefetch candidates.
func (pe *PrefetchEngine) scanner(interval time.Duration) {
	defer pe.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pe.scanForCandidates()
		case <-pe.stopCh:
			return
		}
	}
}

// scanForCandidates scans the cache for entries that need prefetching.
func (pe *PrefetchEngine) scanForCandidates() {
	pe.mu.RLock()
	candidates := make([]*prefetchCandidate, 0, len(pe.candidates))
	for _, candidate := range pe.candidates {
		if candidate.hits >= pe.minHits && !candidate.prefetching {
			candidates = append(candidates, candidate)
		}
	}
	pe.mu.RUnlock()

	// Check each candidate
	for _, candidate := range candidates {
		if pe.shouldPrefetch(candidate) {
			// Mark as prefetching
			pe.mu.Lock()
			if c, exists := pe.candidates[candidate.key]; exists {
				c.prefetching = true
			}
			pe.mu.Unlock()

			// Queue for prefetch
			select {
			case pe.prefetchQueue <- candidate:
			case <-pe.stopCh:
				return
			default:
				// Queue full, skip this one
				pe.mu.Lock()
				if c, exists := pe.candidates[candidate.key]; exists {
					c.prefetching = false
				}
				pe.mu.Unlock()
			}
		}
	}
}

// shouldPrefetch determines if an entry should be prefetched.
func (pe *PrefetchEngine) shouldPrefetch(candidate *prefetchCandidate) bool {
	// Check message cache using the built-in ShouldPrefetch method
	entry := pe.messageCache.GetEntryForPrefetch(candidate.key)
	if entry != nil {
		return entry.ShouldPrefetch(int64(pe.minHits), pe.prefetchThresh)
	}

	// Check RRset cache
	rrsetKey := MakeRRsetKey(candidate.name, candidate.qtype)
	rrsetEntry := pe.rrsetCache.GetEntryForPrefetch(rrsetKey)
	if rrsetEntry != nil {
		// Check if close to expiry
		ttlRemaining := time.Until(rrsetEntry.ExpiresAt)
		if ttlRemaining <= 0 {
			return true // Already expired
		}

		totalTTL := rrsetEntry.ExpiresAt.Sub(rrsetEntry.InsertedAt)
		if totalTTL == 0 {
			return false
		}

		remainingFraction := float64(ttlRemaining) / float64(totalTTL)

		return remainingFraction < pe.prefetchThresh
	}

	return false
}

// prefetchWorker handles prefetch operations.
func (pe *PrefetchEngine) prefetchWorker() {
	defer pe.wg.Done()

	for {
		select {
		case candidate := <-pe.prefetchQueue:
			pe.prefetch(candidate)
		case <-pe.stopCh:
			return
		}
	}
}

// prefetch performs the actual prefetch operation.
func (pe *PrefetchEngine) prefetch(candidate *prefetchCandidate) {
	// Create query
	query := new(dns.Msg)
	query.SetQuestion(candidate.name, candidate.qtype)
	query.RecursionDesired = true

	// Resolve with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := pe.resolver.Resolve(ctx, query)

	// Mark as no longer prefetching
	pe.mu.Lock()
	if c, exists := pe.candidates[candidate.key]; exists {
		c.prefetching = false
		if err == nil {
			// Reset hits counter to track new popularity
			c.hits = pe.minHits
		}
	}
	pe.mu.Unlock()
}

// GetStats returns prefetch statistics.
type PrefetchStats struct {
	Enabled     bool
	Candidates  int
	QueueSize   int
	Prefetching int
}

// GetStats returns current prefetch statistics.
func (pe *PrefetchEngine) GetStats() PrefetchStats {
	if !pe.enabled {
		return PrefetchStats{
			Enabled:     false,
			Candidates:  0,
			QueueSize:   0,
			Prefetching: 0,
		}
	}

	pe.mu.RLock()
	defer pe.mu.RUnlock()

	prefetching := 0
	for _, candidate := range pe.candidates {
		if candidate.prefetching {
			prefetching++
		}
	}

	return PrefetchStats{
		Enabled:     true,
		Candidates:  len(pe.candidates),
		QueueSize:   len(pe.prefetchQueue),
		Prefetching: prefetching,
	}
}
