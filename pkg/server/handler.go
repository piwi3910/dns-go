package server

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/pascalwatteel/dns-go/pkg/cache"
	dnsio "github.com/pascalwatteel/dns-go/pkg/io"
	"github.com/pascalwatteel/dns-go/pkg/resolver"
)

// Handler implements the DNS query handler with fast-path optimization
type Handler struct {
	// Caches
	messageCache *cache.MessageCache
	rrsetCache   *cache.RRsetCache
	infraCache   *cache.InfraCache

	// Pools for zero-allocation
	msgPool    *dnsio.MessagePool
	bufferPool *dnsio.BufferPool

	// Resolver for upstream queries
	resolver *resolver.Resolver

	// Config
	config HandlerConfig
}

// HandlerConfig holds configuration for the handler
type HandlerConfig struct {
	// EnableCache enables caching (default: true)
	EnableCache bool

	// EnableFastPath enables fast-path optimization (default: true)
	EnableFastPath bool

	// DefaultTTL is the default TTL for responses without TTL info
	DefaultTTL time.Duration

	// ResolverMode determines resolution strategy (Forwarding or Recursive)
	ResolverMode resolver.RecursionMode
}

// DefaultHandlerConfig returns configuration with sensible defaults
// Uses forwarding mode for best performance
func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		EnableCache:    true,
		EnableFastPath: true,
		DefaultTTL:     5 * time.Minute,
		ResolverMode:   resolver.ForwardingMode, // Default to forwarding for performance
	}
}

// NewHandler creates a new DNS query handler
func NewHandler(config HandlerConfig) *Handler {
	infraCache := cache.NewInfraCache()

	// Create upstream pool
	upstreamPool := resolver.NewUpstreamPool(resolver.DefaultUpstreamConfig(), infraCache)

	// Create resolver with configured mode
	resolverConfig := resolver.DefaultResolverConfig()
	resolverConfig.Mode = config.ResolverMode
	// Disable coalescing in forwarding mode for better concurrency
	if config.ResolverMode == resolver.ForwardingMode {
		resolverConfig.EnableCoalescing = false
	}
	resolverInstance := resolver.NewResolver(resolverConfig, upstreamPool)

	return &Handler{
		messageCache: cache.NewMessageCache(cache.DefaultMessageCacheConfig()),
		rrsetCache:   cache.NewRRsetCache(cache.DefaultRRsetCacheConfig()),
		infraCache:   infraCache,
		msgPool:      dnsio.NewMessagePool(),
		bufferPool:   dnsio.NewBufferPool(dnsio.DefaultBufferSize),
		resolver:     resolverInstance,
		config:       config,
	}
}

// HandleQuery processes a DNS query and returns a response
// This is the main entry point for all queries
func (h *Handler) HandleQuery(ctx context.Context, query []byte, addr net.Addr) ([]byte, error) {
	// Fast path: Check if this query can use the fast path
	if h.config.EnableFastPath && dnsio.CanUseFastPath(query) {
		return h.handleFastPath(ctx, query, addr)
	}

	// Slow path: Full processing
	return h.handleSlowPath(ctx, query, addr)
}

// handleFastPath processes queries that can use the optimized fast path
// This is the HOT PATH - must be extremely fast and allocation-free
func (h *Handler) handleFastPath(ctx context.Context, query []byte, addr net.Addr) ([]byte, error) {
	// Parse query to get cache key
	fpq, err := dnsio.ParseFastPathQuery(query)
	if err != nil {
		// Fall back to slow path if parsing fails
		return h.handleSlowPath(ctx, query, addr)
	}

	// Check message cache (L1)
	cacheKey := cache.MakeKey(fpq.Name, fpq.Type, fpq.Class)
	if response := h.messageCache.Get(cacheKey); response != nil {
		// Cache hit! Build response with correct message ID
		// Optimize: avoid full copy, only replace ID bytes
		result := make([]byte, len(response))

		// Copy query ID (bytes 0-1) directly from query
		result[0] = query[0]
		result[1] = query[1]

		// Copy rest of cached response (bytes 2+) - everything except ID
		copy(result[2:], response[2:])

		return result, nil
	}

	// Check RRset cache (L2)
	if rrs := h.rrsetCache.Get(fpq.Name, fpq.Type); rrs != nil {
		// Build response from cached RRsets
		msg := h.msgPool.Get()
		defer h.msgPool.Put(msg)

		// Parse query message
		if err := msg.Unpack(query); err != nil {
			return h.buildErrorResponse(query, dns.RcodeServerFailure)
		}

		// Build response
		response := cache.BuildResponse(msg, rrs)
		responseBytes, err := response.Pack()
		if err != nil {
			return h.buildErrorResponse(query, dns.RcodeServerFailure)
		}

		// Cache the complete response for future queries
		ttl := cache.GetMinTTL(rrs)
		if ttl == 0 {
			ttl = h.config.DefaultTTL
		}
		h.messageCache.Set(cacheKey, responseBytes, ttl)

		return responseBytes, nil
	}

	// Cache miss - need to resolve
	// For now, return SERVFAIL (resolver will be added later)
	return h.handleCacheMiss(ctx, query, fpq)
}

// handleSlowPath processes queries that require full processing
// This handles DNSSEC, zone transfers, unusual query types, etc.
func (h *Handler) handleSlowPath(ctx context.Context, query []byte, addr net.Addr) ([]byte, error) {
	msg := h.msgPool.Get()
	defer h.msgPool.Put(msg)

	// Unpack query
	if err := msg.Unpack(query); err != nil {
		return h.buildErrorResponse(query, dns.RcodeFormatError)
	}

	// Validate query
	if len(msg.Question) == 0 {
		return h.buildErrorResponse(query, dns.RcodeFormatError)
	}

	q := msg.Question[0]

	// Check caches even in slow path
	if h.config.EnableCache {
		// Try message cache
		cacheKey := cache.MakeKey(q.Name, q.Qtype, q.Qclass)
		if response := h.messageCache.Get(cacheKey); response != nil {
			// Build response with correct message ID (optimized)
			result := make([]byte, len(response))

			// Copy query ID (bytes 0-1)
			result[0] = query[0]
			result[1] = query[1]

			// Copy rest of cached response (bytes 2+)
			copy(result[2:], response[2:])

			return result, nil
		}

		// Try RRset cache
		if rrs := h.rrsetCache.Get(q.Name, q.Qtype); rrs != nil {
			response := cache.BuildResponse(msg, rrs)
			responseBytes, err := response.Pack()
			if err != nil {
				return h.buildErrorResponse(query, dns.RcodeServerFailure)
			}

			// Cache complete response
			ttl := cache.GetMinTTL(rrs)
			if ttl == 0 {
				ttl = h.config.DefaultTTL
			}
			h.messageCache.Set(cacheKey, responseBytes, ttl)

			return responseBytes, nil
		}
	}

	// Need to resolve
	// For now, return SERVFAIL (resolver will be added later)
	return h.handleCacheMiss(ctx, query, &dnsio.FastPathQuery{
		Name:  q.Name,
		Type:  q.Qtype,
		Class: q.Qclass,
	})
}

// handleCacheMiss handles queries that are not in cache
func (h *Handler) handleCacheMiss(ctx context.Context, query []byte, fpq *dnsio.FastPathQuery) ([]byte, error) {
	// Parse query
	msg := h.msgPool.Get()
	defer h.msgPool.Put(msg)

	if err := msg.Unpack(query); err != nil {
		return h.buildErrorResponse(query, dns.RcodeFormatError)
	}

	// Resolve via upstream
	response, err := h.resolver.Resolve(ctx, msg)
	if err != nil {
		// Resolution failed - return SERVFAIL
		return h.buildErrorResponse(query, dns.RcodeServerFailure)
	}

	// Cache the response
	if len(response.Answer) > 0 {
		ttl := cache.GetMinTTL(response.Answer)
		if ttl == 0 {
			ttl = h.config.DefaultTTL
		}
		h.CacheResponse(response, ttl)
	}

	// Pack and return response
	responseBytes, err := response.Pack()
	if err != nil {
		return h.buildErrorResponse(query, dns.RcodeServerFailure)
	}

	return responseBytes, nil
}

// buildErrorResponse builds an error response for a query
func (h *Handler) buildErrorResponse(query []byte, rcode int) ([]byte, error) {
	msg := h.msgPool.Get()
	defer h.msgPool.Put(msg)

	// Try to parse query to get question
	if err := msg.Unpack(query); err != nil {
		// If we can't parse, build minimal error response
		response := new(dns.Msg)
		response.SetRcode(&dns.Msg{}, rcode)
		return response.Pack()
	}

	// Build error response maintaining question
	response := new(dns.Msg)
	response.SetRcode(msg, rcode)
	return response.Pack()
}

// CacheResponse stores a response in both caches
// This is called after successful resolution
func (h *Handler) CacheResponse(msg *dns.Msg, ttl time.Duration) error {
	if !h.config.EnableCache {
		return nil
	}

	if len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Store in message cache (L1)
	responseBytes, err := msg.Pack()
	if err != nil {
		return err
	}

	cacheKey := cache.MakeKey(q.Name, q.Qtype, q.Qclass)
	h.messageCache.Set(cacheKey, responseBytes, ttl)

	// Extract and store RRsets in RRset cache (L2)
	rrsets := cache.ExtractRRsets(msg)
	for rrsetKey, rrs := range rrsets {
		// Get TTL from RRs
		rrTTL := cache.GetMinTTL(rrs)
		if rrTTL == 0 {
			rrTTL = ttl
		}

		// Parse key to get name and type
		// Key format: "name:type"
		// We need to extract these for the Set call
		// For now, just use the question's info for primary RRset
		if len(rrs) > 0 {
			hdr := rrs[0].Header()
			h.rrsetCache.Set(hdr.Name, hdr.Rrtype, rrs, rrTTL)
		}
		_ = rrsetKey // Silence unused warning
	}

	return nil
}

// GetStats returns combined statistics from all caches
type Stats struct {
	MessageCache cache.MessageCacheStats
	RRsetCache   cache.RRsetCacheStats
}

// GetStats returns statistics from the handler
func (h *Handler) GetStats() Stats {
	return Stats{
		MessageCache: h.messageCache.GetStats(),
		RRsetCache:   h.rrsetCache.GetStats(),
	}
}

// ClearCaches clears all caches
func (h *Handler) ClearCaches() {
	h.messageCache.Clear()
	h.rrsetCache.Clear()
	h.infraCache.Clear()
}
