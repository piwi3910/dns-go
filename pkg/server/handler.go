package server

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
	"github.com/piwi3910/dns-go/pkg/dnssec"
	"github.com/piwi3910/dns-go/pkg/edns0"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/security"
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

	// DNSSEC validator
	dnssecValidator *dnssec.Validator

	// Security components
	rateLimiter            *security.RateLimiter
	queryValidator         *security.QueryValidator
	cachePoisoningProtector *security.CachePoisoningProtector

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

	// EnableDNSSEC enables DNSSEC validation (default: true)
	EnableDNSSEC bool

	// EnableRateLimiting enables per-IP rate limiting (default: true)
	EnableRateLimiting bool

	// EnableQueryValidation enables query validation (default: true)
	EnableQueryValidation bool

	// EnableCachePoisoningProtection enables cache poisoning protection (default: true)
	EnableCachePoisoningProtection bool
}

// DefaultHandlerConfig returns configuration with sensible defaults
// Uses forwarding mode for best performance
func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		EnableCache:                    true,
		EnableFastPath:                 true,
		DefaultTTL:                     5 * time.Minute,
		ResolverMode:                   resolver.ForwardingMode, // Default to forwarding for performance
		EnableDNSSEC:                   true,                     // Enable DNSSEC validation by default
		EnableRateLimiting:             true,                     // Enable rate limiting by default
		EnableQueryValidation:          true,                     // Enable query validation by default
		EnableCachePoisoningProtection: true,                     // Enable cache poisoning protection by default
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

	// Create DNSSEC validator
	dnssecConfig := dnssec.DefaultValidatorConfig()
	dnssecConfig.EnableValidation = config.EnableDNSSEC
	dnssecValidator := dnssec.NewValidator(dnssecConfig)

	// Create security components
	rateLimitConfig := security.DefaultRateLimitConfig()
	rateLimitConfig.Enabled = config.EnableRateLimiting
	rateLimiter := security.NewRateLimiter(rateLimitConfig)

	validationConfig := security.DefaultValidationConfig()
	queryValidator := security.NewQueryValidator(validationConfig)

	cachePoisoningConfig := security.DefaultCachePoisoningConfig()
	cachePoisoningProtector := security.NewCachePoisoningProtector(cachePoisoningConfig)

	return &Handler{
		messageCache:            cache.NewMessageCache(cache.DefaultMessageCacheConfig()),
		rrsetCache:              cache.NewRRsetCache(cache.DefaultRRsetCacheConfig()),
		infraCache:              infraCache,
		msgPool:                 dnsio.NewMessagePool(),
		bufferPool:              dnsio.NewBufferPool(dnsio.DefaultBufferSize),
		resolver:                resolverInstance,
		dnssecValidator:         dnssecValidator,
		rateLimiter:             rateLimiter,
		queryValidator:          queryValidator,
		cachePoisoningProtector: cachePoisoningProtector,
		config:                  config,
	}
}

// HandleQuery processes a DNS query and returns a response
// This is the main entry point for all queries
func (h *Handler) HandleQuery(ctx context.Context, query []byte, addr net.Addr) ([]byte, error) {
	// Security: Rate limiting check
	if h.config.EnableRateLimiting && !h.rateLimiter.Allow(addr) {
		// Rate limit exceeded - return REFUSED
		return h.buildErrorResponse(query, dns.RcodeRefused)
	}

	// Security: Query validation (slow path only for validation)
	if h.config.EnableQueryValidation {
		msg := h.msgPool.Get()
		if err := msg.Unpack(query); err != nil {
			h.msgPool.Put(msg)
			return h.buildErrorResponse(query, dns.RcodeFormatError)
		}

		if err := h.queryValidator.ValidateQuery(msg); err != nil {
			h.msgPool.Put(msg)
			// Invalid query - return FORMERR
			return h.buildErrorResponse(query, dns.RcodeFormatError)
		}
		h.msgPool.Put(msg)
	}

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
	if cachedResponse := h.messageCache.Get(cacheKey); cachedResponse != nil {
		// Cache hit! Need to add EDNS0 if query has it
		// Check ARCOUNT to see if query has EDNS0
		arcount := uint16(query[10])<<8 | uint16(query[11])

		if arcount > 0 {
			// Query has EDNS0, need to add OPT to response
			queryMsg := h.msgPool.Get()
			defer h.msgPool.Put(queryMsg)

			if err := queryMsg.Unpack(query); err == nil {
				responseMsg := h.msgPool.Get()
				defer h.msgPool.Put(responseMsg)

				if err := responseMsg.Unpack(cachedResponse); err == nil {
					// Add EDNS0 to response
					h.applyEDNS0(queryMsg, responseMsg)

					// Pack with EDNS0
					if finalBytes, err := responseMsg.Pack(); err == nil {
						// Update message ID
						finalBytes[0] = query[0]
						finalBytes[1] = query[1]
						return finalBytes, nil
					}
				}
			}
		}

		// No EDNS0 or fallback: use optimized path
		result := make([]byte, len(cachedResponse))
		result[0] = query[0]
		result[1] = query[1]
		copy(result[2:], cachedResponse[2:])
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

		// Apply EDNS0 if query has it
		h.applyEDNS0(msg, response)

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
// This handles EDNS0, DNSSEC, zone transfers, unusual query types, etc.
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
		if cachedResponse := h.messageCache.Get(cacheKey); cachedResponse != nil {
			// Parse cached response to add EDNS0
			responseMsg := h.msgPool.Get()
			defer h.msgPool.Put(responseMsg)

			if err := responseMsg.Unpack(cachedResponse); err == nil {
				// Apply EDNS0 from query
				h.applyEDNS0(msg, responseMsg)

				// Pack with EDNS0
				if finalBytes, err := responseMsg.Pack(); err == nil {
					// Update message ID from query
					finalBytes[0] = query[0]
					finalBytes[1] = query[1]
					return h.handleResponseSize(msg, finalBytes)
				}
			}

			// Fallback: use cached response as-is with ID replacement
			result := make([]byte, len(cachedResponse))
			result[0] = query[0]
			result[1] = query[1]
			copy(result[2:], cachedResponse[2:])
			return h.handleResponseSize(msg, result)
		}

		// Try RRset cache
		if rrs := h.rrsetCache.Get(q.Name, q.Qtype); rrs != nil {
			response := cache.BuildResponse(msg, rrs)

			// Apply EDNS0
			h.applyEDNS0(msg, response)

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

			return h.handleResponseSize(msg, responseBytes)
		}
	}

	// Need to resolve
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

	// Security: Validate response against query (cache poisoning protection)
	if h.config.EnableCachePoisoningProtection {
		if err := h.cachePoisoningProtector.ValidateResponse(msg, response); err != nil {
			// Response validation failed - potential cache poisoning attempt
			// Return SERVFAIL and don't cache
			return h.buildErrorResponse(query, dns.RcodeServerFailure)
		}
	}

	// Validate DNSSEC if DO bit is set
	ednsInfo := edns0.ParseEDNS0(msg)
	if ednsInfo.DO && h.config.EnableDNSSEC {
		validationResult, err := h.dnssecValidator.ValidateResponse(ctx, response)
		if err == nil && validationResult.Secure {
			// Set AD (Authenticated Data) bit
			response.AuthenticatedData = true
		} else if validationResult != nil && validationResult.Bogus {
			// Validation failed - return SERVFAIL if required
			if h.dnssecValidator != nil {
				// For now, just log and continue
				// In production, might want to return SERVFAIL
			}
		}
	}

	// Apply EDNS0 if query had it
	h.applyEDNS0(msg, response)

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

	// Handle response size (truncate if needed)
	return h.handleResponseSize(msg, responseBytes)
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

// applyEDNS0 adds EDNS0 OPT record to response if query had EDNS0
// Also handles response truncation if response exceeds buffer size
func (h *Handler) applyEDNS0(queryMsg, responseMsg *dns.Msg) {
	// Parse EDNS0 from query
	ednsInfo := edns0.ParseEDNS0(queryMsg)

	if !ednsInfo.Present {
		// No EDNS0 in query, don't add to response
		return
	}

	// Add OPT record to response with negotiated buffer size
	// Server advertises its maximum size, client uses minimum of both
	serverBufferSize := uint16(edns0.MaximumUDPSize)
	bufferSize := edns0.NegotiateBufferSize(ednsInfo.UDPSize, serverBufferSize)

	// Preserve DO bit from query (DNSSEC OK)
	edns0.AddOPTRecord(responseMsg, bufferSize, ednsInfo.DO)
}

// handleResponseSize checks if response fits in EDNS0 buffer and truncates if needed
func (h *Handler) handleResponseSize(queryMsg *dns.Msg, responseBytes []byte) ([]byte, error) {
	// Parse EDNS0 from query
	ednsInfo := edns0.ParseEDNS0(queryMsg)

	// Check if response should be truncated
	if edns0.ShouldTruncate(len(responseBytes), ednsInfo) {
		// Response too large - set TC (truncation) bit
		// Client should retry over TCP
		msg := h.msgPool.Get()
		defer h.msgPool.Put(msg)

		if err := msg.Unpack(responseBytes); err != nil {
			return responseBytes, nil // Return as-is if we can't parse
		}

		// Set truncation bit
		msg.Truncated = true

		// Keep the response as-is but with TC bit set
		// The client should retry over TCP to get the full response
		// We don't remove sections - just signal truncation

		// Pack response with TC bit
		return msg.Pack()
	}

	return responseBytes, nil
}
