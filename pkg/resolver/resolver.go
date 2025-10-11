package resolver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
	"github.com/piwi3910/dns-go/pkg/dnssec"
)

// RecursionMode defines how the resolver operates
type RecursionMode int

const (
	// ForwardingMode forwards queries to upstream resolvers (Google DNS, Cloudflare, etc.)
	ForwardingMode RecursionMode = iota
	// RecursiveMode performs true recursive resolution starting from root servers
	RecursiveMode
)

// Resolver handles DNS query resolution
// Uses a worker pool to handle concurrent queries efficiently
type Resolver struct {
	upstream  *UpstreamPool
	iterative *IterativeResolver
	config    ResolverConfig

	// DNSSEC validation
	dnssecValidator *dnssec.Validator
	dnssecEnabled   bool

	// Request coalescing - deduplicate in-flight queries
	inFlight map[string]*inflightRequest
	mu       sync.Mutex
}

// ResolverConfig holds configuration for the resolver
type ResolverConfig struct {
	// Mode determines resolution strategy (Forwarding or Recursive)
	Mode RecursionMode

	// WorkerPoolSize is the maximum number of concurrent queries
	WorkerPoolSize int

	// MaxRetries is the maximum number of retry attempts
	MaxRetries int

	// QueryTimeout is the timeout for individual queries
	QueryTimeout time.Duration

	// EnableCoalescing enables request deduplication
	EnableCoalescing bool

	// EnableDNSSEC enables DNSSEC validation of responses
	EnableDNSSEC bool

	// DNSSECConfig holds DNSSEC validator configuration
	DNSSECConfig dnssec.ValidatorConfig
}

// DefaultResolverConfig returns configuration with sensible defaults
// Uses RecursiveMode for true local recursion from root servers
func DefaultResolverConfig() ResolverConfig {
	return ResolverConfig{
		Mode:             RecursiveMode, // True recursive resolution
		WorkerPoolSize:   1000,
		MaxRetries:       2,
		QueryTimeout:     5 * time.Second,
		EnableCoalescing: true,
		EnableDNSSEC:     true, // DNSSEC validation enabled by default
		DNSSECConfig:     dnssec.DefaultValidatorConfig(),
	}
}

// DefaultForwardingConfig returns configuration for forwarding mode
// Useful for testing or when you want to use upstream resolvers
func DefaultForwardingConfig() ResolverConfig {
	config := DefaultResolverConfig()
	config.Mode = ForwardingMode
	return config
}

// inflightRequest represents a query currently being resolved
// Used for request coalescing to avoid duplicate upstream queries
type inflightRequest struct {
	mu       sync.Mutex
	response *dns.Msg
	err      error
	done     chan struct{}
	waiters  int
}

// NewResolver creates a new DNS resolver
func NewResolver(config ResolverConfig, upstream *UpstreamPool) *Resolver {
	r := &Resolver{
		upstream:      upstream,
		config:        config,
		inFlight:      make(map[string]*inflightRequest),
		dnssecEnabled: config.EnableDNSSEC,
	}

	// Initialize DNSSEC validator if enabled
	if config.EnableDNSSEC {
		r.dnssecValidator = dnssec.NewValidator(config.DNSSECConfig)
	}

	// Initialize iterative resolver if in recursive mode
	if config.Mode == RecursiveMode {
		r.iterative = NewIterativeResolver()
	}

	return r
}

// Resolve resolves a DNS query
// If coalescing is enabled, duplicate queries will wait for the first one
func (r *Resolver) Resolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if len(query.Question) == 0 {
		return nil, fmt.Errorf("query has no questions")
	}

	q := query.Question[0]
	queryKey := makeQueryKey(q.Name, q.Qtype, q.Qclass)

	// Check if coalescing is enabled
	if r.config.EnableCoalescing {
		return r.resolveWithCoalescing(ctx, query, queryKey)
	}

	// No coalescing - resolve directly
	return r.doResolve(ctx, query)
}

// resolveWithCoalescing resolves a query with request coalescing
// If an identical query is in-flight, wait for its result instead of querying again
func (r *Resolver) resolveWithCoalescing(ctx context.Context, query *dns.Msg, queryKey string) (*dns.Msg, error) {
	r.mu.Lock()

	// Check if this query is already in-flight
	if inflight, exists := r.inFlight[queryKey]; exists {
		// Wait for the in-flight query to complete
		inflight.mu.Lock()
		inflight.waiters++
		inflight.mu.Unlock()
		r.mu.Unlock()

		// Wait for completion
		select {
		case <-inflight.done:
			return inflight.response, inflight.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Create new in-flight request
	inflight := &inflightRequest{
		done: make(chan struct{}),
	}
	r.inFlight[queryKey] = inflight
	r.mu.Unlock()

	// Resolve the query
	response, err := r.doResolve(ctx, query)

	// Store result and notify waiters
	inflight.mu.Lock()
	inflight.response = response
	inflight.err = err
	close(inflight.done)
	inflight.mu.Unlock()

	// Remove from in-flight map
	r.mu.Lock()
	delete(r.inFlight, queryKey)
	r.mu.Unlock()

	return response, err
}

// doResolve performs the actual DNS resolution
func (r *Resolver) doResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Create query context with timeout
	queryCtx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	// Choose resolution strategy based on mode
	switch r.config.Mode {
	case RecursiveMode:
		// True recursive resolution from root servers
		return r.doRecursiveResolve(queryCtx, query)

	case ForwardingMode:
		// Forward to upstream resolvers (Google DNS, Cloudflare, etc.)
		return r.doForwardingResolve(queryCtx, query)

	default:
		return nil, fmt.Errorf("unknown recursion mode: %d", r.config.Mode)
	}
}

// doRecursiveResolve performs true recursive resolution from root servers
func (r *Resolver) doRecursiveResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if r.iterative == nil {
		return nil, fmt.Errorf("iterative resolver not initialized")
	}

	if len(query.Question) == 0 {
		return nil, fmt.Errorf("query has no questions")
	}

	q := query.Question[0]

	// Perform iterative resolution
	response, err := r.iterative.Resolve(ctx, q.Name, q.Qtype)
	if err != nil {
		return nil, err
	}

	// Copy query ID and flags to response
	if response != nil {
		response.Id = query.Id
		response.RecursionDesired = query.RecursionDesired
		response.RecursionAvailable = true

		// DNSSEC validation if enabled and CheckingDisabled is not set
		if r.dnssecEnabled && r.dnssecValidator != nil && !query.CheckingDisabled {
			validationResult, err := r.dnssecValidator.ValidateResponse(ctx, response)
			if err != nil {
				// Validation error
				if r.config.DNSSECConfig.RequireValidation {
					return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
				}
				response.AuthenticatedData = false
			} else if validationResult.Secure {
				// Validation successful
				response.AuthenticatedData = true
			} else {
				// Insecure or Bogus
				response.AuthenticatedData = false
			}
		}
	}

	return response, nil
}

// doForwardingResolve forwards queries to upstream resolvers
func (r *Resolver) doForwardingResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Query upstream with fallback
	response, err := r.upstream.QueryWithFallback(ctx, query, r.config.MaxRetries)
	if err != nil {
		return nil, err
	}

	// Validate response
	if response == nil {
		return nil, fmt.Errorf("nil response from upstream")
	}

	// DNSSEC validation if enabled
	if r.dnssecEnabled && r.dnssecValidator != nil {
		validationResult, err := r.dnssecValidator.ValidateResponse(ctx, response)
		if err != nil {
			// Validation error - log but don't fail if RequireValidation is false
			if r.config.DNSSECConfig.RequireValidation {
				return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
			}
			// Set AD (Authentic Data) bit to false
			response.AuthenticatedData = false
		} else if validationResult.Secure {
			// Validation successful - set AD bit
			response.AuthenticatedData = true
		} else {
			// Insecure or Bogus - clear AD bit
			response.AuthenticatedData = false
		}
	}

	// Check response code
	if response.Rcode != dns.RcodeSuccess {
		// Return the response even if it's an error (NXDOMAIN, etc.)
		// The handler can cache error responses too
		return response, nil
	}

	return response, nil
}

// makeQueryKey creates a unique key for a query
// Used for request coalescing
func makeQueryKey(name string, qtype uint16, qclass uint16) string {
	return cache.MakeKey(name, qtype, qclass)
}

// GetStats returns resolver statistics
type ResolverStats struct {
	InFlightQueries int
	Upstreams       []cache.UpstreamSnapshot
}

// GetStats returns current resolver statistics
func (r *Resolver) GetStats() ResolverStats {
	r.mu.Lock()
	inFlight := len(r.inFlight)
	r.mu.Unlock()

	return ResolverStats{
		InFlightQueries: inFlight,
		Upstreams:       r.upstream.GetStats(),
	}
}
