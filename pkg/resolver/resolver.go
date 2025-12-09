package resolver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/cache"
	"github.com/piwi3910/dns-go/pkg/dnssec"
)

// Package-level errors.
var (
	ErrQueryNoQuestions          = errors.New("query has no questions")
	ErrUnknownRecursionMode      = errors.New("unknown recursion mode")
	ErrIterativeResolverNotInit  = errors.New("iterative resolver not initialized")
)

// RecursionMode defines how the resolver operates.
type RecursionMode int

const (
	// ForwardingMode forwards queries to upstream resolvers (Google DNS, Cloudflare, etc.)
	ForwardingMode RecursionMode = iota
	// RecursiveMode performs true recursive resolution starting from root servers.
	RecursiveMode
	// ParallelMode queries multiple forwarders simultaneously and returns fastest good response.
	// Falls back to recursive resolution if all forwarders fail.
	ParallelMode
)

// Resolver configuration defaults.
const (
	defaultWorkerPoolSize   = 1000 // Default worker pool size for concurrent queries
	defaultMaxRetries       = 2    // Default maximum number of retry attempts
	// Note: defaultQueryTimeoutSec is defined in iterative.go.
)

// Resolver handles DNS query resolution
// Uses a worker pool to handle concurrent queries efficiently.
type Resolver struct {
	upstream  *UpstreamPool
	iterative *IterativeResolver
	config    Config

	// DNSSEC validation
	dnssecValidator *dnssec.Validator
	dnssecEnabled   bool

	// Request coalescing - deduplicate in-flight queries
	inFlight map[string]*inflightRequest
	mu       sync.Mutex
}

// Config holds configuration for the resolver.
type Config struct {
	// Mode determines resolution strategy (Forwarding, Recursive, or Parallel)
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

	// ParallelConfig holds configuration for parallel forwarding mode
	ParallelConfig ParallelConfig
}

// ParallelConfig holds configuration for parallel forwarding.
type ParallelConfig struct {
	// NumParallel is the number of upstreams to query in parallel
	NumParallel int

	// FallbackToRecursive enables fallback to recursive resolution
	FallbackToRecursive bool

	// SuccessRcodes defines which response codes are considered successful
	SuccessRcodes []int
}

// DefaultConfig returns configuration with sensible defaults
// Uses ParallelMode for best performance with fallback to recursive.
func DefaultConfig() Config {
	return Config{
		Mode:             ParallelMode,                          // Parallel forwarding with recursive fallback
		WorkerPoolSize:   defaultWorkerPoolSize,                 // 1000 concurrent queries
		MaxRetries:       defaultMaxRetries,                     // 2 retry attempts
		QueryTimeout:     defaultQueryTimeoutSec * time.Second,  // 5 second timeout
		EnableCoalescing: true,                                  // Request deduplication enabled
		EnableDNSSEC:     true,                                  // DNSSEC validation enabled by default
		DNSSECConfig:     dnssec.DefaultValidatorConfig(),
		ParallelConfig: ParallelConfig{
			NumParallel:         3,            // Query 3 upstreams simultaneously
			FallbackToRecursive: true,         // Fall back to recursive if all fail
			SuccessRcodes:       []int{0, 3},  // NOERROR, NXDOMAIN are valid
		},
	}
}

// DefaultForwardingConfig returns configuration for forwarding mode
// Useful for testing or when you want to use upstream resolvers.
func DefaultForwardingConfig() Config {
	config := DefaultConfig()
	config.Mode = ForwardingMode

	return config
}

// inflightRequest represents a query currently being resolved
// Used for request coalescing to avoid duplicate upstream queries.
type inflightRequest struct {
	mu       sync.Mutex
	response *dns.Msg
	err      error
	done     chan struct{}
	waiters  int
}

// NewResolver creates a new DNS resolver.
func NewResolver(config Config, upstream *UpstreamPool) *Resolver {
	r := &Resolver{
		upstream:        upstream,
		iterative:       nil,
		config:          config,
		dnssecValidator: nil,
		dnssecEnabled:   config.EnableDNSSEC,
		inFlight:        make(map[string]*inflightRequest),
		mu:              sync.Mutex{},
	}

	// Initialize DNSSEC validator if enabled
	if config.EnableDNSSEC {
		r.dnssecValidator = dnssec.NewValidator(config.DNSSECConfig)
	}

	// Initialize iterative resolver if needed (recursive mode or parallel mode with fallback)
	if config.Mode == RecursiveMode || (config.Mode == ParallelMode && config.ParallelConfig.FallbackToRecursive) {
		r.iterative = NewIterativeResolver()
	}

	return r
}

// Resolve resolves a DNS query
// If coalescing is enabled, duplicate queries will wait for the first one.
func (r *Resolver) Resolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if len(query.Question) == 0 {
		return nil, ErrQueryNoQuestions
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

// GetStats returns current resolver statistics.
func (r *Resolver) GetStats() Stats {
	r.mu.Lock()
	inFlight := len(r.inFlight)
	r.mu.Unlock()

	return Stats{
		InFlightQueries: inFlight,
		Upstreams:       r.upstream.GetStats(),
	}
}

// resolveWithCoalescing resolves a query with request coalescing
// If an identical query is in-flight, wait for its result instead of querying again.
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
			return nil, fmt.Errorf("query resolution cancelled: %w", ctx.Err())
		}
	}

	// Create new in-flight request
	inflight := &inflightRequest{
		mu:       sync.Mutex{},
		response: nil,
		err:      nil,
		done:     make(chan struct{}),
		waiters:  0,
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

// doResolve performs the actual DNS resolution.
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

	case ParallelMode:
		// Parallel forwarding with recursive fallback
		return r.doParallelResolve(queryCtx, query)

	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownRecursionMode, r.config.Mode)
	}
}

// doRecursiveResolve performs true recursive resolution from root servers.
func (r *Resolver) doRecursiveResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	if r.iterative == nil {
		return nil, ErrIterativeResolverNotInit
	}

	if len(query.Question) == 0 {
		return nil, ErrQueryNoQuestions
	}

	q := query.Question[0]

	// Perform iterative resolution
	response, err := r.iterative.Resolve(ctx, q.Name, q.Qtype)
	if err != nil {
		return nil, err
	}

	if response == nil {
		return response, nil
	}

	// Copy query ID and flags to response
	response.Id = query.Id
	response.RecursionDesired = query.RecursionDesired
	response.RecursionAvailable = true

	// DNSSEC validation if enabled and CheckingDisabled is not set
	if !r.dnssecEnabled || r.dnssecValidator == nil || query.CheckingDisabled {
		return response, nil
	}

	validationResult, err := r.dnssecValidator.ValidateResponse(ctx, response)
	// Handle validation error first
	if err != nil {
		if r.config.DNSSECConfig.RequireValidation {
			return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
		}
		response.AuthenticatedData = false
	} else {
		// Set AD bit based on validation result
		response.AuthenticatedData = validationResult.Secure
	}

	return response, nil
}

// doForwardingResolve forwards queries to upstream resolvers.
func (r *Resolver) doForwardingResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Query upstream with fallback
	response, err := r.upstream.QueryWithFallback(ctx, query, r.config.MaxRetries)
	if err != nil {
		return nil, err
	}

	// Validate response
	if response == nil {
		return nil, ErrNilResponse
	}

	// DNSSEC validation if enabled
	if r.dnssecEnabled && r.dnssecValidator != nil {
		validationResult, err := r.dnssecValidator.ValidateResponse(ctx, response)
		// Handle validation error first
		if err != nil {
			if r.config.DNSSECConfig.RequireValidation {
				return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
			}
			response.AuthenticatedData = false
		} else {
			// Set AD bit based on validation result
			response.AuthenticatedData = validationResult.Secure
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

// doParallelResolve performs parallel queries to multiple forwarders.
// Returns the fastest successful response or falls back to recursive resolution.
func (r *Resolver) doParallelResolve(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	// Try parallel forwarding first
	response, err := r.upstream.QueryParallel(ctx, query, r.config.ParallelConfig.NumParallel, r.config.ParallelConfig.SuccessRcodes)
	if err == nil && response != nil {
		// Got a good response from forwarders
		return r.applyDNSSECValidation(ctx, query, response)
	}

	// All forwarders failed - check if we should fall back to recursive
	if !r.config.ParallelConfig.FallbackToRecursive {
		if err != nil {
			return nil, fmt.Errorf("parallel forwarding failed: %w", err)
		}
		return nil, ErrAllUpstreamsFailed
	}

	// Fall back to recursive resolution
	if r.iterative == nil {
		return nil, ErrIterativeResolverNotInit
	}

	return r.doRecursiveResolve(ctx, query)
}

// applyDNSSECValidation applies DNSSEC validation to a response if enabled.
func (r *Resolver) applyDNSSECValidation(ctx context.Context, query, response *dns.Msg) (*dns.Msg, error) {
	// Copy query ID and flags to response
	response.Id = query.Id
	response.RecursionDesired = query.RecursionDesired
	response.RecursionAvailable = true

	// DNSSEC validation if enabled and CheckingDisabled is not set
	if !r.dnssecEnabled || r.dnssecValidator == nil || query.CheckingDisabled {
		return response, nil
	}

	validationResult, err := r.dnssecValidator.ValidateResponse(ctx, response)
	if err != nil {
		if r.config.DNSSECConfig.RequireValidation {
			return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
		}
		response.AuthenticatedData = false
	} else {
		response.AuthenticatedData = validationResult.Secure
	}

	return response, nil
}

// Stats represents statistical metrics for DNS resolution operations.
type Stats struct {
	InFlightQueries int
	Upstreams       []cache.UpstreamSnapshot
}

// makeQueryKey creates a unique key for a query
// Used for request coalescing.
func makeQueryKey(name string, qtype uint16, qclass uint16) string {
	return cache.MakeKey(name, qtype, qclass)
}
