// Package resolver implements DNS resolution with support for recursive and iterative modes.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Package-level errors for iterative resolution.
var (
	ErrMaxDelegationDepthExceeded = errors.New("maximum delegation depth exceeded")
	ErrNoNameserversAvailable     = errors.New("no nameservers available")
	ErrIterativeNilResponse       = errors.New("nil response")
	ErrServerFailure              = errors.New("SERVFAIL")
	ErrErrorRcode                 = errors.New("error rcode")
	ErrAllNameserversFailed       = errors.New("all nameservers failed")
	ErrNoARecordsForNS            = errors.New("no A records for NS")
)

// Iterative resolution configuration constants.
const (
	defaultQueryTimeoutSec  = 5  // Default DNS query timeout in seconds
	defaultMaxDelegationDepth = 16 // Maximum delegation depth to prevent loops
	defaultParallelNSLimit  = 2  // Number of nameservers to query in parallel
	defaultNSCacheTimeoutMin = 5  // Default NS cache timeout in minutes
)

// IterativeResolver performs iterative DNS resolution starting from root servers.
type IterativeResolver struct {
	client          *dns.Client
	rootPool        *RootServerPool
	maxDepth        int                             // Maximum delegation depth to prevent loops
	parallelNSLimit int                             // Number of nameservers to query in parallel
	queryCache      map[string]*iterativeCacheEntry // Cache for NS records and glue
}

// iterativeCacheEntry caches nameserver information.
type iterativeCacheEntry struct {
	nameservers []string            // NS names
	glue        map[string][]string // NS name -> IP addresses
	expiry      time.Time
}

// NewIterativeResolver creates a new iterative resolver.
func NewIterativeResolver() *IterativeResolver {
	return &IterativeResolver{
		client: &dns.Client{
			Net:            "udp",
			UDPSize:        0,
			TLSConfig:      nil,
			Dialer:         nil,
			Timeout:        defaultQueryTimeoutSec * time.Second,
			DialTimeout:    0,
			ReadTimeout:    0,
			WriteTimeout:   0,
			TsigSecret:     nil,
			TsigProvider:   nil,
			SingleInflight: false,
		},
		rootPool:        NewRootServerPool(),
		maxDepth:        defaultMaxDelegationDepth,
		parallelNSLimit: defaultParallelNSLimit,
		queryCache:      make(map[string]*iterativeCacheEntry),
	}
}

// Resolve performs iterative resolution starting from root servers.
func (ir *IterativeResolver) Resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	// Normalize query name
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}

	// Start from root servers
	return ir.resolveIterative(ctx, qname, qtype, 0)
}

// resolveIterative performs the iterative resolution process.
func (ir *IterativeResolver) resolveIterative(
	ctx context.Context,
	qname string,
	qtype uint16,
	depth int,
) (*dns.Msg, error) {
	// Check depth limit to prevent infinite loops
	if depth > ir.maxDepth {
		return nil, ErrMaxDelegationDepthExceeded
	}

	// Build query
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.RecursionDesired = false // We handle recursion ourselves

	// Get nameservers to query
	nameservers, glue := ir.getNameserversToQuery(qname)

	// Try each nameserver
	return ir.queryNameservers(ctx, qname, qtype, query, nameservers, glue, depth)
}

// getNameserversToQuery determines which nameservers to query for a domain.
func (ir *IterativeResolver) getNameserversToQuery(qname string) ([]string, map[string][]string) {
	// Walk up the domain hierarchy to find cached NS records
	nameservers, glue := ir.findNameservers(qname)

	if len(nameservers) == 0 {
		// No cached NS records, start from root
		nameservers = ir.rootPool.GetAllServers()
	}

	return nameservers, glue
}

// queryNameservers queries a list of nameservers and returns the first successful response.
func (ir *IterativeResolver) queryNameservers(
	ctx context.Context,
	qname string,
	qtype uint16,
	query *dns.Msg,
	nameservers []string,
	glue map[string][]string,
	depth int,
) (*dns.Msg, error) {
	var lastErr error

	for _, ns := range nameservers {
		// Resolve NS name to IP addresses
		nsAddrs, err := ir.resolveNSAddresses(ctx, ns, glue, depth)
		if err != nil {
			lastErr = err

			continue
		}

		// Query each NS address
		response, err := ir.queryNSAddresses(ctx, qname, qtype, query, nsAddrs, depth)
		if err != nil {
			lastErr = err

			continue
		}

		if response != nil {
			return response, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all nameservers failed: %w", lastErr)
	}

	return nil, ErrNoNameserversAvailable
}

// resolveNSAddresses resolves a nameserver name to IP addresses.
func (ir *IterativeResolver) resolveNSAddresses(
	ctx context.Context,
	ns string,
	glue map[string][]string,
	depth int,
) ([]string, error) {
	// If already an IP address, return it
	if isIPAddress(ns) {
		return []string{ns}, nil
	}

	// Look up in glue records first
	if addrs, ok := glue[ns]; ok && len(addrs) > 0 {
		return addrs, nil
	}

	// Need to resolve NS name (out-of-bailiwick)
	return ir.resolveNS(ctx, ns, depth+1)
}

// queryNSAddresses queries a list of NS addresses and returns the first successful response.
func (ir *IterativeResolver) queryNSAddresses(
	ctx context.Context,
	qname string,
	qtype uint16,
	query *dns.Msg,
	nsAddrs []string,
	depth int,
) (*dns.Msg, error) {
	var lastErr error

	for _, addr := range nsAddrs {
		// Ensure address has port
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}

		start := time.Now()
		response, _, err := ir.client.ExchangeContext(ctx, query, addr)
		rtt := time.Since(start)

		if err != nil {
			lastErr = err

			continue
		}

		if response == nil {
			lastErr = fmt.Errorf("%w from %s", ErrIterativeNilResponse, addr)

			continue
		}

		// Record RTT if this is a root server
		ir.rootPool.RecordRTT(addr, rtt)

		// Process response
		result, err := ir.processIterativeResponse(ctx, qname, qtype, response, depth)
		if err != nil {
			lastErr = err

			continue
		}

		if result != nil {
			return result, nil
		}
	}

	return nil, lastErr
}

// processIterativeResponse processes a DNS response and handles referrals.
func (ir *IterativeResolver) processIterativeResponse(
	ctx context.Context,
	qname string,
	qtype uint16,
	response *dns.Msg,
	depth int,
) (*dns.Msg, error) {
	switch response.Rcode {
	case dns.RcodeSuccess:
		// Check if this is the final answer or a referral
		if len(response.Answer) > 0 {
			// Got answer!
			return response, nil
		}

		// Check for delegation (NS records in Authority section)
		if len(response.Ns) > 0 {
			// This is a referral - extract NS records and glue
			newNS, newGlue := extractNSAndGlue(response)
			if len(newNS) > 0 {
				// Cache the delegation
				ir.cacheNS(qname, newNS, newGlue)

				// Follow the referral
				return ir.resolveWithNS(ctx, qname, qtype, newNS, newGlue, depth+1)
			}
		}

		// Empty response with no answer or referral
		return response, nil

	case dns.RcodeNameError:
		// NXDOMAIN - name doesn't exist
		return response, nil

	case dns.RcodeServerFailure:
		// SERVFAIL - try next server
		return nil, ErrServerFailure

	default:
		// Other error - try next server
		return nil, fmt.Errorf("%w: %s", ErrErrorRcode, dns.RcodeToString[response.Rcode])
	}
}

// resolveWithNS continues resolution with specific nameservers
// Uses parallel queries for faster resolution.
func (ir *IterativeResolver) resolveWithNS(
	ctx context.Context,
	qname string,
	qtype uint16,
	nameservers []string,
	glue map[string][]string,
	depth int,
) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.RecursionDesired = false

	// Use only the first N nameservers for parallel queries to avoid overwhelming the network
	nsLimit := ir.getLimitedNSCount(nameservers)

	// Query nameservers sequentially but try multiple addresses in parallel
	for _, ns := range nameservers[:nsLimit] {
		nsAddrs, err := ir.resolveNSForParallel(ctx, ns, glue, depth)
		if err != nil || len(nsAddrs) == 0 {
			continue
		}

		// Try this NS's addresses in parallel
		response, err := ir.queryNSAddressesParallel(ctx, qname, qtype, query, nsAddrs, depth)
		if err != nil {
			continue
		}

		if response != nil {
			return response, nil
		}
	}

	// All nameservers failed
	return nil, ErrAllNameserversFailed
}

// getLimitedNSCount returns the number of nameservers to query (limited by parallelNSLimit).
func (ir *IterativeResolver) getLimitedNSCount(nameservers []string) int {
	nsLimit := ir.parallelNSLimit
	if len(nameservers) < nsLimit {
		nsLimit = len(nameservers)
	}

	return nsLimit
}

// resolveNSForParallel resolves a nameserver name to addresses for parallel queries.
func (ir *IterativeResolver) resolveNSForParallel(
	ctx context.Context,
	ns string,
	glue map[string][]string,
	depth int,
) ([]string, error) {
	if addrs, ok := glue[ns]; ok && len(addrs) > 0 {
		return addrs, nil
	}

	// Need to resolve the NS name (out-of-bailiwick)
	return ir.resolveNS(ctx, ns, depth+1)
}

// queryResult holds the result of a parallel DNS query.
type queryResult struct {
	response *dns.Msg
	err      error
}

// queryNSAddressesParallel queries multiple NS addresses in parallel.
func (ir *IterativeResolver) queryNSAddressesParallel(
	ctx context.Context,
	qname string,
	qtype uint16,
	query *dns.Msg,
	nsAddrs []string,
	depth int,
) (*dns.Msg, error) {
	results := make(chan queryResult, len(nsAddrs))
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start parallel queries
	for _, addr := range nsAddrs {
		go ir.executeParallelQuery(queryCtx, query, addr, results)
	}

	// Collect and process results
	return ir.collectParallelResults(ctx, qname, qtype, nsAddrs, results, cancel, depth)
}

// executeParallelQuery executes a single DNS query in a goroutine.
func (ir *IterativeResolver) executeParallelQuery(
	ctx context.Context,
	query *dns.Msg,
	addr string,
	results chan<- queryResult,
) {
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	response, _, err := ir.client.ExchangeContext(ctx, query, addr)
	if err != nil {
		results <- queryResult{nil, err}

		return
	}

	if response != nil {
		results <- queryResult{response, nil}
	} else {
		results <- queryResult{nil, ErrIterativeNilResponse}
	}
}

// collectParallelResults collects and processes results from parallel queries.
func (ir *IterativeResolver) collectParallelResults(
	ctx context.Context,
	qname string,
	qtype uint16,
	nsAddrs []string,
	results <-chan queryResult,
	cancel context.CancelFunc,
	depth int,
) (*dns.Msg, error) {
	var lastErr error

	for range nsAddrs {
		select {
		case res := <-results:
			if res.err != nil {
				lastErr = res.err

				continue
			}

			response, err := ir.processParallelResponse(ctx, qname, qtype, res.response, depth)
			if err != nil {
				lastErr = err

				continue
			}

			if response != nil {
				cancel() // Cancel other queries

				return response, nil
			}

		case <-ctx.Done():
			return nil, fmt.Errorf("iterative resolution cancelled: %w", ctx.Err())
		}
	}

	return nil, lastErr
}

// processParallelResponse processes a response from a parallel query.
func (ir *IterativeResolver) processParallelResponse(
	ctx context.Context,
	qname string,
	qtype uint16,
	response *dns.Msg,
	depth int,
) (*dns.Msg, error) {
	switch response.Rcode {
	case dns.RcodeSuccess:
		if len(response.Answer) > 0 {
			return response, nil
		}

		// Another referral?
		if len(response.Ns) > 0 {
			newNS, newGlue := extractNSAndGlue(response)
			if len(newNS) > 0 {
				ir.cacheNS(qname, newNS, newGlue)

				return ir.resolveWithNS(ctx, qname, qtype, newNS, newGlue, depth+1)
			}
		}

		return response, nil

	case dns.RcodeNameError:
		return response, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrErrorRcode, dns.RcodeToString[response.Rcode])
	}
}

// resolveNS resolves a nameserver name to IP addresses.
func (ir *IterativeResolver) resolveNS(ctx context.Context, nsName string, depth int) ([]string, error) {
	// Query for A record
	response, err := ir.resolveIterative(ctx, nsName, dns.TypeA, depth)
	if err != nil {
		return nil, err
	}

	addresses := []string{}
	if response != nil && len(response.Answer) > 0 {
		for _, rr := range response.Answer {
			if a, ok := rr.(*dns.A); ok {
				addresses = append(addresses, a.A.String())
			}
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoARecordsForNS, nsName)
	}

	return addresses, nil
}

// findNameservers finds cached nameservers for a domain.
func (ir *IterativeResolver) findNameservers(qname string) ([]string, map[string][]string) {
	// Walk up the domain hierarchy looking for cached NS records
	labels := dns.SplitDomainName(qname)

	for i := range labels {
		domain := dns.Fqdn(strings.Join(labels[i:], "."))
		if entry, exists := ir.queryCache[domain]; exists {
			if time.Now().Before(entry.expiry) {
				return entry.nameservers, entry.glue
			}
			// Expired - remove
			delete(ir.queryCache, domain)
		}
	}

	return nil, nil
}

// cacheNS caches nameserver information.
func (ir *IterativeResolver) cacheNS(domain string, nameservers []string, glue map[string][]string) {
	ir.queryCache[domain] = &iterativeCacheEntry{
		nameservers: nameservers,
		glue:        glue,
		expiry:      time.Now().Add(defaultNSCacheTimeoutMin * time.Minute), // Cache for 5 minutes
	}
}

// extractNSAndGlue extracts NS records and glue records from a response.
func extractNSAndGlue(msg *dns.Msg) ([]string, map[string][]string) {
	nameservers := []string{}
	glue := make(map[string][]string)

	// Extract NS records from Authority section
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nameservers = append(nameservers, ns.Ns)
		}
	}

	// Extract glue (A/AAAA records) from Additional section
	for _, rr := range msg.Extra {
		switch rec := rr.(type) {
		case *dns.A:
			name := rec.Header().Name
			glue[name] = append(glue[name], rec.A.String())
		case *dns.AAAA:
			name := rec.Header().Name
			glue[name] = append(glue[name], rec.AAAA.String())
		}
	}

	return nameservers, glue
}

// isIPAddress checks if a string is an IP address.
func isIPAddress(s string) bool {
	// Remove port if present
	host := s
	if idx := strings.LastIndex(s, ":"); idx > 0 {
		host = s[:idx]
	}

	return net.ParseIP(host) != nil
}
