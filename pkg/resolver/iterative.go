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
			Net:     "udp",
			Timeout: 5 * time.Second,
		},
		rootPool:        NewRootServerPool(),
		maxDepth:        16, // Reasonable depth limit
		parallelNSLimit: 2,  // Query 2 nameservers in parallel by default
		queryCache:      make(map[string]*iterativeCacheEntry),
	}
}

// Resolve performs iterative resolution starting from root servers.
func (ir *IterativeResolver) Resolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	// Normalize query name
	if !strings.HasSuffix(qname, ".") {
		qname = qname + "."
	}

	// Start from root servers
	return ir.resolveIterative(ctx, qname, qtype, 0)
}

// resolveIterative performs the iterative resolution process.
func (ir *IterativeResolver) resolveIterative(ctx context.Context, qname string, qtype uint16, depth int) (*dns.Msg, error) {
	// Check depth limit to prevent infinite loops
	if depth > ir.maxDepth {
		return nil, errors.New("maximum delegation depth exceeded")
	}

	// Build query
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.RecursionDesired = false // We handle recursion ourselves

	// Start with root servers
	var nameservers []string
	var glue map[string][]string

	// Determine which nameservers to query
	// Walk up the domain hierarchy to find cached NS records
	nameservers, glue = ir.findNameservers(qname)

	if len(nameservers) == 0 {
		// No cached NS records, start from root
		nameservers = ir.rootPool.GetAllServers()
	}

	// Try each nameserver
	var lastErr error
	for _, ns := range nameservers {
		// Resolve NS name to IP if not already an IP
		nsAddrs := []string{ns}
		if !isIPAddress(ns) {
			// Look up in glue records first
			if addrs, ok := glue[ns]; ok && len(addrs) > 0 {
				nsAddrs = addrs
			} else {
				// Need to resolve NS name (out-of-bailiwick)
				resolved, err := ir.resolveNS(ctx, ns, depth+1)
				if err != nil {
					lastErr = err

					continue
				}
				nsAddrs = resolved
			}
		}

		// Query each NS address
		for _, addr := range nsAddrs {
			// Ensure address has port
			if !strings.Contains(addr, ":") {
				addr = addr + ":53"
			}

			start := time.Now()
			response, _, err := ir.client.ExchangeContext(ctx, query, addr)
			rtt := time.Since(start)

			if err != nil {
				lastErr = err

				continue
			}

			if response == nil {
				lastErr = fmt.Errorf("nil response from %s", addr)

				continue
			}

			// Record RTT if this is a root server
			ir.rootPool.RecordRTT(addr, rtt)

			// Process response based on rcode
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
				lastErr = fmt.Errorf("SERVFAIL from %s", addr)

				continue

			default:
				// Other error - try next server
				lastErr = fmt.Errorf("error response from %s: %s", addr, dns.RcodeToString[response.Rcode])

				continue
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all nameservers failed: %w", lastErr)
	}

	return nil, errors.New("no nameservers available")
}

// resolveWithNS continues resolution with specific nameservers
// Uses parallel queries for faster resolution.
func (ir *IterativeResolver) resolveWithNS(ctx context.Context, qname string, qtype uint16, nameservers []string, glue map[string][]string, depth int) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(qname, qtype)
	query.RecursionDesired = false

	// Use only the first N nameservers for parallel queries to avoid overwhelming the network
	nsLimit := ir.parallelNSLimit
	if len(nameservers) < nsLimit {
		nsLimit = len(nameservers)
	}

	// Query nameservers sequentially but try multiple addresses in parallel
	for _, ns := range nameservers[:nsLimit] {
		var nsAddrs []string
		if addrs, ok := glue[ns]; ok && len(addrs) > 0 {
			nsAddrs = addrs
		} else {
			// Need to resolve the NS name (out-of-bailiwick)
			resolved, err := ir.resolveNS(ctx, ns, depth+1)
			if err != nil {
				continue // Try next NS
			}
			nsAddrs = resolved
		}

		if len(nsAddrs) == 0 {
			continue
		}

		// Try this NS's addresses in parallel
		type result struct {
			response *dns.Msg
			err      error
		}

		results := make(chan result, len(nsAddrs))
		queryCtx, cancel := context.WithCancel(ctx)

		// Start parallel queries to this NS's addresses
		for _, addr := range nsAddrs {
			go func(address string) {
				if !strings.Contains(address, ":") {
					address = address + ":53"
				}

				response, _, err := ir.client.ExchangeContext(queryCtx, query, address)
				if err != nil {
					results <- result{nil, err}

					return
				}

				if response != nil {
					results <- result{response, nil}
				} else {
					results <- result{nil, errors.New("nil response")}
				}
			}(addr)
		}

		// Wait for results from this NS's addresses
		var lastErr error
		for range nsAddrs {
			select {
			case res := <-results:
				if res.err != nil {
					lastErr = res.err

					continue
				}

				response := res.response

				// Process response
				switch response.Rcode {
				case dns.RcodeSuccess:
					if len(response.Answer) > 0 {
						cancel() // Cancel other queries for this NS

						return response, nil
					}

					// Another referral?
					if len(response.Ns) > 0 {
						newNS, newGlue := extractNSAndGlue(response)
						if len(newNS) > 0 {
							cancel() // Cancel other queries for this NS
							ir.cacheNS(qname, newNS, newGlue)

							return ir.resolveWithNS(ctx, qname, qtype, newNS, newGlue, depth+1)
						}
					}

					cancel() // Cancel other queries for this NS

					return response, nil

				case dns.RcodeNameError:
					cancel() // Cancel other queries for this NS

					return response, nil

				default:
					lastErr = fmt.Errorf("error rcode: %s", dns.RcodeToString[response.Rcode])

					continue
				}

			case <-ctx.Done():
				cancel()

				return nil, ctx.Err()
			}
		}
		cancel() // Clean up this NS's queries

		// All addresses for this NS failed, try next NS
		if lastErr != nil {
			continue
		}
	}

	// All nameservers failed
	return nil, errors.New("all nameservers failed")
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
		return nil, fmt.Errorf("no A records for NS %s", nsName)
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
		expiry:      time.Now().Add(5 * time.Minute), // Cache for 5 minutes
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
