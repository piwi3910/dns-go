// Package main provides a DNS test client for querying DNS servers and measuring performance.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
)

// Package-level errors.
var (
	ErrUnknownQueryType = errors.New("unknown query type")
)

// Configuration constants for the DNS test client.
const (
	defaultTimeoutSec      = 5  // Default DNS query timeout in seconds
	rateLimitDelayMS       = 10 // Rate limit delay between queries in milliseconds
	maxQueriesForDetails   = 10 // Show detailed output for queries if count <= this value
)

type config struct {
	server string
	domain string
	qtype  string
	count  int
}

func parseFlags() *config {
	cfg := &config{
		server: "",
		domain: "",
		qtype:  "",
		count:  0,
	}
	flag.StringVar(&cfg.server, "server", "127.0.0.1:5353", "DNS server address")
	flag.StringVar(&cfg.domain, "domain", "example.com", "Domain to query")
	flag.StringVar(&cfg.qtype, "type", "A", "Query type (A, AAAA, MX, etc.)")
	flag.IntVar(&cfg.count, "count", 1, "Number of queries to send")
	flag.Parse()

	return cfg
}

func main() {
	cfg := parseFlags()

	// Parse query type
	queryType, err := parseQueryType(cfg.qtype)
	if err != nil {
		log.Fatal(err)
	}

	client := createClient()

	// Execute queries and collect statistics
	stats := executeQueries(client, cfg, queryType)

	// Print summary if multiple queries
	printSummary(cfg, stats)
}

// parseQueryType converts a string query type to DNS type constant.
func parseQueryType(qtype string) (uint16, error) {
	switch qtype {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "MX":
		return dns.TypeMX, nil
	case "NS":
		return dns.TypeNS, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnknownQueryType, qtype)
	}
}

// createClient creates and configures a DNS client.
func createClient() *dns.Client {
	return &dns.Client{
		Net:            "",
		UDPSize:        0,
		TLSConfig:      nil,
		Dialer:         nil,
		Timeout:        defaultTimeoutSec * time.Second,
		DialTimeout:    0,
		ReadTimeout:    0,
		WriteTimeout:   0,
		TsigSecret:     nil,
		TsigProvider:   nil,
		SingleInflight: false,
	}
}

// queryStats holds statistics for query execution.
type queryStats struct {
	totalRTT  time.Duration
	successes int
	failures  int
}

// executeQueries performs DNS queries and returns statistics.
func executeQueries(client *dns.Client, cfg *config, queryType uint16) queryStats {
	stats := queryStats{
		totalRTT:  0,
		successes: 0,
		failures:  0,
	}

	for i := range cfg.count {
		response, rtt, err := performQuery(client, cfg, queryType)

		if err != nil {
			log.Printf("Query %d failed: %v", i+1, err)
			stats.failures++

			continue
		}

		stats.successes++
		stats.totalRTT += rtt

		// Print detailed response for first query or if count <= maxQueriesForDetails
		if i == 0 || cfg.count <= maxQueriesForDetails {
			printQueryResponse(cfg, i, response, rtt)
		}

		// Rate limiting for multiple queries
		if cfg.count > 1 && i < cfg.count-1 {
			time.Sleep(rateLimitDelayMS * time.Millisecond)
		}
	}

	return stats
}

// performQuery executes a single DNS query.
func performQuery(client *dns.Client, cfg *config, queryType uint16) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(cfg.domain), queryType)
	msg.RecursionDesired = true

	response, rtt, err := client.Exchange(msg, cfg.server)
	if err != nil {
		return nil, 0, fmt.Errorf("DNS query failed for %s: %w", cfg.domain, err)
	}

	return response, rtt, nil
}

// printQueryResponse prints the details of a query response.
func printQueryResponse(cfg *config, queryNum int, response *dns.Msg, rtt time.Duration) {
	_, _ = fmt.Fprintf(os.Stdout, "\nQuery %d:\n", queryNum+1)
	_, _ = fmt.Fprintf(os.Stdout, "  Question: %s %s\n", cfg.domain, cfg.qtype)
	_, _ = fmt.Fprintf(os.Stdout, "  RTT: %v\n", rtt)
	_, _ = fmt.Fprintf(os.Stdout, "  Rcode: %s\n", dns.RcodeToString[response.Rcode])

	if len(response.Answer) > 0 {
		_, _ = fmt.Fprintf(os.Stdout, "  Answers (%d):\n", len(response.Answer))
		for _, answer := range response.Answer {
			_, _ = fmt.Fprintf(os.Stdout, "    %s\n", answer.String())
		}
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "  No answers\n")
	}
}

// printSummary prints query execution statistics.
func printSummary(cfg *config, stats queryStats) {
	if cfg.count <= 1 {
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, "\nSummary:\n")
	_, _ = fmt.Fprintf(os.Stdout, "  Total queries: %d\n", cfg.count)
	_, _ = fmt.Fprintf(os.Stdout, "  Successes: %d\n", stats.successes)
	_, _ = fmt.Fprintf(os.Stdout, "  Failures: %d\n", stats.failures)

	if stats.successes > 0 {
		avgRTT := stats.totalRTT / time.Duration(stats.successes)
		_, _ = fmt.Fprintf(os.Stdout, "  Average RTT: %v\n", avgRTT)
		qps := float64(stats.successes) / (stats.totalRTT.Seconds())
		_, _ = fmt.Fprintf(os.Stdout, "  Approximate QPS: %.0f\n", qps)
	}
}
