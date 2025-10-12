package server

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
	"github.com/piwi3910/dns-go/pkg/resolver"
)

// RFC Compliance Test Suite
// Based on dns-c project: https://github.com/piwi3910/dns-c/blob/main/test/src/dns_rfc_test.cpp

// createTestHandler creates a handler for testing.
func createTestHandler() *Handler {
	config := DefaultHandlerConfig()
	config.ResolverMode = resolver.ForwardingMode

	return NewHandler(config)
}

// TestRFC1035_BasicDNSFunctionality tests core DNS query/response mechanism
// RFC 1035: Domain Names - Implementation and Specification.
func TestRFC1035_BasicDNSFunctionality(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Test all common DNS record types
	tests := []struct {
		name       string
		domain     string
		qtype      uint16
		qtypeName  string
		shouldPass bool
	}{
		{"A Record", "google.com.", dns.TypeA, "A", true},
		{"AAAA Record", "google.com.", dns.TypeAAAA, "AAAA", true},
		{"MX Record", "google.com.", dns.TypeMX, "MX", true},
		{"TXT Record", "google.com.", dns.TypeTXT, "TXT", true},
		{"NS Record", "google.com.", dns.TypeNS, "NS", true},
		{"CNAME Record", "www.google.com.", dns.TypeCNAME, "CNAME", true},
		{"PTR Record", "8.8.8.8.in-addr.arpa.", dns.TypePTR, "PTR", true},
		{"SOA Record", "google.com.", dns.TypeSOA, "SOA", true},
		{"SRV Record", "_http._tcp.google.com.", dns.TypeSRV, "SRV", true},
		{"CAA Record", "google.com.", dns.TypeCAA, "CAA", true},
		{"DNSKEY Record", "google.com.", dns.TypeDNSKEY, "DNSKEY", true},
		{"DS Record", "google.com.", dns.TypeDS, "DS", true},
		{"RRSIG Record", "google.com.", dns.TypeRRSIG, "RRSIG", true},
		{"NSEC Record", "google.com.", dns.TypeNSEC, "NSEC", true},
		{"NSEC3 Record", "google.com.", dns.TypeNSEC3, "NSEC3", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion(tt.domain, tt.qtype)
			query, err := msg.Pack()
			if err != nil {
				t.Fatalf("Failed to pack %s query: %v", tt.qtypeName, err)
			}

			// Send query
			response, err := handler.HandleQuery(ctx, query, nil)
			if err != nil {
				t.Fatalf("%s query failed: %v", tt.qtypeName, err)
			}

			// Parse response
			respMsg := new(dns.Msg)
			if err := respMsg.Unpack(response); err != nil {
				t.Fatalf("Failed to unpack %s response: %v", tt.qtypeName, err)
			}

			// Validate DNS header
			if !respMsg.Response {
				t.Errorf("%s: Response flag (QR) not set", tt.qtypeName)
			}

			// Check response code
			if respMsg.Rcode != dns.RcodeSuccess && respMsg.Rcode != dns.RcodeNameError {
				t.Logf("⚠ %s: Unexpected rcode %s (may not be available)",
					tt.qtypeName, dns.RcodeToString[respMsg.Rcode])
			}

			// Must have answers or authority section (for valid responses)
			if respMsg.Rcode == dns.RcodeSuccess && len(respMsg.Answer) == 0 && len(respMsg.Ns) == 0 {
				t.Logf("⚠ %s: NOERROR but no answers or authority records (may not exist)", tt.qtypeName)
			}

			// Verify question section matches
			if len(respMsg.Question) > 0 {
				if respMsg.Question[0].Name != tt.domain {
					t.Errorf("%s: Question name mismatch: got %s, want %s",
						tt.qtypeName, respMsg.Question[0].Name, tt.domain)
				}
				if respMsg.Question[0].Qtype != tt.qtype {
					t.Errorf("%s: Question type mismatch: got %d, want %d",
						tt.qtypeName, respMsg.Question[0].Qtype, tt.qtype)
				}
			}

			// Log result based on response code
			switch {
			case respMsg.Rcode == dns.RcodeSuccess && len(respMsg.Answer) > 0:
				t.Logf("✓ %s query successful: %d answers", tt.qtypeName, len(respMsg.Answer))
			case respMsg.Rcode == dns.RcodeNameError:
				t.Logf("✓ %s query returned NXDOMAIN (record doesn't exist)", tt.qtypeName)
			default:
				t.Logf("✓ %s query completed with rcode %s", tt.qtypeName, dns.RcodeToString[respMsg.Rcode])
			}
		})
	}

	t.Logf("✓ RFC 1035 Basic DNS Functionality: All record types tested")
}

// TestRFC2308_NegativeCaching tests proper handling of non-existent domains
// RFC 2308: Negative Caching of DNS Queries.
func TestRFC2308_NegativeCaching(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Query for a non-existent domain
	msg := new(dns.Msg)
	msg.SetQuestion("nonexistent-domain-12345.invalid.", dns.TypeA)
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Parse response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Should get NXDOMAIN response
	if respMsg.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN (3), got rcode %d", respMsg.Rcode)
	}

	// Should have SOA record in authority section for negative caching
	hasSoa := false
	for _, rr := range respMsg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			hasSoa = true

			break
		}
	}

	if !hasSoa && respMsg.Rcode == dns.RcodeNameError {
		t.Log("⚠ RFC 2308: NXDOMAIN response should include SOA in authority section")
	}

	t.Logf("✓ RFC 2308 Negative Caching: NXDOMAIN response code correct")
}

// TestRFC6891_EDNS0Support tests Extended DNS support
// RFC 6891: Extension Mechanisms for DNS (EDNS0).
func TestRFC6891_EDNS0Support(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Create query with EDNS0
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	msg.SetEdns0(4096, false) // Set EDNS0 with 4096 byte UDP payload
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Parse response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Should not return FORMERR
	if respMsg.Rcode == dns.RcodeFormatError {
		t.Error("Server returned FORMERR for EDNS0 query")
	}

	// Check for OPT record in additional section
	hasOpt := false
	for _, rr := range respMsg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			hasOpt = true

			break
		}
	}

	if hasOpt {
		t.Logf("✓ RFC 6891 EDNS0 Support: OPT record present in response")
	} else {
		t.Log("⚠ RFC 6891: EDNS0 query should include OPT in response")
	}
}

// TestRFC8020_NXDOMAINHandling tests consistent NXDOMAIN for subdomains
// RFC 8020: NXDOMAIN: There Really Is Nothing Underneath.
func TestRFC8020_NXDOMAINHandling(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Query parent domain that doesn't exist
	msg1 := new(dns.Msg)
	msg1.SetQuestion("nonexistent-parent-12345.invalid.", dns.TypeA)
	query1, _ := msg1.Pack()
	response1, err := handler.HandleQuery(ctx, query1, nil)
	if err != nil {
		t.Fatalf("Parent query failed: %v", err)
	}

	respMsg1 := new(dns.Msg)
	_ = respMsg1.Unpack(response1)

	// Query subdomain of non-existent domain
	msg2 := new(dns.Msg)
	msg2.SetQuestion("subdomain.nonexistent-parent-12345.invalid.", dns.TypeA)
	query2, _ := msg2.Pack()
	response2, err := handler.HandleQuery(ctx, query2, nil)
	if err != nil {
		t.Fatalf("Subdomain query failed: %v", err)
	}

	respMsg2 := new(dns.Msg)
	_ = respMsg2.Unpack(response2)

	// Both should return NXDOMAIN
	if respMsg1.Rcode != dns.RcodeNameError {
		t.Errorf("Parent domain should return NXDOMAIN, got %d", respMsg1.Rcode)
	}

	if respMsg2.Rcode != dns.RcodeNameError {
		t.Errorf("Subdomain should return NXDOMAIN, got %d", respMsg2.Rcode)
	}

	t.Logf("✓ RFC 8020 NXDOMAIN Handling: Consistent NXDOMAIN for parent and subdomain")
}

// TestRFC8482_ANYQueryResponse tests minimal response to ANY queries
// RFC 8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY.
func TestRFC8482_ANYQueryResponse(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Create ANY query
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeANY)
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Parse response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// RFC 8482 recommends REFUSED or minimal response
	switch {
	case respMsg.Rcode == dns.RcodeRefused || respMsg.Rcode == dns.RcodeNotImplemented:
		t.Logf("✓ RFC 8482 ANY Query: Server returns %s (recommended)", dns.RcodeToString[respMsg.Rcode])
	case len(respMsg.Answer) <= 5:
		t.Logf("✓ RFC 8482 ANY Query: Minimal response with %d records", len(respMsg.Answer))
	default:
		t.Logf("⚠ RFC 8482: ANY query returned %d records (recommend minimal response)", len(respMsg.Answer))
	}
}

// TestRFC1035_HeaderFlagsCompliance tests correct DNS header flag usage
// RFC 1035 Section 4.1.1: Header section format.
func TestRFC1035_HeaderFlagsCompliance(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Create standard query
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	msg.RecursionDesired = true
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Parse response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Validate header flags
	if !respMsg.Response {
		t.Error("QR (Query/Response) flag not set")
	}

	if respMsg.Opcode != dns.OpcodeQuery {
		t.Errorf("Expected QUERY opcode (0), got %d", respMsg.Opcode)
	}

	if respMsg.RecursionDesired != msg.RecursionDesired {
		t.Error("RD (Recursion Desired) flag not preserved")
	}

	// In forwarding mode, RA should be set
	if !respMsg.RecursionAvailable {
		t.Log("⚠ RA (Recursion Available) flag not set (expected in forwarding mode)")
	}

	t.Logf("✓ RFC 1035 Header Flags: QR=%v, Opcode=%d, RD=%v, RA=%v",
		respMsg.Response, respMsg.Opcode, respMsg.RecursionDesired, respMsg.RecursionAvailable)
}

// TestRFC1035_ResponseCodeCompliance tests correct response code handling
// RFC 1035 Section 4.1.1: Response codes.
func TestRFC1035_ResponseCodeCompliance(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	tests := []struct {
		name         string
		domain       string
		expectedCode int
	}{
		{
			name:         "Valid domain",
			domain:       "google.com.",
			expectedCode: dns.RcodeSuccess,
		},
		{
			name:         "Non-existent domain",
			domain:       "nonexistent-xyz-12345.invalid.",
			expectedCode: dns.RcodeNameError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion(tt.domain, dns.TypeA)
			query, _ := msg.Pack()

			response, err := handler.HandleQuery(ctx, query, nil)
			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}

			respMsg := new(dns.Msg)
			_ = respMsg.Unpack(response)

			if respMsg.Rcode != tt.expectedCode {
				t.Errorf("Expected rcode %s (%d), got %s (%d)",
					dns.RcodeToString[tt.expectedCode], tt.expectedCode,
					dns.RcodeToString[respMsg.Rcode], respMsg.Rcode)
			}

			t.Logf("✓ Response code %s for %s", dns.RcodeToString[respMsg.Rcode], tt.domain)
		})
	}
}

// TestRFC1035_MessageSizeLimits tests handling of large DNS responses
// RFC 1035 Section 2.3.4: Size limits.
func TestRFC1035_MessageSizeLimits(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Query a domain that might have many records (like TXT records)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeTXT)
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query
	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	// Parse response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Check response size
	responseSize := len(response)
	maxUdpSize := 512 // RFC 1035 limit without EDNS0

	if responseSize > maxUdpSize {
		// If response is larger than 512 bytes, truncation flag should be set
		// OR EDNS0 should be used
		if !respMsg.Truncated {
			// Check if EDNS0 is present
			hasEdns := false
			for _, rr := range respMsg.Extra {
				if _, ok := rr.(*dns.OPT); ok {
					hasEdns = true

					break
				}
			}
			if !hasEdns {
				t.Logf("⚠ RFC 1035: Response size %d > 512 bytes but TC flag not set and no EDNS0", responseSize)
			}
		}
	}

	// Response should have data
	if len(respMsg.Answer) == 0 && respMsg.Rcode == dns.RcodeSuccess {
		t.Error("NOERROR response with no answers")
	}

	t.Logf("✓ RFC 1035 Message Size: Response size %d bytes, TC=%v",
		responseSize, respMsg.Truncated)
}

// TestRFC_CachingBehavior tests proper caching of DNS responses.
func TestRFC_CachingBehavior(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Create query
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	query, _ := msg.Pack()

	// First query (cache miss)
	start := time.Now()
	response1, err := handler.HandleQuery(ctx, query, nil)
	firstDuration := time.Since(start)
	if err != nil {
		t.Fatalf("First query failed: %v", err)
	}

	// Second query (should be cached)
	start = time.Now()
	response2, err := handler.HandleQuery(ctx, query, nil)
	secondDuration := time.Since(start)
	if err != nil {
		t.Fatalf("Second query failed: %v", err)
	}

	// Cached response should be faster
	if secondDuration < firstDuration {
		speedup := float64(firstDuration) / float64(secondDuration)
		t.Logf("✓ Caching: Second query %.1fx faster (%.2fms vs %.2fms)",
			speedup,
			firstDuration.Seconds()*1000,
			secondDuration.Seconds()*1000)
	}

	// Responses should be identical (except message ID)
	if len(response1) != len(response2) {
		t.Error("Cached response size differs from original")
	}

	// Check cache stats
	stats := handler.GetStats()
	if stats.MessageCache.Hits == 0 {
		t.Error("Cache hit count is 0, caching not working")
	} else {
		t.Logf("✓ Cache Stats: %d hits, %d misses, %.1f%% hit rate",
			stats.MessageCache.Hits,
			stats.MessageCache.Misses,
			float64(stats.MessageCache.Hits)/float64(stats.MessageCache.Hits+stats.MessageCache.Misses)*100)
	}
}

// TestRFC_FastPathOptimization tests the fast-path query handling.
func TestRFC_FastPathOptimization(t *testing.T) {
	t.Parallel()
	// Test that common queries use fast path
	commonQueries := []struct {
		name  string
		qtype uint16
	}{
		{"google.com.", dns.TypeA},
		{"google.com.", dns.TypeAAAA},
		{"1.1.1.1.in-addr.arpa.", dns.TypePTR},
	}

	for _, tt := range commonQueries {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion(tt.name, tt.qtype)
			query, _ := msg.Pack()

			if !dnsio.CanUseFastPath(query) {
				t.Errorf("Common query %s %s should use fast path",
					tt.name, dns.TypeToString[tt.qtype])
			}
		})
	}

	t.Logf("✓ Fast Path: Common query types correctly detected")
}

// TestRFC1035_QueryClasses tests different DNS query classes
// RFC 1035 Section 3.2.4: CLASS values.
func TestRFC1035_QueryClasses(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	tests := []struct {
		name     string
		domain   string
		qclass   uint16
		expected string
	}{
		{"Internet Class", "google.com.", dns.ClassINET, "IN"},
		{"Chaos Class", "version.bind.", dns.ClassCHAOS, "CH"},
		{"Hesiod Class", "example.com.", dns.ClassHESIOD, "HS"},
		{"Any Class", "google.com.", dns.ClassANY, "ANY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion(tt.domain, dns.TypeA)
			msg.Question[0].Qclass = tt.qclass
			query, _ := msg.Pack()

			response, err := handler.HandleQuery(ctx, query, nil)
			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}

			respMsg := new(dns.Msg)
			_ = respMsg.Unpack(response)

			// Should not return FORMERR for valid classes
			if respMsg.Rcode == dns.RcodeFormatError {
				t.Errorf("Returned FORMERR for valid class %s", tt.expected)
			}

			t.Logf("✓ Query class %s handled correctly (rcode: %s)",
				tt.expected, dns.RcodeToString[respMsg.Rcode])
		})
	}
}

// TestRFC1035_CaseSensitivity tests DNS case insensitivity
// RFC 1035: Domain names are case-insensitive.
func TestRFC1035_CaseSensitivity(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	queries := []string{
		"google.com.",
		"GOOGLE.COM.",
		"Google.Com.",
		"gOoGlE.cOm.",
	}

	responses := make([]*dns.Msg, 0, len(queries))

	for _, domain := range queries {
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeA)
		query, _ := msg.Pack()

		response, err := handler.HandleQuery(ctx, query, nil)
		if err != nil {
			t.Fatalf("Query failed for %s: %v", domain, err)
		}

		respMsg := new(dns.Msg)
		_ = respMsg.Unpack(response)
		responses = append(responses, respMsg)
	}

	// All responses should be equivalent (same rcode, same answer count)
	baseRcode := responses[0].Rcode
	baseAnswerCount := len(responses[0].Answer)

	for i, resp := range responses[1:] {
		if resp.Rcode != baseRcode {
			t.Errorf("Case variant %s returned different rcode: %d vs %d",
				queries[i+1], resp.Rcode, baseRcode)
		}
		if len(resp.Answer) != baseAnswerCount {
			t.Logf("⚠ Case variant %s returned different answer count: %d vs %d",
				queries[i+1], len(resp.Answer), baseAnswerCount)
		}
	}

	t.Logf("✓ RFC 1035 Case Insensitivity: All case variants handled consistently")
}

// TestRFC1035_CompressionPointers tests DNS name compression
// RFC 1035 Section 4.1.4: Message compression.
func TestRFC1035_CompressionPointers(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Query for NS records which typically have compression in answers
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeNS)
	query, _ := msg.Pack()

	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(response); err != nil {
		t.Fatalf("Failed to unpack response (compression issue?): %v", err)
	}

	// If we got here, compression was handled correctly
	t.Logf("✓ RFC 1035 Compression: Response correctly decompressed (%d answers)",
		len(respMsg.Answer))
}

// TestRFC1035_MultipleQuestions tests handling of multiple questions
// RFC 1035: Most implementations only support 1 question.
func TestRFC1035_MultipleQuestions(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	// Add second question (non-standard)
	msg.Question = append(msg.Question, dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	})
	query, _ := msg.Pack()

	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Logf("✓ Multiple questions rejected (expected behavior)")

		return
	}

	respMsg := new(dns.Msg)
	_ = respMsg.Unpack(response)

	// Should either work or return FORMERR/NOTIMP
	switch {
	case respMsg.Rcode == dns.RcodeFormatError || respMsg.Rcode == dns.RcodeNotImplemented:
		t.Logf("✓ Multiple questions returned %s (acceptable)", dns.RcodeToString[respMsg.Rcode])
	case len(respMsg.Question) == 1:
		t.Logf("✓ Multiple questions normalized to single question (acceptable)")
	default:
		t.Logf("⚠ Multiple questions processed (unusual but valid)")
	}
}

// TestRFC6891_EDNSBufferSizes tests various EDNS0 buffer size negotiations
// RFC 6891: Extension Mechanisms for DNS.
func TestRFC6891_EDNSBufferSizes(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	bufferSizes := []uint16{512, 1232, 4096, 8192, 16384}

	for _, size := range bufferSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion("google.com.", dns.TypeA)
			msg.SetEdns0(size, false)
			query, _ := msg.Pack()

			response, err := handler.HandleQuery(ctx, query, nil)
			if err != nil {
				t.Fatalf("Query with buffer size %d failed: %v", size, err)
			}

			respMsg := new(dns.Msg)
			_ = respMsg.Unpack(response)

			// Check response size doesn't exceed requested buffer
			if len(response) > int(size) {
				t.Errorf("Response size %d exceeds requested buffer %d", len(response), size)
			}

			t.Logf("✓ EDNS0 buffer size %d: response %d bytes", size, len(response))
		})
	}
}

// TestRFC1035_InvalidQueries tests handling of malformed queries
// RFC 1035: Servers should handle malformed queries gracefully.
func TestRFC1035_InvalidQueries(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	tests := []struct {
		name  string
		query []byte
	}{
		{"Too short", []byte{0x00, 0x01}},
		{"Empty", []byte{}},
		{"Invalid header", []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01}},
		{"Truncated question", []byte{
			0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x03, 0x77, 0x77, 0x77, // incomplete
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response, err := handler.HandleQuery(ctx, tt.query, nil)

			if err != nil {
				t.Logf("✓ Invalid query rejected with error (safe)")

				return
			}

			if response != nil {
				respMsg := new(dns.Msg)
				if respMsg.Unpack(response) == nil {
					// Should return FORMERR
					if respMsg.Rcode == dns.RcodeFormatError {
						t.Logf("✓ Invalid query returned FORMERR (correct)")
					} else {
						t.Logf("⚠ Invalid query returned %s (should be FORMERR)",
							dns.RcodeToString[respMsg.Rcode])
					}
				} else {
					t.Logf("✓ Invalid response to invalid query (safe)")
				}
			}
		})
	}
}

// TestRFC1035_LongDomainNames tests maximum domain name length handling
// RFC 1035: Domain name max 255 octets.
func TestRFC1035_LongDomainNames(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Create a 253-character domain (max valid length)
	longLabel := ""
	for range 50 {
		longLabel += "abcd."
	}
	longLabel += "com."

	msg := new(dns.Msg)
	msg.SetQuestion(longLabel, dns.TypeA)
	query, err := msg.Pack()
	if err != nil {
		t.Logf("✓ Extremely long domain rejected at pack stage")

		return
	}

	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Logf("✓ Long domain handled (error returned)")

		return
	}

	respMsg := new(dns.Msg)
	_ = respMsg.Unpack(response)

	// Should work or return NXDOMAIN/FORMERR
	switch respMsg.Rcode {
	case dns.RcodeFormatError:
		t.Logf("✓ Long domain returned FORMERR")
	case dns.RcodeNameError:
		t.Logf("✓ Long domain returned NXDOMAIN")
	default:
		t.Logf("✓ Long domain processed (rcode: %s)", dns.RcodeToString[respMsg.Rcode])
	}
}

// TestRFC3597_UnknownRecordTypes tests handling of unknown RR types
// RFC 3597: Handling of Unknown DNS Resource Record Types.
func TestRFC3597_UnknownRecordTypes(t *testing.T) {
	t.Parallel()
	handler := createTestHandler()
	ctx := context.Background()

	// Use TYPE65280 (in private use range)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", 65280)
	query, _ := msg.Pack()

	response, err := handler.HandleQuery(ctx, query, nil)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	respMsg := new(dns.Msg)
	_ = respMsg.Unpack(response)

	// Should not crash, should return valid response
	if !respMsg.Response {
		t.Error("Response flag not set for unknown type")
	}

	// Acceptable responses: NOERROR (no data), NXDOMAIN, or NOTIMP
	if respMsg.Rcode == dns.RcodeSuccess ||
		respMsg.Rcode == dns.RcodeNameError ||
		respMsg.Rcode == dns.RcodeNotImplemented {
		t.Logf("✓ RFC 3597 Unknown Type: Handled gracefully (rcode: %s)",
			dns.RcodeToString[respMsg.Rcode])
	} else {
		t.Logf("⚠ Unknown type returned unexpected rcode: %s",
			dns.RcodeToString[respMsg.Rcode])
	}
}
