package io

import (
	"testing"

	"github.com/miekg/dns"
)

// BenchmarkCanUseFastPath tests zero-allocation fast path detection
// Target: <50ns per call, 0 allocs/op.
func BenchmarkCanUseFastPath(b *testing.B) {
	// Create a typical A record query
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	query, _ := msg.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = CanUseFastPath(query)
	}
}

// BenchmarkCanUseFastPathParallel tests concurrent fast path detection.
func BenchmarkCanUseFastPathParallel(b *testing.B) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	query, _ := msg.Pack()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = CanUseFastPath(query)
		}
	})
}

// TestCanUseFastPath_CommonQueries tests fast path detection for common queries.
func TestCanUseFastPath_CommonQueries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		qtype    uint16
		expected bool
	}{
		{"A record", dns.TypeA, true},
		{"AAAA record", dns.TypeAAAA, true},
		{"PTR record", dns.TypePTR, true},
		{"MX record", dns.TypeMX, true},
		{"TXT record", dns.TypeTXT, true},
		{"CNAME record", dns.TypeCNAME, true},
		{"NS record", dns.TypeNS, true},
		{"SOA record", dns.TypeSOA, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion("example.com.", tt.qtype)
			query, err := msg.Pack()
			if err != nil {
				t.Fatalf("Failed to pack message: %v", err)
			}

			result := CanUseFastPath(query)
			if result != tt.expected {
				t.Errorf("CanUseFastPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestCanUseFastPath_UncommonQueries tests queries that should use slow path.
func TestCanUseFastPath_UncommonQueries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		qtype uint16
	}{
		{"AXFR (zone transfer)", dns.TypeAXFR},
		{"IXFR (incremental zone transfer)", dns.TypeIXFR},
		{"ANY", dns.TypeANY},
		{"DNSKEY", dns.TypeDNSKEY},
		{"RRSIG", dns.TypeRRSIG},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := new(dns.Msg)
			msg.SetQuestion("example.com.", tt.qtype)
			query, err := msg.Pack()
			if err != nil {
				t.Fatalf("Failed to pack message: %v", err)
			}

			result := CanUseFastPath(query)
			if result != false {
				t.Errorf("CanUseFastPath() = %v, want false for uncommon query type", result)
			}
		})
	}
}

// TestCanUseFastPath_EDNS0 tests that EDNS0 queries use fast path when DO bit is not set.
func TestCanUseFastPath_EDNS0(t *testing.T) {
	t.Parallel()
	// EDNS0 without DO bit should use fast path
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.SetEdns0(4096, false) // DO bit = false

	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	result := CanUseFastPath(query)
	if result != true {
		t.Error("EDNS0 query without DO bit should use fast path")
	}

	// EDNS0 with DO bit should NOT use fast path (requires DNSSEC validation)
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)
	msg2.SetEdns0(4096, true) // DO bit = true

	query2, err := msg2.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	result2 := CanUseFastPath(query2)
	if result2 != false {
		t.Error("EDNS0 query with DO bit should not use fast path (requires DNSSEC)")
	}
}

// TestCanUseFastPath_MultipleQuestions tests that queries with multiple questions go to slow path.
func TestCanUseFastPath_MultipleQuestions(t *testing.T) {
	t.Parallel()
	msg := new(dns.Msg)
	msg.Question = []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	result := CanUseFastPath(query)
	if result != false {
		t.Error("Query with multiple questions should not use fast path")
	}
}

// TestCanUseFastPath_Response tests that responses are rejected.
func TestCanUseFastPath_Response(t *testing.T) {
	t.Parallel()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true // Mark as response

	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	result := CanUseFastPath(query)
	if result != false {
		t.Error("DNS response should not use fast path")
	}
}

// TestCanUseFastPath_InvalidQuery tests handling of malformed queries.
func TestCanUseFastPath_InvalidQuery(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query []byte
	}{
		{"Empty query", []byte{}},
		{"Too short", []byte{0, 1, 2, 3}},
		{"Truncated header", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := CanUseFastPath(tt.query)
			if result != false {
				t.Error("Invalid query should not use fast path")
			}
		})
	}
}

// TestParseFastPathQuery tests query parsing.
func TestParseFastPathQuery(t *testing.T) {
	t.Parallel()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	fpq, err := ParseFastPathQuery(query)
	if err != nil {
		t.Fatalf("ParseFastPathQuery failed: %v", err)
	}

	if fpq.Name != "example.com." {
		t.Errorf("Name = %v, want example.com.", fpq.Name)
	}
	if fpq.Type != dns.TypeA {
		t.Errorf("Type = %v, want %v", fpq.Type, dns.TypeA)
	}
	if fpq.Class != dns.ClassINET {
		t.Errorf("Class = %v, want %v", fpq.Class, dns.ClassINET)
	}
}
