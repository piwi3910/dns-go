package cache_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/piwi3910/dns-go/pkg/cache"
)

const testExampleDomain = "example.com."

func TestNegativeCacheEntry_IsExpired(t *testing.T) {
	t.Parallel()
	entry := &cache.NegativeCacheEntry{
		Type:     cache.NegativeNXDOMAIN,
		Expiry:   time.Now().Add(-1 * time.Second), // Expired 1 second ago
		TTL:      0,
		HitCount: atomic.Int64{},
		SOA:      nil,
	}

	if !entry.IsExpired() {
		t.Error("Expected entry to be expired")
	}

	entry.Expiry = time.Now().Add(10 * time.Second)
	if entry.IsExpired() {
		t.Error("Expected entry to not be expired")
	}
}

func TestNegativeCacheEntry_IncrementHitCount(t *testing.T) {
	t.Parallel()
	entry := &cache.NegativeCacheEntry{
		Type:     cache.NegativeNXDOMAIN,
		Expiry:   time.Time{},
		TTL:      0,
		HitCount: atomic.Int64{},
		SOA:      nil,
	}

	entry.IncrementHitCount()
	if entry.HitCount.Load() != 1 {
		t.Errorf("Expected hit count 1, got %d", entry.HitCount.Load())
	}

	entry.IncrementHitCount()
	if entry.HitCount.Load() != 2 {
		t.Errorf("Expected hit count 2, got %d", entry.HitCount.Load())
	}
}

func TestNegativeCache_SetAndGet(t *testing.T) {
	t.Parallel()
	config := cache.DefaultNegativeCacheConfig()
	nc := cache.NewNegativeCache(config)

	// Create SOA
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:     testExampleDomain,
			Rrtype:   dns.TypeSOA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300, // 5 minutes
	}

	key := cache.MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store negative response
	nc.Set(key, cache.NegativeNXDOMAIN, soa)

	// Retrieve it
	entry := nc.Get(key)
	if entry == nil {
		t.Fatal("Expected to retrieve cached negative response")
	}

	if entry.Type != cache.NegativeNXDOMAIN {
		t.Errorf("Expected type NXDOMAIN, got %v", entry.Type)
	}

	if entry.SOA.Hdr.Name != testExampleDomain {
		t.Errorf("Expected SOA for %s, got %s", testExampleDomain, entry.SOA.Hdr.Name)
	}
}

func TestNegativeCache_GetExpired(t *testing.T) {
	t.Parallel()
	config := cache.DefaultNegativeCacheConfig()
	config.MinTTL = 1 * time.Millisecond
	config.MaxTTL = 1 * time.Millisecond
	nc := cache.NewNegativeCache(config)

	key := cache.MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store negative response with very short TTL
	nc.Set(key, cache.NegativeNXDOMAIN, nil)

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	// Should return nil (lazy eviction)
	entry := nc.Get(key)
	if entry != nil {
		t.Error("Expected expired entry to return nil")
	}
}

func TestNegativeCache_Disabled(t *testing.T) {
	t.Parallel()
	config := cache.DefaultNegativeCacheConfig()
	config.Enable = false
	nc := cache.NewNegativeCache(config)

	key := cache.MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Try to store
	nc.Set(key, cache.NegativeNXDOMAIN, nil)

	// Should return nil (caching disabled)
	entry := nc.Get(key)
	if entry != nil {
		t.Error("Expected disabled cache to return nil")
	}
}

// Note: calculateNegativeTTL is an unexported method and cannot be tested directly
// through the public API. TTL calculation is tested indirectly through Set/Get tests.

func TestExtractSOA(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}

	// No SOA
	soa := cache.ExtractSOA(msg)
	if soa != nil {
		t.Error("Expected nil SOA when none present")
	}

	// SOA in authority section
	soaRecord := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:     testExampleDomain,
			Rrtype:   dns.TypeSOA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  0,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	msg.Ns = append(msg.Ns, soaRecord)

	soa = cache.ExtractSOA(msg)
	if soa == nil {
		t.Fatal("Expected to extract SOA")
	}
	if soa.Hdr.Name != testExampleDomain {
		t.Errorf("Expected SOA for %s, got %s", testExampleDomain, soa.Hdr.Name)
	}
}

func TestIsNegativeResponse_Negative(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		rcode          int
		expectedType   cache.NegativeType
		expectedIsNeg  bool
		errorMsg       string
	}{
		{
			name:          "NXDOMAIN",
			rcode:         dns.RcodeNameError,
			expectedType:  cache.NegativeNXDOMAIN,
			expectedIsNeg: true,
			errorMsg:      "Expected NXDOMAIN to be negative response",
		},
		{
			name:          "NODATA",
			rcode:         dns.RcodeSuccess,
			expectedType:  cache.NegativeNODATA,
			expectedIsNeg: true,
			errorMsg:      "Expected NODATA to be negative response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := createTestDNSMessage(tt.rcode)
			soa := createTestSOA()
			msg.Ns = append(msg.Ns, soa)

			isNeg, negType, extractedSOA := cache.IsNegativeResponse(msg)
			if isNeg != tt.expectedIsNeg {
				t.Error(tt.errorMsg)
			}
			if negType != tt.expectedType {
				t.Errorf("Expected %v type, got %v", tt.expectedType, negType)
			}
			if extractedSOA == nil {
				t.Error("Expected SOA to be extracted")
			}
		})
	}
}

// createTestDNSMessage creates a test DNS message with the specified rcode.
func createTestDNSMessage(rcode int) *dns.Msg {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	msg.Response = true
	msg.Rcode = rcode

	return msg
}

// createTestSOA creates a test SOA record.
func createTestSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:     testExampleDomain,
			Rrtype:   dns.TypeSOA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		Ns:      "",
		Mbox:    "",
		Serial:  0,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
}

func TestIsNegativeResponse_NotNegative(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess

	// Add answer
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:     testExampleDomain,
			Rrtype:   dns.TypeA,
			Class:    dns.ClassINET,
			Ttl:      300,
			Rdlength: 0,
		},
		A: []byte{192, 0, 2, 1},
	}
	msg.Answer = append(msg.Answer, a)

	isNeg, _, _ := cache.IsNegativeResponse(msg)
	if isNeg {
		t.Error("Expected positive response to not be negative")
	}
}

func TestIsNegativeResponse_NotResponse(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	msg.Response = false
	msg.Rcode = dns.RcodeNameError

	isNeg, _, _ := cache.IsNegativeResponse(msg)
	if isNeg {
		t.Error("Expected query to not be negative response")
	}
}

func TestCreateNegativeResponse_NXDOMAIN(t *testing.T) {
	t.Parallel()
	query := createTestDNSMessage(0)
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)

	soa := createTestSOA()
	soa.Ns = "ns1.example.com."
	soa.Mbox = "admin.example.com."

	response := cache.CreateNegativeResponse(query, cache.NegativeNXDOMAIN, soa)

	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected RCODE NXDOMAIN, got %d", response.Rcode)
	}

	validateNegativeResponse(t, response, testExampleDomain)
}

// validateNegativeResponse validates common properties of negative responses.
func validateNegativeResponse(t *testing.T, response *dns.Msg, expectedSOAName string) {
	t.Helper()

	if len(response.Answer) != 0 {
		t.Error("Expected empty answer section")
	}

	if len(response.Ns) != 1 {
		t.Fatalf("Expected 1 SOA in authority section, got %d", len(response.Ns))
	}

	responseSOA, ok := response.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatal("Expected SOA in authority section")
	}
	if responseSOA.Hdr.Name != expectedSOAName {
		t.Errorf("Expected SOA for %s, got %s", expectedSOAName, responseSOA.Hdr.Name)
	}
}

func TestCreateNegativeResponse_NODATA(t *testing.T) {
	t.Parallel()
	query := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	query.SetQuestion(testExampleDomain, dns.TypeAAAA)

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:     testExampleDomain,
			Rrtype:   dns.TypeSOA,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 0,
		},
		Ns:      "",
		Mbox:    "",
		Serial:  0,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}

	response := cache.CreateNegativeResponse(query, cache.NegativeNODATA, soa)

	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RCODE SUCCESS, got %d", response.Rcode)
	}

	if len(response.Answer) != 0 {
		t.Error("Expected empty answer section")
	}

	if len(response.Ns) != 1 {
		t.Errorf("Expected 1 SOA in authority section, got %d", len(response.Ns))
	}
}

func TestNegativeCache_Stats(t *testing.T) {
	t.Parallel()
	nc := cache.NewNegativeCache(cache.DefaultNegativeCacheConfig())

	key := cache.MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Initial stats
	stats := nc.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Expected initial stats to be zero")
	}

	// Miss
	nc.Get(key)
	stats = nc.GetStats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}

	// Store and hit
	nc.Set(key, cache.NegativeNXDOMAIN, nil)
	nc.Get(key)
	stats = nc.GetStats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}

	// Hit rate
	if stats.HitRate != 0.5 {
		t.Errorf("Expected hit rate 0.5, got %f", stats.HitRate)
	}
}

func TestNegativeCache_Delete(t *testing.T) {
	t.Parallel()
	nc := cache.NewNegativeCache(cache.DefaultNegativeCacheConfig())

	key := cache.MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store
	nc.Set(key, cache.NegativeNXDOMAIN, nil)

	// Verify it's there
	if nc.Get(key) == nil {
		t.Fatal("Expected entry to be cached")
	}

	// Delete
	nc.Delete(key)

	// Verify it's gone
	if nc.Get(key) != nil {
		t.Error("Expected entry to be deleted")
	}
}

// TestNegativeCache_Sharding tests that cache works with multiple shards.
// Note: shards field is unexported so we can't directly test shard count.
func TestNegativeCache_Sharding(t *testing.T) {
	t.Parallel()
	config := cache.DefaultNegativeCacheConfig()
	config.NumShards = 4
	nc := cache.NewNegativeCache(config)

	// Store entries and verify they can be retrieved
	keys := []string{
		cache.MakeKey("domain1.com.", dns.TypeA, dns.ClassINET),
		cache.MakeKey("domain2.com.", dns.TypeA, dns.ClassINET),
		cache.MakeKey("domain3.com.", dns.TypeA, dns.ClassINET),
		cache.MakeKey("domain4.com.", dns.TypeA, dns.ClassINET),
	}

	for _, key := range keys {
		nc.Set(key, cache.NegativeNXDOMAIN, nil)
	}

	// Verify retrieval
	for _, key := range keys {
		if nc.Get(key) == nil {
			t.Errorf("Failed to retrieve key %s", key)
		}
	}
}
