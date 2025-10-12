package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testExampleDomain = "example.com."

func TestNegativeCacheEntry_IsExpired(t *testing.T) {
	t.Parallel()
	entry := &NegativeCacheEntry{
		Type:   NegativeNXDOMAIN,
		Expiry: time.Now().Add(-1 * time.Second), // Expired 1 second ago
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
	entry := &NegativeCacheEntry{
		Type: NegativeNXDOMAIN,
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
	config := DefaultNegativeCacheConfig()
	nc := NewNegativeCache(config)

	// Create SOA
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300, // 5 minutes
	}

	key := MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store negative response
	nc.Set(key, NegativeNXDOMAIN, soa)

	// Retrieve it
	entry := nc.Get(key)
	if entry == nil {
		t.Fatal("Expected to retrieve cached negative response")
	}

	if entry.Type != NegativeNXDOMAIN {
		t.Errorf("Expected type NXDOMAIN, got %v", entry.Type)
	}

	if entry.SOA.Hdr.Name != testExampleDomain {
		t.Errorf("Expected SOA for %s, got %s", testExampleDomain, entry.SOA.Hdr.Name)
	}
}

func TestNegativeCache_GetExpired(t *testing.T) {
	t.Parallel()
	config := DefaultNegativeCacheConfig()
	config.MinTTL = 1 * time.Millisecond
	config.MaxTTL = 1 * time.Millisecond
	nc := NewNegativeCache(config)

	key := MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store negative response with very short TTL
	nc.Set(key, NegativeNXDOMAIN, nil)

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
	config := DefaultNegativeCacheConfig()
	config.Enable = false
	nc := NewNegativeCache(config)

	key := MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Try to store
	nc.Set(key, NegativeNXDOMAIN, nil)

	// Should return nil (caching disabled)
	entry := nc.Get(key)
	if entry != nil {
		t.Error("Expected disabled cache to return nil")
	}
}

func TestCalculateNegativeTTL_WithSOA(t *testing.T) {
	t.Parallel()
	nc := NewNegativeCache(DefaultNegativeCacheConfig())

	tests := []struct {
		name     string
		soaTTL   uint32
		soaMin   uint32
		expected time.Duration
	}{
		{
			name:     "SOA TTL smaller",
			soaTTL:   300,
			soaMin:   600,
			expected: 300 * time.Second,
		},
		{
			name:     "SOA minimum smaller",
			soaTTL:   600,
			soaMin:   300,
			expected: 300 * time.Second,
		},
		{
			name:     "Equal",
			soaTTL:   300,
			soaMin:   300,
			expected: 300 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			soa := &dns.SOA{
				Hdr: dns.RR_Header{
					Ttl: tt.soaTTL,
				},
				Minttl: tt.soaMin,
			}

			result := nc.calculateNegativeTTL(soa)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCalculateNegativeTTL_Bounds(t *testing.T) {
	t.Parallel()
	config := DefaultNegativeCacheConfig()
	config.MinTTL = 5 * time.Minute
	config.MaxTTL = 1 * time.Hour
	nc := NewNegativeCache(config)

	// TTL below minimum
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Ttl: 60},
		Minttl: 60,
	}
	ttl := nc.calculateNegativeTTL(soa)
	if ttl != config.MinTTL {
		t.Errorf("Expected TTL to be clamped to MinTTL %v, got %v", config.MinTTL, ttl)
	}

	// TTL above maximum
	soa.Hdr.Ttl = 7200
	soa.Minttl = 7200
	ttl = nc.calculateNegativeTTL(soa)
	if ttl != config.MaxTTL {
		t.Errorf("Expected TTL to be clamped to MaxTTL %v, got %v", config.MaxTTL, ttl)
	}
}

func TestCalculateNegativeTTL_NoSOA(t *testing.T) {
	t.Parallel()
	config := DefaultNegativeCacheConfig()
	config.DefaultTTL = 10 * time.Minute
	nc := NewNegativeCache(config)

	ttl := nc.calculateNegativeTTL(nil)
	if ttl != config.DefaultTTL {
		t.Errorf("Expected default TTL %v, got %v", config.DefaultTTL, ttl)
	}
}

func TestExtractSOA(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{}

	// No SOA
	soa := ExtractSOA(msg)
	if soa != nil {
		t.Error("Expected nil SOA when none present")
	}

	// SOA in authority section
	soaRecord := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:   "ns1.example.com.",
		Mbox: "admin.example.com.",
	}
	msg.Ns = append(msg.Ns, soaRecord)

	soa = ExtractSOA(msg)
	if soa == nil {
		t.Fatal("Expected to extract SOA")
	}
	if soa.Hdr.Name != testExampleDomain {
		t.Errorf("Expected SOA for %s, got %s", testExampleDomain, soa.Hdr.Name)
	}
}

func TestIsNegativeResponse_NXDOMAIN(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{}
	msg.Response = true
	msg.Rcode = dns.RcodeNameError

	// Add SOA
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	}
	msg.Ns = append(msg.Ns, soa)

	isNeg, negType, extractedSOA := IsNegativeResponse(msg)
	if !isNeg {
		t.Error("Expected NXDOMAIN to be negative response")
	}
	if negType != NegativeNXDOMAIN {
		t.Errorf("Expected NXDOMAIN type, got %v", negType)
	}
	if extractedSOA == nil {
		t.Error("Expected SOA to be extracted")
	}
}

func TestIsNegativeResponse_NODATA(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{}
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	// Empty answer section

	// Add SOA to authority section
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	}
	msg.Ns = append(msg.Ns, soa)

	isNeg, negType, extractedSOA := IsNegativeResponse(msg)
	if !isNeg {
		t.Error("Expected NODATA to be negative response")
	}
	if negType != NegativeNODATA {
		t.Errorf("Expected NODATA type, got %v", negType)
	}
	if extractedSOA == nil {
		t.Error("Expected SOA to be extracted")
	}
}

func TestIsNegativeResponse_NotNegative(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{}
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess

	// Add answer
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 1},
	}
	msg.Answer = append(msg.Answer, a)

	isNeg, _, _ := IsNegativeResponse(msg)
	if isNeg {
		t.Error("Expected positive response to not be negative")
	}
}

func TestIsNegativeResponse_NotResponse(t *testing.T) {
	t.Parallel()
	msg := &dns.Msg{}
	msg.Response = false
	msg.Rcode = dns.RcodeNameError

	isNeg, _, _ := IsNegativeResponse(msg)
	if isNeg {
		t.Error("Expected query to not be negative response")
	}
}

func TestCreateNegativeResponse_NXDOMAIN(t *testing.T) {
	t.Parallel()
	query := &dns.Msg{}
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:   "ns1.example.com.",
		Mbox: "admin.example.com.",
	}

	response := CreateNegativeResponse(query, NegativeNXDOMAIN, soa)

	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected RCODE NXDOMAIN, got %d", response.Rcode)
	}

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
	if responseSOA.Hdr.Name != testExampleDomain {
		t.Errorf("Expected SOA for %s, got %s", testExampleDomain, responseSOA.Hdr.Name)
	}
}

func TestCreateNegativeResponse_NODATA(t *testing.T) {
	t.Parallel()
	query := &dns.Msg{}
	query.SetQuestion(testExampleDomain, dns.TypeAAAA)

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   testExampleDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	}

	response := CreateNegativeResponse(query, NegativeNODATA, soa)

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
	nc := NewNegativeCache(DefaultNegativeCacheConfig())

	key := MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

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
	nc.Set(key, NegativeNXDOMAIN, nil)
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
	nc := NewNegativeCache(DefaultNegativeCacheConfig())

	key := MakeKey("nonexistent.example.com.", dns.TypeA, dns.ClassINET)

	// Store
	nc.Set(key, NegativeNXDOMAIN, nil)

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

func TestNegativeCache_Sharding(t *testing.T) {
	t.Parallel()
	config := DefaultNegativeCacheConfig()
	config.NumShards = 4
	nc := NewNegativeCache(config)

	if len(nc.shards) != 4 {
		t.Errorf("Expected 4 shards, got %d", len(nc.shards))
	}

	// Store entries and verify they go to different shards
	keys := []string{
		MakeKey("domain1.com.", dns.TypeA, dns.ClassINET),
		MakeKey("domain2.com.", dns.TypeA, dns.ClassINET),
		MakeKey("domain3.com.", dns.TypeA, dns.ClassINET),
		MakeKey("domain4.com.", dns.TypeA, dns.ClassINET),
	}

	for _, key := range keys {
		nc.Set(key, NegativeNXDOMAIN, nil)
	}

	// Verify retrieval
	for _, key := range keys {
		if nc.Get(key) == nil {
			t.Errorf("Failed to retrieve key %s", key)
		}
	}
}
