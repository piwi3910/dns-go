package dnssec

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// TestValidatorCreation tests basic validator creation
func TestValidatorCreation(t *testing.T) {
	config := DefaultValidatorConfig()
	validator := NewValidator(config)

	if validator == nil {
		t.Fatal("Failed to create validator")
	}

	if len(validator.trustAnchors) == 0 {
		t.Error("No trust anchors loaded")
	}

	t.Logf("✓ DNSSEC Validator created with %d trust anchors", len(validator.trustAnchors))
}

// TestRootTrustAnchor tests root zone trust anchor loading
func TestRootTrustAnchor(t *testing.T) {
	validator := NewValidator(DefaultValidatorConfig())

	// Check for root KSK-2017 (key tag 20326)
	rootTA := validator.GetTrustAnchor(".", 20326)
	if rootTA == nil {
		t.Fatal("Root trust anchor (KSK-2017, 20326) not found")
	}

	if rootTA.Algorithm != dns.RSASHA256 {
		t.Errorf("Expected algorithm %d (RSASHA256), got %d", dns.RSASHA256, rootTA.Algorithm)
	}

	if rootTA.KeyTag != 20326 {
		t.Errorf("Expected key tag 20326, got %d", rootTA.KeyTag)
	}

	t.Logf("✓ Root trust anchor verified: KeyTag=%d, Algorithm=%d", rootTA.KeyTag, rootTA.Algorithm)
}

// TestValidateResponse_NoRRSIG tests validation of responses without RRSIG
func TestValidateResponse_NoRRSIG(t *testing.T) {
	validator := NewValidator(DefaultValidatorConfig())

	// Create a simple response without RRSIG
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true

	// Add answer without RRSIG
	rr, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	msg.Answer = append(msg.Answer, rr)

	result, err := validator.ValidateResponse(context.Background(), msg)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Insecure {
		t.Error("Expected insecure result for response without RRSIG")
	}

	if result.Message != "No RRSIG records in response" {
		t.Errorf("Unexpected message: %s", result.Message)
	}

	t.Logf("✓ Insecure response handled correctly: %s", result.Message)
}

// TestValidateResponse_Disabled tests validation when disabled
func TestValidateResponse_Disabled(t *testing.T) {
	config := DefaultValidatorConfig()
	config.EnableValidation = false
	validator := NewValidator(config)

	// Create any response
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true

	result, err := validator.ValidateResponse(context.Background(), msg)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Insecure {
		t.Error("Expected insecure result when validation is disabled")
	}

	if result.Message != "DNSSEC validation disabled" {
		t.Errorf("Unexpected message: %s", result.Message)
	}

	t.Logf("✓ Disabled validation returns insecure: %s", result.Message)
}

// TestCalculateKeyTag tests key tag calculation
func TestCalculateKeyTag(t *testing.T) {
	// Create a test DNSKEY
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257, // KSK flag
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}

	keyTag := CalculateKeyTag(dnskey)

	// Root KSK-2017 has key tag 20326
	expectedKeyTag := uint16(20326)
	if keyTag != expectedKeyTag {
		t.Errorf("Expected key tag %d, got %d", expectedKeyTag, keyTag)
	}

	t.Logf("✓ Key tag calculated correctly: %d", keyTag)
}

// TestAddTrustAnchor tests adding custom trust anchors
func TestAddTrustAnchor(t *testing.T) {
	validator := NewValidator(DefaultValidatorConfig())

	// Add a custom trust anchor
	customTA := &TrustAnchor{
		Name:      "example.com.",
		Algorithm: dns.RSASHA256,
		KeyTag:    12345,
		PublicKey: "test-public-key",
	}

	validator.AddTrustAnchor(customTA)

	// Retrieve it
	retrieved := validator.GetTrustAnchor("example.com.", 12345)
	if retrieved == nil {
		t.Fatal("Failed to retrieve custom trust anchor")
	}

	if retrieved.KeyTag != 12345 {
		t.Errorf("Expected key tag 12345, got %d", retrieved.KeyTag)
	}

	t.Logf("✓ Custom trust anchor added and retrieved successfully")
}

// TestValidatorConfig tests configuration options
func TestValidatorConfig(t *testing.T) {
	config := ValidatorConfig{
		EnableValidation:   true,
		ValidateExpiration: false,
		MaxChainLength:     5,
		RequireValidation:  true,
	}

	validator := NewValidator(config)

	if validator.config.EnableValidation != true {
		t.Error("EnableValidation not set correctly")
	}

	if validator.config.ValidateExpiration != false {
		t.Error("ValidateExpiration not set correctly")
	}

	if validator.config.MaxChainLength != 5 {
		t.Error("MaxChainLength not set correctly")
	}

	if validator.config.RequireValidation != true {
		t.Error("RequireValidation not set correctly")
	}

	t.Logf("✓ Validator configuration set correctly")
}

// TestDNSKEYCache tests DNSKEY caching functionality
func TestDNSKEYCache(t *testing.T) {
	cache := NewDNSKEYCache(DefaultDNSKEYCacheConfig())

	// Create a test DNSKEY
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "test-key-data",
	}

	// Add to cache
	cache.Add(dnskey, true)

	// Retrieve from cache
	cached := cache.Get("example.com.", dnskey.KeyTag(), dns.RSASHA256)
	if cached == nil {
		t.Fatal("Failed to retrieve DNSKEY from cache")
	}

	if cached.PublicKey != "test-key-data" {
		t.Errorf("Cached key data mismatch: expected 'test-key-data', got '%s'", cached.PublicKey)
	}

	// Check validation status
	if !cache.IsValidated("example.com.", dnskey.KeyTag(), dns.RSASHA256) {
		t.Error("Key should be marked as validated")
	}

	t.Logf("✓ DNSKEY cache working correctly")
}

// TestIsKSK tests KSK flag detection
func TestIsKSK(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		expected bool
	}{
		{"KSK", 257, true},  // 0x0101 - Zone key + SEP
		{"ZSK", 256, false}, // 0x0100 - Zone key only
		{"Invalid", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnskey := &dns.DNSKEY{
				Flags:     tt.flags,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
			}

			result := IsKSK(dnskey)
			if result != tt.expected {
				t.Errorf("IsKSK(%d): expected %v, got %v", tt.flags, tt.expected, result)
			}
		})
	}

	t.Logf("✓ KSK detection working correctly")
}

// TestIsZSK tests ZSK flag detection
func TestIsZSK(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint16
		expected bool
	}{
		{"ZSK", 256, true},  // 0x0100 - Zone key only
		{"KSK", 257, false}, // 0x0101 - Zone key + SEP
		{"Invalid", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnskey := &dns.DNSKEY{
				Flags:     tt.flags,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
			}

			result := IsZSK(dnskey)
			if result != tt.expected {
				t.Errorf("IsZSK(%d): expected %v, got %v", tt.flags, tt.expected, result)
			}
		})
	}

	t.Logf("✓ ZSK detection working correctly")
}

// TestCanonicalName tests canonical name conversion
func TestCanonicalName(t *testing.T) {
	tests := []struct {
		input    string
		expected []byte
	}{
		{
			"example.com.",
			[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			"WWW.EXAMPLE.COM.", // Should be lowercased
			[]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			".",
			[]byte{0},
		},
	}

	for _, tt := range tests {
		result := canonicalName(tt.input)
		if string(result) != string(tt.expected) {
			t.Errorf("canonicalName(%s): expected %v, got %v", tt.input, tt.expected, result)
		}
	}

	t.Logf("✓ Canonical name conversion working correctly")
}

// TestNSECCoversName tests NSEC name covering logic
func TestNSECCoversName(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		next     string
		testName string
		expected bool
	}{
		{
			"Normal coverage",
			"a.example.com.",
			"c.example.com.",
			"b.example.com.",
			true,
		},
		{
			"Not covered (before)",
			"b.example.com.",
			"d.example.com.",
			"a.example.com.",
			false,
		},
		{
			"Not covered (after)",
			"b.example.com.",
			"d.example.com.",
			"e.example.com.",
			false,
		},
		{
			"Wrap-around (last NSEC)",
			"z.example.com.",
			"a.example.com.",
			"zz.example.com.",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := coversName(tt.owner, tt.next, tt.testName)
			if result != tt.expected {
				t.Errorf("coversName(%s, %s, %s): expected %v, got %v",
					tt.owner, tt.next, tt.testName, tt.expected, result)
			}
		})
	}

	t.Logf("✓ NSEC coverage logic working correctly")
}

// TestGetParentZone tests parent zone extraction
func TestGetParentZone(t *testing.T) {
	tests := []struct {
		zone     string
		expected string
	}{
		{"example.com.", "com."},
		{"www.example.com.", "example.com."},
		{"com.", "."},
		{".", ""},
	}

	for _, tt := range tests {
		result := getParentZone(tt.zone)
		if result != tt.expected {
			t.Errorf("getParentZone(%s): expected %s, got %s", tt.zone, tt.expected, result)
		}
	}

	t.Logf("✓ Parent zone extraction working correctly")
}

// TestBuildChainPath tests chain path building
func TestBuildChainPath(t *testing.T) {
	path := BuildChainPath("www.example.com.")

	expected := []string{
		"www.example.com.",
		"example.com.",
		"com.",
		".",
	}

	if len(path) != len(expected) {
		t.Fatalf("Expected path length %d, got %d", len(expected), len(path))
	}

	for i, zone := range path {
		if zone != expected[i] {
			t.Errorf("Path[%d]: expected %s, got %s", i, expected[i], zone)
		}
	}

	t.Logf("✓ Chain path building working correctly: %v", path)
}

// TestNSEC3HashName tests NSEC3 name hashing
func TestNSEC3HashName(t *testing.T) {
	// Test with known values from RFC 5155 examples
	nsec3 := &dns.NSEC3{
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 12,
		Salt:       "AABBCCDD",
	}

	// Hash a test name
	name := "example.com."
	hash := hashName(name, nsec3)

	if hash == "" {
		t.Error("Hash result is empty")
	}

	// Hash should be base32hex encoded (no padding)
	if len(hash) != 32 { // SHA-1 is 160 bits = 20 bytes = 32 base32 chars
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	t.Logf("✓ NSEC3 hash for %s: %s", name, hash)
}

// TestNSEC3OptOut tests opt-out flag detection
func TestNSEC3OptOut(t *testing.T) {
	tests := []struct {
		flags    uint8
		expected bool
	}{
		{0x00, false}, // Opt-out disabled
		{0x01, true},  // Opt-out enabled
	}

	for _, tt := range tests {
		nsec3 := &dns.NSEC3{
			Flags: tt.flags,
		}

		result := IsOptOut(nsec3)
		if result != tt.expected {
			t.Errorf("IsOptOut(%d): expected %v, got %v", tt.flags, tt.expected, result)
		}
	}

	t.Logf("✓ NSEC3 opt-out detection working correctly")
}

// TestValidateNSEC3Params tests NSEC3 parameter validation
func TestValidateNSEC3Params(t *testing.T) {
	tests := []struct {
		name       string
		nsec3      *dns.NSEC3
		shouldFail bool
	}{
		{
			"Valid parameters",
			&dns.NSEC3{
				Hash:       dns.SHA1,
				Iterations: 10,
				Salt:       "AABBCCDD",
			},
			false,
		},
		{
			"Too many iterations",
			&dns.NSEC3{
				Hash:       dns.SHA1,
				Iterations: 200,
				Salt:       "AABBCCDD",
			},
			true,
		},
		{
			"Unsupported hash",
			&dns.NSEC3{
				Hash:       255,
				Iterations: 10,
				Salt:       "AABBCCDD",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNSEC3Params(tt.nsec3)
			if (err != nil) != tt.shouldFail {
				t.Errorf("ValidateNSEC3Params: expected error=%v, got error=%v",
					tt.shouldFail, err != nil)
			}
		})
	}

	t.Logf("✓ NSEC3 parameter validation working correctly")
}

// TestExtractNSECRecords tests NSEC record extraction from messages
func TestExtractNSECRecords(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// Add NSEC records to authority section
	nsec1, _ := dns.NewRR("example.com. 3600 IN NSEC next.example.com. A RRSIG NSEC")
	nsec2, _ := dns.NewRR("next.example.com. 3600 IN NSEC zzz.example.com. A RRSIG NSEC")

	msg.Ns = append(msg.Ns, nsec1, nsec2)

	nsecs := ExtractNSECRecords(msg)
	if len(nsecs) != 2 {
		t.Errorf("Expected 2 NSEC records, got %d", len(nsecs))
	}

	t.Logf("✓ NSEC record extraction working correctly")
}

// TestExtractNSEC3Records tests NSEC3 record extraction from messages
func TestExtractNSEC3Records(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// Create NSEC3 records
	nsec3_1 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   "ABC123.example.com.",
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 10,
		Salt:       "AABBCCDD",
		NextDomain: "DEF456",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}

	msg.Ns = append(msg.Ns, nsec3_1)

	nsec3s := ExtractNSEC3Records(msg)
	if len(nsec3s) != 1 {
		t.Errorf("Expected 1 NSEC3 record, got %d", len(nsec3s))
	}

	t.Logf("✓ NSEC3 record extraction working correctly")
}
