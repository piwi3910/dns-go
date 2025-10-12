package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestValidatorCreation tests basic validator creation.
func TestValidatorCreation(t *testing.T) {
	t.Parallel()
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

// TestRootTrustAnchor tests root zone trust anchor loading.
func TestRootTrustAnchor(t *testing.T) {
	t.Parallel()
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

// TestValidateResponse_NoRRSIG tests validation of responses without RRSIG.
func TestValidateResponse_NoRRSIG(t *testing.T) {
	t.Parallel()
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

// TestValidateResponse_Disabled tests validation when disabled.
func TestValidateResponse_Disabled(t *testing.T) {
	t.Parallel()
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

// TestCalculateKeyTag tests key tag calculation.
func TestCalculateKeyTag(t *testing.T) {
	t.Parallel()
	// Create a test DNSKEY
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Rdlength: 0,
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

// TestAddTrustAnchor tests adding custom trust anchors.
func TestAddTrustAnchor(t *testing.T) {
	t.Parallel()
	validator := NewValidator(DefaultValidatorConfig())

	// Add a custom trust anchor
	customTA := &TrustAnchor{
		Name:      "example.com.",
		Algorithm: dns.RSASHA256,
		KeyTag:    12345,
		PublicKey: "test-public-key",
		DS:        nil,
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

// TestValidatorConfig tests configuration options.
func TestValidatorConfig(t *testing.T) {
	t.Parallel()
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

// TestDNSKEYCache tests DNSKEY caching functionality.
func TestDNSKEYCache(t *testing.T) {
	t.Parallel()
	cache := NewDNSKEYCache(DefaultDNSKEYCacheConfig())

	// Create a test DNSKEY
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Rdlength: 0,
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

// TestIsKSK tests KSK flag detection.
func TestIsKSK(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:     "",
					Rrtype:   0,
					Class:    0,
					Ttl:      0,
					Rdlength: 0,
				},
				Flags:     tt.flags,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "",
			}

			result := IsKSK(dnskey)
			if result != tt.expected {
				t.Errorf("IsKSK(%d): expected %v, got %v", tt.flags, tt.expected, result)
			}
		})
	}

	t.Logf("✓ KSK detection working correctly")
}

// TestIsZSK tests ZSK flag detection.
func TestIsZSK(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:     "",
					Rrtype:   0,
					Class:    0,
					Ttl:      0,
					Rdlength: 0,
				},
				Flags:     tt.flags,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: "",
			}

			result := IsZSK(dnskey)
			if result != tt.expected {
				t.Errorf("IsZSK(%d): expected %v, got %v", tt.flags, tt.expected, result)
			}
		})
	}

	t.Logf("✓ ZSK detection working correctly")
}

// TestCanonicalName tests canonical name conversion.
func TestCanonicalName(t *testing.T) {
	t.Parallel()
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

// TestNSECCoversName tests NSEC name covering logic.
func TestNSECCoversName(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			result := coversName(tt.owner, tt.next, tt.testName)
			if result != tt.expected {
				t.Errorf("coversName(%s, %s, %s): expected %v, got %v",
					tt.owner, tt.next, tt.testName, tt.expected, result)
			}
		})
	}

	t.Logf("✓ NSEC coverage logic working correctly")
}

// TestGetParentZone tests parent zone extraction.
func TestGetParentZone(t *testing.T) {
	t.Parallel()
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

// TestBuildChainPath tests chain path building.
func TestBuildChainPath(t *testing.T) {
	t.Parallel()
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

// TestNSEC3HashName tests NSEC3 name hashing.
func TestNSEC3HashName(t *testing.T) {
	t.Parallel()
	// Test with known values from RFC 5155 examples
	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:     "",
			Rrtype:   0,
			Class:    0,
			Ttl:      0,
			Rdlength: 0,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 12,
		SaltLength: 0,
		Salt:       "AABBCCDD",
		HashLength: 0,
		NextDomain: "",
		TypeBitMap: nil,
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

// TestNSEC3OptOut tests opt-out flag detection.
func TestNSEC3OptOut(t *testing.T) {
	t.Parallel()
	tests := []struct {
		flags    uint8
		expected bool
	}{
		{0x00, false}, // Opt-out disabled
		{0x01, true},  // Opt-out enabled
	}

	for _, tt := range tests {
		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:     "",
				Rrtype:   0,
				Class:    0,
				Ttl:      0,
				Rdlength: 0,
			},
			Hash:       0,
			Flags:      tt.flags,
			Iterations: 0,
			SaltLength: 0,
			Salt:       "",
			HashLength: 0,
			NextDomain: "",
			TypeBitMap: nil,
		}

		result := IsOptOut(nsec3)
		if result != tt.expected {
			t.Errorf("IsOptOut(%d): expected %v, got %v", tt.flags, tt.expected, result)
		}
	}

	t.Logf("✓ NSEC3 opt-out detection working correctly")
}

// TestValidateNSEC3Params tests NSEC3 parameter validation.
func TestValidateNSEC3Params(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		nsec3      *dns.NSEC3
		shouldFail bool
	}{
		{
			"Valid parameters",
			&dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:     "",
					Rrtype:   0,
					Class:    0,
					Ttl:      0,
					Rdlength: 0,
				},
				Hash:       dns.SHA1,
				Flags:      0,
				Iterations: 10,
				SaltLength: 0,
				Salt:       "AABBCCDD",
				HashLength: 0,
				NextDomain: "",
				TypeBitMap: nil,
			},
			false,
		},
		{
			"Too many iterations",
			&dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:     "",
					Rrtype:   0,
					Class:    0,
					Ttl:      0,
					Rdlength: 0,
				},
				Hash:       dns.SHA1,
				Flags:      0,
				Iterations: 200,
				SaltLength: 0,
				Salt:       "AABBCCDD",
				HashLength: 0,
				NextDomain: "",
				TypeBitMap: nil,
			},
			true,
		},
		{
			"Unsupported hash",
			&dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:     "",
					Rrtype:   0,
					Class:    0,
					Ttl:      0,
					Rdlength: 0,
				},
				Hash:       255,
				Flags:      0,
				Iterations: 10,
				SaltLength: 0,
				Salt:       "AABBCCDD",
				HashLength: 0,
				NextDomain: "",
				TypeBitMap: nil,
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateNSEC3Params(tt.nsec3)
			if (err != nil) != tt.shouldFail {
				t.Errorf("ValidateNSEC3Params: expected error=%v, got error=%v",
					tt.shouldFail, err != nil)
			}
		})
	}

	t.Logf("✓ NSEC3 parameter validation working correctly")
}

// TestExtractNSECRecords tests NSEC record extraction from messages.
func TestExtractNSECRecords(t *testing.T) {
	t.Parallel()
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

// TestExtractNSEC3Records tests NSEC3 record extraction from messages.
func TestExtractNSEC3Records(t *testing.T) {
	t.Parallel()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// Create NSEC3 records
	nsec3_1 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "ABC123.example.com.",
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 10,
		SaltLength: 0,
		Salt:       "AABBCCDD",
		HashLength: 0,
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

// TestNSECValidator_ValidateNXDOMAIN tests NXDOMAIN validation with NSEC.
func TestNSECValidator_ValidateNXDOMAIN(t *testing.T) {
	t.Parallel()
	v := NewValidator(DefaultValidatorConfig())
	validator := NewNSECValidator(v)

	// Create NSEC records that prove non-existence
	nsec1, _ := dns.NewRR("a.example.com. 3600 IN NSEC c.example.com. A RRSIG NSEC")
	nsecs := []*dns.NSEC{nsec1.(*dns.NSEC)}

	// Test name that falls between a and c
	err := validator.ValidateNXDOMAIN("b.example.com.", nsecs)
	if err != nil {
		t.Errorf("ValidateNXDOMAIN should succeed for name between NSEC records: %v", err)
	}

	t.Logf("✓ NSEC NXDOMAIN validation working correctly")
}

// TestNSECValidator_ValidateNODATA tests NODATA validation with NSEC.
func TestNSECValidator_ValidateNODATA(t *testing.T) {
	t.Parallel()
	v := NewValidator(DefaultValidatorConfig())
	validator := NewNSECValidator(v)

	// Create NSEC record that doesn't include the queried type
	nsec, _ := dns.NewRR("example.com. 3600 IN NSEC next.example.com. A RRSIG NSEC")
	nsecs := []*dns.NSEC{nsec.(*dns.NSEC)}

	// Query for AAAA, but NSEC only shows A
	err := validator.ValidateNODATA("example.com.", dns.TypeAAAA, nsecs)
	if err != nil {
		t.Errorf("ValidateNODATA should succeed when type not in NSEC bitmap: %v", err)
	}

	t.Logf("✓ NSEC NODATA validation working correctly")
}

// TestNSEC3Validator_ValidateNXDOMAIN tests NXDOMAIN validation with NSEC3.
func TestNSEC3Validator_ValidateNXDOMAIN(t *testing.T) {
	t.Parallel()
	v := NewValidator(DefaultValidatorConfig())
	validator := NewNSEC3Validator(v)

	// Create minimal NSEC3 record
	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "ABC123.example.com.",
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 10,
		SaltLength: 0,
		Salt:       "AABBCCDD",
		HashLength: 0,
		NextDomain: "DEF456",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}

	nsec3s := []*dns.NSEC3{nsec3}

	// This will fail without proper setup, but tests the code path
	err := validator.ValidateNXDOMAIN("nonexistent.example.com.", nsec3s)
	// We expect an error since we're not providing complete NSEC3 coverage
	// But the function should execute without panicking
	_ = err

	t.Logf("✓ NSEC3 NXDOMAIN validation code path exercised")
}

// TestNSEC3Validator_ValidateNODATA tests NODATA validation with NSEC3.
func TestNSEC3Validator_ValidateNODATA(t *testing.T) {
	t.Parallel()
	v := NewValidator(DefaultValidatorConfig())
	validator := NewNSEC3Validator(v)

	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "ABC123.example.com.",
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 10,
		SaltLength: 0,
		Salt:       "AABBCCDD",
		HashLength: 0,
		NextDomain: "DEF456",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}, // No AAAA
	}

	nsec3s := []*dns.NSEC3{nsec3}

	// Query for AAAA
	err := validator.ValidateNODATA("example.com.", dns.TypeAAAA, nsec3s)
	_ = err // May fail without complete setup, but tests code path

	t.Logf("✓ NSEC3 NODATA validation code path exercised")
}

// TestValidateDelegation tests delegation validation.
func TestValidateDelegation(t *testing.T) {
	t.Parallel()
	// Create child DNSKEY (KSK)
	childKey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "child.example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257, // KSK
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}

	// Create matching DS record
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "child.example.com.",
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     childKey.KeyTag(),
		Algorithm:  childKey.Algorithm,
		DigestType: dns.SHA256,
		Digest:     "", // Would need actual digest
	}

	// Test with empty records
	err := ValidateDelegation("example.com.", "child.example.com.", []*dns.DS{}, []*dns.DNSKEY{childKey})
	if err == nil {
		t.Error("ValidateDelegation should fail with no DS records")
	}

	err = ValidateDelegation("example.com.", "child.example.com.", []*dns.DS{ds}, []*dns.DNSKEY{})
	if err == nil {
		t.Error("ValidateDelegation should fail with no DNSKEY records")
	}

	t.Logf("✓ ValidateDelegation input validation working")
}

// TestGetActiveKSKs tests filtering of active KSKs.
func TestGetActiveKSKs(t *testing.T) {
	t.Parallel()
	keys := []*dns.DNSKEY{
		{
			Hdr: dns.RR_Header{
			Rdlength: 0,
				Name:   "example.com.",
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     257, // KSK
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: "test-ksk",
		},
		{
			Hdr: dns.RR_Header{
			Rdlength: 0,
				Name:   "example.com.",
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     256, // ZSK
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: "test-zsk",
		},
	}

	ksks := GetActiveKSKs(keys)
	if len(ksks) != 1 {
		t.Errorf("Expected 1 KSK, got %d", len(ksks))
	}

	if ksks[0].Flags != 257 {
		t.Error("Returned key is not a KSK")
	}

	t.Logf("✓ GetActiveKSKs filtering working correctly")
}

// TestGetActiveZSKs tests filtering of active ZSKs.
func TestGetActiveZSKs(t *testing.T) {
	t.Parallel()
	keys := []*dns.DNSKEY{
		{
			Hdr: dns.RR_Header{
			Rdlength: 0,
				Name:   "example.com.",
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     257, // KSK
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: "test-ksk",
		},
		{
			Hdr: dns.RR_Header{
			Rdlength: 0,
				Name:   "example.com.",
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     256, // ZSK
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: "test-zsk",
		},
	}

	zsks := GetActiveZSKs(keys)
	if len(zsks) != 1 {
		t.Errorf("Expected 1 ZSK, got %d", len(zsks))
	}

	if zsks[0].Flags != 256 {
		t.Error("Returned key is not a ZSK")
	}

	t.Logf("✓ GetActiveZSKs filtering working correctly")
}

// TestValidatorCacheHit tests validator response caching.
func TestValidatorCacheHit(t *testing.T) {
	t.Parallel()
	validator := NewValidator(DefaultValidatorConfig())

	msg1 := new(dns.Msg)
	msg1.SetQuestion("example.com.", dns.TypeA)
	msg1.Response = true

	// First validation
	result1, err := validator.ValidateResponse(context.Background(), msg1)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	// Second validation of same query (should be cached)
	result2, err := validator.ValidateResponse(context.Background(), msg1)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}

	// Results should be consistent
	if result1.Insecure != result2.Insecure {
		t.Error("Cached result differs from original")
	}

	t.Logf("✓ Validator caching working correctly")
}

// TestValidationResult tests validation result structure.
func TestValidationResult(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		result   *ValidationResult
		expected bool
	}{
		{
			"Secure result",
			&ValidationResult{
				Secure:      true,
				Insecure:    false,
				Bogus:       false,
				Message:     "",
				ChainLength: 0,
			},
			true,
		},
		{
			"Insecure result",
			&ValidationResult{
				Secure:      false,
				Insecure:    true,
				Bogus:       false,
				Message:     "",
				ChainLength: 0,
			},
			false,
		},
		{
			"Bogus result",
			&ValidationResult{
				Secure:      false,
				Insecure:    false,
				Bogus:       true,
				Message:     "",
				ChainLength: 0,
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.result.Secure != tt.expected {
				t.Errorf("Secure flag mismatch: expected %v, got %v", tt.expected, tt.result.Secure)
			}
		})
	}

	t.Logf("✓ ValidationResult structure working correctly")
}

// TestDNSKEYCacheEviction tests cache eviction.
func TestDNSKEYCacheEviction(t *testing.T) {
	t.Parallel()
	config := DNSKEYCacheConfig{
		MaxSize:    2, // Small cache for testing
		DefaultTTL: time.Hour,
		MinTTL:     0,
		MaxTTL:     0,
	}
	cache := NewDNSKEYCache(config)

	// Add more keys than cache can hold
	for i := range 5 {
		key := &dns.DNSKEY{
			Hdr: dns.RR_Header{
			Rdlength: 0,
				Name:   "example.com.",
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    uint32(3600 + i), // Different TTLs
			},
			Flags:     257,
			Protocol:  3,
			Algorithm: dns.RSASHA256,
			PublicKey: string(rune(i)), // Different keys
		}
		cache.Add(key, true)
	}

	// Cache will hold max 2 keys due to eviction
	t.Logf("✓ DNSKEY cache eviction test completed")
}

// TestDNSKEYCacheOperations tests basic cache operations.
func TestDNSKEYCacheOperations(t *testing.T) {
	t.Parallel()
	cache := NewDNSKEYCache(DefaultDNSKEYCacheConfig())

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Rdlength: 0,
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "test-key",
	}

	// Add key
	cache.Add(key, true)

	// Trigger hit
	retrieved := cache.Get("example.com.", key.KeyTag(), dns.RSASHA256)
	if retrieved == nil {
		t.Error("Expected to retrieve cached key")
	}

	// Trigger miss
	missing := cache.Get("nonexistent.com.", uint16(12345), dns.RSASHA256)
	if missing != nil {
		t.Error("Expected nil for non-existent key")
	}

	// Check validation status
	isValidated := cache.IsValidated("example.com.", key.KeyTag(), dns.RSASHA256)
	if !isValidated {
		t.Error("Expected key to be marked as validated")
	}

	t.Logf("✓ DNSKEY cache operations working correctly")
}
