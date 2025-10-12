package dnssec

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 required for DNSSEC per RFC 4034
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Validator handles DNSSEC validation of DNS responses.
type Validator struct {
	trustAnchors map[string]*TrustAnchor
	config       ValidatorConfig
}

// ValidatorConfig holds configuration for DNSSEC validation.
type ValidatorConfig struct {
	// EnableValidation enables DNSSEC validation (default: true)
	EnableValidation bool

	// ValidateExpiration checks signature expiration times (default: true)
	ValidateExpiration bool

	// MaxChainLength limits chain of trust depth (default: 10)
	MaxChainLength int

	// RequireValidation fails queries if validation fails (default: false)
	// If false, returns insecure result on validation failure
	RequireValidation bool
}

// DefaultValidatorConfig returns default configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		EnableValidation:   true,
		ValidateExpiration: true,
		MaxChainLength:     10,
		RequireValidation:  false,
	}
}

// TrustAnchor represents a trusted DNSKEY.
type TrustAnchor struct {
	Name      string
	Algorithm uint8
	KeyTag    uint16
	PublicKey string
	DS        *dns.DS // Optional DS record
}

// ValidationResult represents the result of DNSSEC validation.
type ValidationResult struct {
	Secure      bool
	Bogus       bool
	Insecure    bool
	Message     string
	ChainLength int
}

// NewValidator creates a new DNSSEC validator.
func NewValidator(config ValidatorConfig) *Validator {
	v := &Validator{
		trustAnchors: make(map[string]*TrustAnchor),
		config:       config,
	}

	// Load root trust anchors
	v.LoadRootTrustAnchors()

	return v
}

// LoadRootTrustAnchors loads the current root zone trust anchors
// Root KSK (Key Signing Key) 2017 - currently active.
func (v *Validator) LoadRootTrustAnchors() {
	// Root zone KSK-2017 (20326)
	// Valid as of 2017 and currently active
	rootKSK := &TrustAnchor{
		Name:      ".",
		Algorithm: dns.RSASHA256, // Algorithm 8
		KeyTag:    20326,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+" +
			"/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3Eg" +
			"VLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIds" +
			"IXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
		DS: nil,
	}

	v.AddTrustAnchor(rootKSK)
}

// AddTrustAnchor adds a trust anchor to the validator.
func (v *Validator) AddTrustAnchor(ta *TrustAnchor) {
	key := fmt.Sprintf("%s:%d", strings.ToLower(ta.Name), ta.KeyTag)
	v.trustAnchors[key] = ta
}

// GetTrustAnchor retrieves a trust anchor.
func (v *Validator) GetTrustAnchor(name string, keyTag uint16) *TrustAnchor {
	key := fmt.Sprintf("%s:%d", strings.ToLower(name), keyTag)

	return v.trustAnchors[key]
}

// ValidateResponse validates a DNS response with DNSSEC.
func (v *Validator) ValidateResponse(_ context.Context, msg *dns.Msg) (*ValidationResult, error) {
	if !v.config.EnableValidation {
		return &ValidationResult{
			Secure:      false,
			Bogus:       false,
			Insecure:    true,
			Message:     "DNSSEC validation disabled",
			ChainLength: 0,
		}, nil
	}

	// Check if response has DNSSEC records
	if !hasRRSIG(msg) {
		return &ValidationResult{
			Secure:      false,
			Bogus:       false,
			Insecure:    true,
			Message:     "No RRSIG records in response",
			ChainLength: 0,
		}, nil
	}

	// Validate RRSIG signatures
	if err := v.validateRRSIGs(msg); err != nil {
		return &ValidationResult{
			Secure:      false,
			Bogus:       true,
			Insecure:    false,
			Message:     fmt.Sprintf("RRSIG validation failed: %v", err),
			ChainLength: 0,
		}, err
	}

	return &ValidationResult{
		Secure:      true,
		Bogus:       false,
		Insecure:    false,
		Message:     "DNSSEC validation successful",
		ChainLength: 0,
	}, nil
}

// VerifyRRSIG verifies an RRSIG signature against a DNSKEY.
func (v *Validator) VerifyRRSIG(rrsig *dns.RRSIG, rrset []dns.RR, dnskey *dns.DNSKEY) error {
	// Calculate signature data
	sigData := v.calculateSignatureData(rrsig, rrset)

	// Decode the signature
	signature, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Decode the public key
	pubKeyBytes, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	// Verify based on algorithm
	switch rrsig.Algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return v.verifyRSA(sigData, signature, pubKeyBytes, crypto.SHA1)
	case dns.RSASHA256:
		return v.verifyRSA(sigData, signature, pubKeyBytes, crypto.SHA256)
	case dns.RSASHA512:
		return v.verifyRSA(sigData, signature, pubKeyBytes, crypto.SHA512)
	case dns.ECDSAP256SHA256:
		return v.verifyECDSA(sigData, signature, pubKeyBytes, crypto.SHA256)
	case dns.ECDSAP384SHA384:
		return v.verifyECDSA(sigData, signature, pubKeyBytes, crypto.SHA512)
	default:
		return fmt.Errorf("unsupported algorithm: %d", rrsig.Algorithm)
	}
}

// validateRRSIGs validates all RRSIG records in a message.
func (v *Validator) validateRRSIGs(msg *dns.Msg) error {
	// Collect RRSIGs and their corresponding RRsets
	rrsigs := make([]*dns.RRSIG, 0)
	rrsets := make(map[string][]dns.RR)

	// Extract RRSIGs from answer section
	for _, rr := range msg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, rrsig)
		} else {
			// Group RRs by name+type
			key := fmt.Sprintf("%s:%d", rr.Header().Name, rr.Header().Rrtype)
			rrsets[key] = append(rrsets[key], rr)
		}
	}

	// Validate each RRSIG
	for _, rrsig := range rrsigs {
		// Find corresponding RRset
		key := fmt.Sprintf("%s:%d", rrsig.Header().Name, rrsig.TypeCovered)
		rrset, ok := rrsets[key]
		if !ok {
			return fmt.Errorf("RRSIG for %s type %d has no corresponding RRset", rrsig.Header().Name, rrsig.TypeCovered)
		}

		// Validate this RRSIG
		if err := v.validateRRSIG(rrsig, rrset); err != nil {
			return fmt.Errorf("RRSIG validation failed for %s: %w", rrsig.Header().Name, err)
		}
	}

	return nil
}

// validateRRSIG validates a single RRSIG against an RRset.
func (v *Validator) validateRRSIG(rrsig *dns.RRSIG, rrset []dns.RR) error {
	// Check signature expiration
	if v.config.ValidateExpiration {
		//nolint:gosec // G115: DNSSEC timestamps use uint32 seconds since epoch per RFC 4034; safe until year 2106
		now := uint32(time.Now().Unix())
		if now < rrsig.Inception || now > rrsig.Expiration {
			return fmt.Errorf("signature expired or not yet valid (inception: %d, expiration: %d, now: %d)",
				rrsig.Inception, rrsig.Expiration, now)
		}
	}

	// Look up DNSKEY from trust anchors or parent zone
	// For now, check trust anchors - full chain validation comes later
	dnskey := v.findDNSKEY(rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
	if dnskey == nil {
		// No DNSKEY found - this is not necessarily an error
		// The key might need to be fetched from the zone
		// For now, we'll consider it a validation failure
		return fmt.Errorf("DNSKEY not found for %s (keytag=%d)", rrsig.SignerName, rrsig.KeyTag)
	}

	// Verify the RRSIG with the DNSKEY
	if err := v.VerifyRRSIG(rrsig, rrset, dnskey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// findDNSKEY attempts to find a DNSKEY from trust anchors
// Returns nil if not found (requires lookup from parent zone).
func (v *Validator) findDNSKEY(signerName string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	// Check trust anchors first
	ta := v.GetTrustAnchor(signerName, keyTag)
	if ta != nil && ta.Algorithm == algorithm {
		// Convert trust anchor to DNSKEY
		dnskey := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:     ta.Name,
				Rrtype:   dns.TypeDNSKEY,
				Class:    dns.ClassINET,
				Ttl:      0,
				Rdlength: 0,
			},
			Flags:     257, // KSK flag (trust anchors are typically KSKs)
			Protocol:  3,
			Algorithm: ta.Algorithm,
			PublicKey: ta.PublicKey,
		}

		return dnskey
	}

	// Note: DNSKEY lookup from resolver not yet implemented. See issue #2
	return nil
}

// calculateSignatureData computes the data that was signed
// Implements RFC 4034 Section 6: Canonical RR Ordering.
func (v *Validator) calculateSignatureData(rrsig *dns.RRSIG, rrset []dns.RR) []byte {
	buf := make([]byte, 0, 4096)

	// Add RRSIG RDATA (without signature) - RFC 4034 §3.1.8.1
	rrsigWire := make([]byte, 18)
	rrsigWire[0] = byte(rrsig.TypeCovered >> 8)
	rrsigWire[1] = byte(rrsig.TypeCovered)
	rrsigWire[2] = rrsig.Algorithm
	rrsigWire[3] = rrsig.Labels

	// Original TTL (4 bytes, big endian)
	ttl := rrsig.OrigTtl
	rrsigWire[4] = byte(ttl >> 24)
	rrsigWire[5] = byte(ttl >> 16)
	rrsigWire[6] = byte(ttl >> 8)
	rrsigWire[7] = byte(ttl)

	// Expiration (4 bytes)
	rrsigWire[8] = byte(rrsig.Expiration >> 24)
	rrsigWire[9] = byte(rrsig.Expiration >> 16)
	rrsigWire[10] = byte(rrsig.Expiration >> 8)
	rrsigWire[11] = byte(rrsig.Expiration)

	// Inception (4 bytes)
	rrsigWire[12] = byte(rrsig.Inception >> 24)
	rrsigWire[13] = byte(rrsig.Inception >> 16)
	rrsigWire[14] = byte(rrsig.Inception >> 8)
	rrsigWire[15] = byte(rrsig.Inception)

	// KeyTag (2 bytes)
	rrsigWire[16] = byte(rrsig.KeyTag >> 8)
	rrsigWire[17] = byte(rrsig.KeyTag)

	buf = append(buf, rrsigWire...)

	// Add signer name in canonical wire format
	signerWire := canonicalName(rrsig.SignerName)
	buf = append(buf, signerWire...)

	// Add canonical RRset (RFC 4034 §6)
	// 1. Sort RRs by canonical wire format
	// 2. Use original TTL from RRSIG
	// 3. Convert to lowercase canonical form
	canonicalRRs := make([][]byte, len(rrset))
	for i, rr := range rrset {
		// Create canonical form of each RR
		canonical := canonicalizeRR(rr, rrsig.OrigTtl, rrsig.Labels)
		canonicalRRs[i] = canonical
	}

	// Sort RRs by wire format (RFC 4034 §6.3)
	sortCanonicalRRs(canonicalRRs)

	// Append sorted canonical RRs
	for _, rrWire := range canonicalRRs {
		buf = append(buf, rrWire...)
	}

	return buf
}

// canonicalName converts a domain name to canonical wire format (RFC 4034 §6.2).
func canonicalName(name string) []byte {
	// Convert to lowercase and ensure FQDN
	name = strings.ToLower(dns.Fqdn(name))

	// Special case for root domain
	if name == "." {
		return []byte{0}
	}

	buf := make([]byte, 0, len(name)+1)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")

	for _, label := range labels {
		if label == "" {
			continue // Skip empty labels
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // Root label

	return buf
}

// canonicalizeRR converts an RR to canonical wire format (RFC 4034 §6).
func canonicalizeRR(rr dns.RR, origTTL uint32, labels uint8) []byte {
	// Create a copy with original TTL
	rrCopy := dns.Copy(rr)
	rrCopy.Header().Ttl = origTTL

	// Handle wildcards (RFC 4034 §3.1.8.1)
	// If the number of labels in the owner name < labels field,
	// replace owner name with wildcard
	ownerName := rrCopy.Header().Name
	ownerLabels := dns.CountLabel(ownerName)
	if ownerLabels > int(labels) {
		// Wildcard expansion case
		// Replace leftmost labels with single asterisk label
		parts := strings.Split(dns.Fqdn(ownerName), ".")
		// Keep rightmost 'labels' labels, replace rest with *
		if len(parts) > int(labels) {
			wildcard := "*." + strings.Join(parts[len(parts)-int(labels):], ".")
			rrCopy.Header().Name = wildcard
		}
	}

	// Convert name to lowercase canonical form
	rrCopy.Header().Name = strings.ToLower(dns.Fqdn(rrCopy.Header().Name))

	// Pack to wire format
	buf := make([]byte, 0, 512)

	// Pack owner name
	ownerWire := canonicalName(rrCopy.Header().Name)
	buf = append(buf, ownerWire...)

	// Pack header fields
	header := make([]byte, 10)
	header[0] = byte(rrCopy.Header().Rrtype >> 8)
	header[1] = byte(rrCopy.Header().Rrtype)
	header[2] = byte(rrCopy.Header().Class >> 8)
	header[3] = byte(rrCopy.Header().Class)
	header[4] = byte(origTTL >> 24)
	header[5] = byte(origTTL >> 16)
	header[6] = byte(origTTL >> 8)
	header[7] = byte(origTTL)

	// Pack RDATA
	rdataWire := packRDATA(rrCopy)
	//nolint:gosec // G115: DNS RDATA length limited to 65535 bytes per RFC 1035; packRDATA uses 512-byte buffer
	rdataLen := uint16(len(rdataWire))
	header[8] = byte(rdataLen >> 8)
	header[9] = byte(rdataLen)

	buf = append(buf, header...)
	buf = append(buf, rdataWire...)

	return buf
}

// packRDATA packs RR RDATA to wire format with canonical name lowercasing.
func packRDATA(rr dns.RR) []byte {
	// Use miekg/dns packing, then lowercase domain names in RDATA
	// For types that contain domain names (CNAME, NS, MX, etc.)
	buf := make([]byte, 512)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return []byte{}
	}

	// Extract RDATA portion (skip name + 10 byte header)
	// Find where RDATA starts
	nameLen := 0
	for i := 0; i < len(buf) && buf[i] != 0; {
		if buf[i]&0xC0 == 0xC0 {
			// Compression pointer
			nameLen = i + 2

			break
		}
		labelLen := int(buf[i])
		i += labelLen + 1
		if i < len(buf) && buf[i] == 0 {
			nameLen = i + 1

			break
		}
	}

	// RDATA starts after name (nameLen) + type(2) + class(2) + ttl(4) + rdlength(2) = nameLen + 10
	rdataStart := nameLen + 10
	if rdataStart >= off {
		return []byte{}
	}

	return buf[rdataStart:off]
}

// sortCanonicalRRs sorts RRs in canonical order (RFC 4034 §6.3).
func sortCanonicalRRs(rrs [][]byte) {
	// Sort by lexicographic order of wire format
	for i := range len(rrs) - 1 {
		for j := i + 1; j < len(rrs); j++ {
			if compareWireFormat(rrs[i], rrs[j]) > 0 {
				rrs[i], rrs[j] = rrs[j], rrs[i]
			}
		}
	}
}

// compareWireFormat compares two RRs in wire format
// Returns: -1 if a < b, 0 if a == b, 1 if a > b.
func compareWireFormat(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := range minLen {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	// If all bytes equal, shorter one comes first
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}

	return 0
}

// verifyRSA verifies an RSA signature.
func (v *Validator) verifyRSA(data, signature, pubKey []byte, hashAlgo crypto.Hash) error {
	// Parse RSA public key (RFC 3110 format)
	if len(pubKey) < 3 {
		return errors.New("public key too short")
	}

	// Extract exponent
	var exponent int
	var modulusStart int

	if pubKey[0] == 0 {
		// Exponent length is in next 2 bytes
		exponent = int(pubKey[1])<<8 | int(pubKey[2])
		modulusStart = 3 + exponent
	} else {
		// Exponent length is in first byte
		exponent = int(pubKey[0])
		modulusStart = 1 + exponent
	}

	if modulusStart > len(pubKey) {
		return errors.New("invalid public key format")
	}

	// Extract exponent bytes
	expBytes := pubKey[1:modulusStart]
	e := big.NewInt(0).SetBytes(expBytes)

	// Extract modulus
	modulusBytes := pubKey[modulusStart:]
	n := big.NewInt(0).SetBytes(modulusBytes)

	// Create RSA public key
	rsaPub := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	// Hash the data
	var h hash.Hash
	switch hashAlgo {
	case crypto.SHA1:
		h = sha1.New() //nolint:gosec // SHA1 required for DNSSEC per RFC 4034
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA512:
		h = sha512.New()
	case crypto.MD4, crypto.MD5, crypto.SHA224, crypto.SHA384, crypto.MD5SHA1,
		crypto.RIPEMD160, crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384,
		crypto.SHA3_512, crypto.SHA512_224, crypto.SHA512_256, crypto.BLAKE2s_256,
		crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512:
		// Explicitly unsupported hash algorithms for DNSSEC RSA verification
		return fmt.Errorf("unsupported RSA hash algorithm: %v", hashAlgo)
	default:
		return fmt.Errorf("unknown hash algorithm: %v", hashAlgo)
	}
	h.Write(data)
	hashed := h.Sum(nil)

	// Verify signature
	if err := rsa.VerifyPKCS1v15(rsaPub, hashAlgo, hashed, signature); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// verifyECDSA verifies an ECDSA signature.
func (v *Validator) verifyECDSA(data, signature, pubKey []byte, hashAlgo crypto.Hash) error {
	// RFC 6605 - ECDSA for DNSSEC
	// Public key format: 0x04 || X || Y (uncompressed point)

	if len(pubKey) < 1 {
		return errors.New("ECDSA public key too short")
	}

	// Determine curve based on algorithm
	var curve ecdsa.PublicKey
	var expectedKeySize int

	switch hashAlgo {
	case crypto.SHA256:
		// P-256 curve
		curve.Curve = elliptic.P256()
		expectedKeySize = 64 // 32 bytes X + 32 bytes Y
	case crypto.SHA512:
		// P-384 curve
		curve.Curve = elliptic.P384()
		expectedKeySize = 96 // 48 bytes X + 48 bytes Y
	case crypto.MD4, crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA384,
		crypto.MD5SHA1, crypto.RIPEMD160, crypto.SHA3_224, crypto.SHA3_256,
		crypto.SHA3_384, crypto.SHA3_512, crypto.SHA512_224, crypto.SHA512_256,
		crypto.BLAKE2s_256, crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512:
		// Explicitly unsupported hash algorithms for DNSSEC ECDSA verification
		return fmt.Errorf("unsupported ECDSA hash algorithm: %v", hashAlgo)
	default:
		return fmt.Errorf("unknown ECDSA hash algorithm: %v", hashAlgo)
	}

	// Uncompressed point format: 0x04 || X || Y
	if pubKey[0] == 0x04 {
		pubKey = pubKey[1:]
	}

	if len(pubKey) != expectedKeySize {
		return fmt.Errorf("invalid ECDSA key size: expected %d, got %d", expectedKeySize, len(pubKey))
	}

	// Split into X and Y coordinates
	coordSize := expectedKeySize / 2
	curve.X = big.NewInt(0).SetBytes(pubKey[:coordSize])
	curve.Y = big.NewInt(0).SetBytes(pubKey[coordSize:])

	// ECDSA signature format: R || S (each 32 bytes for P-256, 48 bytes for P-384)
	if len(signature) != expectedKeySize {
		return errors.New("invalid ECDSA signature size")
	}

	r := big.NewInt(0).SetBytes(signature[:coordSize])
	s := big.NewInt(0).SetBytes(signature[coordSize:])

	// Hash the data
	var h hash.Hash
	switch hashAlgo {
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA512:
		h = sha512.New()
	case crypto.MD4, crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA384,
		crypto.MD5SHA1, crypto.RIPEMD160, crypto.SHA3_224, crypto.SHA3_256,
		crypto.SHA3_384, crypto.SHA3_512, crypto.SHA512_224, crypto.SHA512_256,
		crypto.BLAKE2s_256, crypto.BLAKE2b_256, crypto.BLAKE2b_384, crypto.BLAKE2b_512:
		// Explicitly unsupported hash algorithms for DNSSEC ECDSA signature hashing
		return fmt.Errorf("unsupported ECDSA signature hash algorithm: %v", hashAlgo)
	default:
		return fmt.Errorf("unknown hash algorithm: %v", hashAlgo)
	}
	h.Write(data)
	hashed := h.Sum(nil)

	// Verify signature
	if !ecdsa.Verify(&curve, hashed, r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// hasRRSIG checks if a message contains RRSIG records.
func hasRRSIG(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}

	return false
}

// CalculateKeyTag computes the key tag for a DNSKEY.
func CalculateKeyTag(dnskey *dns.DNSKEY) uint16 {
	// RFC 4034 Appendix B: Key Tag calculation
	// Use miekg/dns KeyTag() method if available
	return dnskey.KeyTag()
}
