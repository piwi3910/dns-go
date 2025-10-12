package dnssec

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA1 required for DNSSEC per RFC 4034
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Package-level errors.
var (
	ErrAlgorithmMismatch = errors.New("algorithm mismatch")
	ErrKeyTagMismatch    = errors.New("key tag mismatch")
	ErrDigestMismatch    = errors.New("digest mismatch")
	ErrInvalidDNSKEYWire = errors.New("invalid DNSKEY wire format")
	ErrUnsupportedDigest = errors.New("unsupported digest type")
)

// DNSKEY cache configuration constants.
const (
	defaultDNSKEYCacheMaxSize  = 1000 // Maximum number of cached keys
	defaultDNSKEYCacheMinTTLMin = 5    // Minimum TTL in minutes
	defaultDNSKEYCacheMaxTTLHr  = 24   // Maximum TTL in hours

	// DNS wire format constants (RFC 1035).
	dnsWireBufferSize        = 512 // Default DNS message size
	dnsRDataHeaderSize       = 10  // Size of RR header before RDATA (type + class + ttl + rdlength)
	dnsCompressionPointerMask = 0xC0 // DNS name compression pointer mask
	dnsCompressionPointerSize = 2    // Size of compression pointer in bytes
)

// DNSKEYCache caches DNSKEY records for DNSSEC validation.
type DNSKEYCache struct {
	keys   map[string]*CachedDNSKEY
	mu     sync.RWMutex
	config DNSKEYCacheConfig
}

// DNSKEYCacheConfig holds configuration for DNSKEY caching.
type DNSKEYCacheConfig struct {
	// MaxSize is the maximum number of cached keys (default: 1000)
	MaxSize int

	// DefaultTTL is the default TTL for cached keys (default: 1 hour)
	DefaultTTL time.Duration

	// MinTTL is the minimum TTL for cached keys (default: 5 minutes)
	MinTTL time.Duration

	// MaxTTL is the maximum TTL for cached keys (default: 24 hours)
	MaxTTL time.Duration
}

// DefaultDNSKEYCacheConfig returns default configuration.
func DefaultDNSKEYCacheConfig() DNSKEYCacheConfig {
	return DNSKEYCacheConfig{
		MaxSize:    defaultDNSKEYCacheMaxSize,
		DefaultTTL: 1 * time.Hour,
		MinTTL:     defaultDNSKEYCacheMinTTLMin * time.Minute,
		MaxTTL:     defaultDNSKEYCacheMaxTTLHr * time.Hour,
	}
}

// CachedDNSKEY represents a cached DNSKEY with metadata.
type CachedDNSKEY struct {
	Key       *dns.DNSKEY
	Expiry    time.Time
	Validated bool // Whether this key has been validated via chain of trust
}

// NewDNSKEYCache creates a new DNSKEY cache.
func NewDNSKEYCache(config DNSKEYCacheConfig) *DNSKEYCache {
	return &DNSKEYCache{
		keys:   make(map[string]*CachedDNSKEY),
		mu:     sync.RWMutex{},
		config: config,
	}
}

// Add adds a DNSKEY to the cache.
func (kc *DNSKEYCache) Add(key *dns.DNSKEY, validated bool) {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	// Calculate expiry based on TTL
	ttl := time.Duration(key.Hdr.Ttl) * time.Second
	if ttl < kc.config.MinTTL {
		ttl = kc.config.MinTTL
	}
	if ttl > kc.config.MaxTTL {
		ttl = kc.config.MaxTTL
	}

	cacheKey := makeDNSKEYCacheKey(key.Hdr.Name, key.KeyTag(), key.Algorithm)
	kc.keys[cacheKey] = &CachedDNSKEY{
		Key:       key,
		Expiry:    time.Now().Add(ttl),
		Validated: validated,
	}

	// Simple eviction: if cache is full, remove expired entries
	if len(kc.keys) > kc.config.MaxSize {
		kc.evictExpired()
	}
}

// Get retrieves a DNSKEY from the cache.
func (kc *DNSKEYCache) Get(name string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	cacheKey := makeDNSKEYCacheKey(name, keyTag, algorithm)
	cached, ok := kc.keys[cacheKey]
	if !ok {
		return nil
	}

	// Check expiry
	if time.Now().After(cached.Expiry) {
		return nil
	}

	return cached.Key
}

// IsValidated checks if a DNSKEY has been validated via chain of trust.
func (kc *DNSKEYCache) IsValidated(name string, keyTag uint16, algorithm uint8) bool {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	cacheKey := makeDNSKEYCacheKey(name, keyTag, algorithm)
	cached, ok := kc.keys[cacheKey]
	if !ok {
		return false
	}

	return cached.Validated && time.Now().Before(cached.Expiry)
}

// evictExpired removes expired entries from cache.
func (kc *DNSKEYCache) evictExpired() {
	now := time.Now()
	for key, cached := range kc.keys {
		if now.After(cached.Expiry) {
			delete(kc.keys, key)
		}
	}
}

// makeDNSKEYCacheKey creates a cache key for a DNSKEY.
func makeDNSKEYCacheKey(name string, keyTag uint16, algorithm uint8) string {
	return fmt.Sprintf("%s:%d:%d", dns.Fqdn(name), keyTag, algorithm)
}

// ValidateDNSKEYWithDS validates a DNSKEY using a DS record
// Returns true if the DNSKEY matches the DS record hash.
func ValidateDNSKEYWithDS(dnskey *dns.DNSKEY, ds *dns.DS) error {
	// RFC 4034 §5.1.4: DS RR Wire Format
	// Verify algorithm match
	if dnskey.Algorithm != ds.Algorithm {
		return fmt.Errorf("%w: DNSKEY=%d, DS=%d", ErrAlgorithmMismatch, dnskey.Algorithm, ds.Algorithm)
	}

	// Verify key tag match
	keyTag := dnskey.KeyTag()
	if keyTag != ds.KeyTag {
		return fmt.Errorf("%w: DNSKEY=%d, DS=%d", ErrKeyTagMismatch, keyTag, ds.KeyTag)
	}

	// Calculate digest of DNSKEY
	digest, err := calculateDNSKEYDigest(dnskey, ds.DigestType)
	if err != nil {
		return fmt.Errorf("failed to calculate DNSKEY digest: %w", err)
	}

	// Compare digests
	if digest != ds.Digest {
		return ErrDigestMismatch
	}

	return nil
}

// calculateDNSKEYDigest calculates the digest of a DNSKEY (RFC 4034 §5.1.4).
func calculateDNSKEYDigest(dnskey *dns.DNSKEY, digestType uint8) (string, error) {
	// Construct owner name in wire format
	ownerWire := canonicalName(dnskey.Hdr.Name)

	// Pack DNSKEY to wire format
	wireBuf, off, err := packDNSKEY(dnskey)
	if err != nil {
		return "", err
	}

	// Extract RDATA portion
	rdata, err := extractRDATA(wireBuf, off)
	if err != nil {
		return "", err
	}

	// Construct buffer: owner name + RDATA
	ownerWire = append(ownerWire, rdata...)

	// Hash and return
	return hashOwnerWithRDATA(ownerWire, digestType)
}

// packDNSKEY packs a DNSKEY record into wire format.
func packDNSKEY(dnskey *dns.DNSKEY) ([]byte, int, error) {
	wireBuf := make([]byte, dnsWireBufferSize)
	off, err := dns.PackRR(dnskey, wireBuf, 0, nil, false)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack DNSKEY: %w", err)
	}

	return wireBuf, off, nil
}

// extractRDATA extracts the RDATA portion from a packed DNS record.
func extractRDATA(wireBuf []byte, off int) ([]byte, error) {
	nameEnd := findNameEnd(wireBuf)

	// RDATA starts at nameEnd + dnsRDataHeaderSize (type + class + ttl + rdlength)
	rdataStart := nameEnd + dnsRDataHeaderSize
	if rdataStart >= off {
		return nil, ErrInvalidDNSKEYWire
	}

	return wireBuf[rdataStart:off], nil
}

// findNameEnd finds the end position of a DNS name in wire format.
func findNameEnd(wireBuf []byte) int {
	for i := 0; i < len(wireBuf) && wireBuf[i] != 0; {
		// Check for compression pointer
		if wireBuf[i]&dnsCompressionPointerMask == dnsCompressionPointerMask {
			return i + dnsCompressionPointerSize
		}

		// Move to next label
		labelLen := int(wireBuf[i])
		i += labelLen + 1

		// Check for name terminator
		if i < len(wireBuf) && wireBuf[i] == 0 {
			return i + 1
		}
	}

	return 0
}

// hashOwnerWithRDATA hashes owner name and RDATA using specified digest type.
func hashOwnerWithRDATA(ownerWire []byte, digestType uint8) (string, error) {
	h, err := getHasher(digestType)
	if err != nil {
		return "", err
	}

	h.Write(ownerWire)
	digest := h.Sum(nil)

	// Convert to hex string (uppercase)
	return fmt.Sprintf("%X", digest), nil
}

// getHasher returns the appropriate hasher for the digest type.
func getHasher(digestType uint8) (hash.Hash, error) {
	switch digestType {
	case dns.SHA1: // Digest type 1
		return sha1.New(), nil //nolint:gosec // SHA1 required for DNSSEC per RFC 4034
	case dns.SHA256: // Digest type 2
		return sha256.New(), nil
	case dns.SHA384: // Digest type 4
		return sha512.New384(), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedDigest, digestType)
	}
}

// DNSKEYFetcher is an interface for fetching DNSKEYs from DNS.
type DNSKEYFetcher interface {
	// FetchDNSKEY fetches DNSKEY records for a zone
	FetchDNSKEY(ctx context.Context, zone string) ([]*dns.DNSKEY, error)

	// FetchDS fetches DS records for a zone from its parent
	FetchDS(ctx context.Context, zone string) ([]*dns.DS, error)
}

// IsKSK returns true if the DNSKEY is a Key Signing Key.
func IsKSK(key *dns.DNSKEY) bool {
	// Bit 7 of Flags (0x0100) is Zone Key flag (always 1 for DNSSEC)
	// Bit 15 of Flags (0x0001 in wire format, bit 0 counting from right) is Secure Entry Point (SEP) flag (KSK indicator)
	// KSK: flags = 257 (0x0101) = Zone Key + SEP
	return key.Flags&0x0100 == 0x0100 && key.Flags&0x0001 == 0x0001
}

// IsZSK returns true if the DNSKEY is a Zone Signing Key.
func IsZSK(key *dns.DNSKEY) bool {
	// ZSK: flags = 256 (0x0100) = Zone Key only, no SEP
	return key.Flags&0x0100 == 0x0100 && key.Flags&0x0001 == 0
}

// GetActiveKSKs returns all KSKs from a set of DNSKEYs.
func GetActiveKSKs(keys []*dns.DNSKEY) []*dns.DNSKEY {
	ksks := make([]*dns.DNSKEY, 0)
	for _, key := range keys {
		if IsKSK(key) {
			ksks = append(ksks, key)
		}
	}

	return ksks
}

// GetActiveZSKs returns all ZSKs from a set of DNSKEYs.
func GetActiveZSKs(keys []*dns.DNSKEY) []*dns.DNSKEY {
	zsks := make([]*dns.DNSKEY, 0)
	for _, key := range keys {
		if IsZSK(key) {
			zsks = append(zsks, key)
		}
	}

	return zsks
}
