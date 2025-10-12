// Package dnssec implements DNSSEC validation including signature verification and chain of trust.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DNSSEC protocol constants.
const (
	dnskeyFlagsKSK      = 257 // DNSKEY flags value for Key Signing Key (RFC 4034)
	dnskeyProtocol      = 3   // DNSSEC protocol value (always 3 per RFC 4034)
	zonePartsMaxSplit   = 2   // Maximum parts when splitting zone name
)

// Package-level errors for chain of trust validation.
var (
	ErrChainTooLong               = errors.New("chain of trust too long")
	ErrDNSKEYNotFoundInZone       = errors.New("DNSKEY not found in zone")
	ErrRootDNSKEYNotInTrustAnchor = errors.New("root DNSKEY not in trust anchors")
	ErrRootDNSKEYMismatch         = errors.New("root DNSKEY does not match trust anchor")
	ErrNoParentZone               = errors.New("no parent zone")
	ErrNoDSRecordsFound           = errors.New("no DS records found")
	ErrNoMatchingDSRecord         = errors.New("no matching DS record for DNSKEY")
	ErrNoKSKsInParentZone         = errors.New("no KSKs found in parent zone")
	ErrNoDSRecordsForDelegation   = errors.New("no DS records for delegation")
	ErrNoDNSKEYForChildZone       = errors.New("no DNSKEY records for child zone")
	ErrNoMatchingDNSKEYForDS      = errors.New("no matching DNSKEY found for DS records")
)

// ChainOfTrustValidator validates DNSSEC chains of trust.
type ChainOfTrustValidator struct {
	validator   *Validator
	keyCache    *DNSKEYCache
	keyFetcher  DNSKEYFetcher
	maxChainLen int
}

// NewChainOfTrustValidator creates a new chain of trust validator.
func NewChainOfTrustValidator(
	validator *Validator,
	keyCache *DNSKEYCache,
	keyFetcher DNSKEYFetcher,
	maxChainLen int,
) *ChainOfTrustValidator {
	return &ChainOfTrustValidator{
		validator:   validator,
		keyCache:    keyCache,
		keyFetcher:  keyFetcher,
		maxChainLen: maxChainLen,
	}
}

// ValidateChain validates the chain of trust from a zone to a trust anchor
// Returns the validated DNSKEY if successful, error otherwise.
func (ctv *ChainOfTrustValidator) ValidateChain(
	ctx context.Context,
	zone string,
	keyTag uint16,
	algorithm uint8,
) (*dns.DNSKEY, error) {
	// Check if we've already validated this key
	if ctv.keyCache.IsValidated(zone, keyTag, algorithm) {
		return ctv.keyCache.Get(zone, keyTag, algorithm), nil
	}

	// Check if this is a trust anchor
	ta := ctv.validator.GetTrustAnchor(zone, keyTag)
	if ta != nil && ta.Algorithm == algorithm {
		// This is a trust anchor - automatically trusted
		dnskey := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:     ta.Name,
				Rrtype:   dns.TypeDNSKEY,
				Class:    dns.ClassINET,
				Ttl:      0,
				Rdlength: 0,
			},
			Flags:     dnskeyFlagsKSK,
			Protocol:  dnskeyProtocol,
			Algorithm: ta.Algorithm,
			PublicKey: ta.PublicKey,
		}
		// Cache as validated
		ctv.keyCache.Add(dnskey, true)

		return dnskey, nil
	}

	// Walk the chain from this zone to a trust anchor
	return ctv.walkChain(ctx, zone, keyTag, algorithm, 0)
}

// ValidateRRSIGChain validates an RRSIG and its chain of trust
// This is the main entry point for validating signed responses.
func (ctv *ChainOfTrustValidator) ValidateRRSIGChain(ctx context.Context, rrsig *dns.RRSIG, rrset []dns.RR) error {
	// First, validate the RRSIG signature itself
	// Get the DNSKEY
	dnskey, err := ctv.ValidateChain(ctx, rrsig.SignerName, rrsig.KeyTag, rrsig.Algorithm)
	if err != nil {
		return fmt.Errorf("chain of trust validation failed: %w", err)
	}

	// Verify the signature
	if err := ctv.validator.VerifyRRSIG(rrsig, rrset, dnskey); err != nil {
		return fmt.Errorf("RRSIG verification failed: %w", err)
	}

	return nil
}

// walkChain recursively walks the chain of trust upward.
func (ctv *ChainOfTrustValidator) walkChain(
	ctx context.Context,
	zone string,
	keyTag uint16,
	algorithm uint8,
	depth int,
) (*dns.DNSKEY, error) {
	// Prevent infinite recursion
	if depth > ctv.maxChainLen {
		return nil, fmt.Errorf("%w (depth > %d)", ErrChainTooLong, ctv.maxChainLen)
	}

	// Check cache first
	if cachedKey := ctv.checkCachedKey(zone, keyTag, algorithm); cachedKey != nil {
		return cachedKey, nil
	}

	// Fetch and find target key
	targetKey, err := ctv.fetchAndFindKey(ctx, zone, keyTag, algorithm)
	if err != nil {
		return nil, err
	}

	// Handle root zone validation
	if zone == "." {
		return ctv.validateRootZoneKey(targetKey, keyTag)
	}

	// Validate non-root zone via parent
	return ctv.validateViaParent(ctx, zone, keyTag, algorithm, targetKey, depth)
}

// checkCachedKey checks if a validated key exists in cache.
func (ctv *ChainOfTrustValidator) checkCachedKey(zone string, keyTag uint16, algorithm uint8) *dns.DNSKEY {
	if cachedKey := ctv.keyCache.Get(zone, keyTag, algorithm); cachedKey != nil {
		if ctv.keyCache.IsValidated(zone, keyTag, algorithm) {
			return cachedKey
		}
	}

	return nil
}

// fetchAndFindKey fetches DNSKEY records and finds the requested key.
func (ctv *ChainOfTrustValidator) fetchAndFindKey(
	ctx context.Context,
	zone string,
	keyTag uint16,
	algorithm uint8,
) (*dns.DNSKEY, error) {
	dnskeys, err := ctv.keyFetcher.FetchDNSKEY(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DNSKEY for %s: %w", zone, err)
	}

	for _, key := range dnskeys {
		if key.KeyTag() == keyTag && key.Algorithm == algorithm {
			return key, nil
		}
	}

	return nil, fmt.Errorf("%w: DNSKEY %d not found in zone %s", ErrDNSKEYNotFoundInZone, keyTag, zone)
}

// validateRootZoneKey validates a root zone key against trust anchors.
func (ctv *ChainOfTrustValidator) validateRootZoneKey(targetKey *dns.DNSKEY, keyTag uint16) (*dns.DNSKEY, error) {
	ta := ctv.validator.GetTrustAnchor(".", targetKey.KeyTag())
	if ta == nil {
		return nil, fmt.Errorf("%w: root DNSKEY %d not in trust anchors", ErrRootDNSKEYNotInTrustAnchor, keyTag)
	}

	if ta.Algorithm != targetKey.Algorithm || ta.PublicKey != targetKey.PublicKey {
		return nil, ErrRootDNSKEYMismatch
	}

	ctv.keyCache.Add(targetKey, true)

	return targetKey, nil
}

// validateViaParent validates a zone's key via parent zone delegation.
func (ctv *ChainOfTrustValidator) validateViaParent(
	ctx context.Context,
	zone string,
	keyTag uint16,
	algorithm uint8,
	targetKey *dns.DNSKEY,
	depth int,
) (*dns.DNSKEY, error) {
	// Fetch and validate DS records
	if err := ctv.fetchAndValidateDS(ctx, zone, keyTag, algorithm, targetKey); err != nil {
		return nil, err
	}

	// Validate parent zone
	parent := getParentZone(zone)
	if err := ctv.validateParentZone(ctx, parent, depth); err != nil {
		return nil, err
	}

	// DS is validated via parent, so our key is validated
	ctv.keyCache.Add(targetKey, true)

	return targetKey, nil
}

// fetchAndValidateDS fetches DS records and validates the DNSKEY against them.
func (ctv *ChainOfTrustValidator) fetchAndValidateDS(
	ctx context.Context,
	zone string,
	keyTag uint16,
	algorithm uint8,
	targetKey *dns.DNSKEY,
) error {
	parent := getParentZone(zone)
	if parent == "" {
		return fmt.Errorf("%w: %s", ErrNoParentZone, zone)
	}

	dsRecords, err := ctv.keyFetcher.FetchDS(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to fetch DS for %s: %w", zone, err)
	}

	if len(dsRecords) == 0 {
		return fmt.Errorf("%w: %s", ErrNoDSRecordsFound, zone)
	}

	// Find matching DS record
	for _, ds := range dsRecords {
		if ds.KeyTag == keyTag && ds.Algorithm == algorithm {
			if err := ValidateDNSKEYWithDS(targetKey, ds); err != nil {
				return fmt.Errorf("DNSKEY validation failed: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("%w: DNSKEY %d in zone %s", ErrNoMatchingDSRecord, keyTag, zone)
}

// validateParentZone validates the parent zone's KSK.
func (ctv *ChainOfTrustValidator) validateParentZone(ctx context.Context, parent string, depth int) error {
	parentKeys, err := ctv.keyFetcher.FetchDNSKEY(ctx, parent)
	if err != nil {
		return fmt.Errorf("failed to fetch parent DNSKEY for %s: %w", parent, err)
	}

	parentKSKs := GetActiveKSKs(parentKeys)
	if len(parentKSKs) == 0 {
		return fmt.Errorf("%w: %s", ErrNoKSKsInParentZone, parent)
	}

	// Validate parent's KSK (recursive call)
	_, err = ctv.walkChain(ctx, parent, parentKSKs[0].KeyTag(), parentKSKs[0].Algorithm, depth+1)
	if err != nil {
		return fmt.Errorf("failed to validate parent zone %s: %w", parent, err)
	}

	return nil
}

// getParentZone returns the parent zone of a given zone.
func getParentZone(zone string) string {
	zone = dns.Fqdn(zone)

	// Root has no parent
	if zone == "." {
		return ""
	}

	// Remove first label
	parts := strings.SplitN(zone, ".", zonePartsMaxSplit)
	if len(parts) < zonePartsMaxSplit || parts[1] == "" {
		// TLD, parent is root
		return "."
	}

	return parts[1]
}

// ValidateDelegation validates a delegation from parent to child.
func ValidateDelegation(parentZone, childZone string, dsRecords []*dns.DS, childKeys []*dns.DNSKEY) error {
	if len(dsRecords) == 0 {
		return ErrNoDSRecordsForDelegation
	}

	if len(childKeys) == 0 {
		return ErrNoDNSKEYForChildZone
	}

	// At least one DS must match a child KSK
	if !findMatchingDSKey(dsRecords, childKeys) {
		return fmt.Errorf("%w in delegation from %s to %s", ErrNoMatchingDNSKEYForDS, parentZone, childZone)
	}

	return nil
}

// findMatchingDSKey searches for a matching DNSKEY for any DS record.
func findMatchingDSKey(dsRecords []*dns.DS, childKeys []*dns.DNSKEY) bool {
	for _, ds := range dsRecords {
		if matchesDSRecord(ds, childKeys) {
			return true
		}
	}

	return false
}

// matchesDSRecord checks if any child KSK matches the DS record.
func matchesDSRecord(ds *dns.DS, childKeys []*dns.DNSKEY) bool {
	for _, key := range childKeys {
		if !IsKSK(key) {
			continue
		}

		if key.KeyTag() == ds.KeyTag && key.Algorithm == ds.Algorithm {
			if err := ValidateDNSKEYWithDS(key, ds); err == nil {
				return true
			}
		}
	}

	return false
}

// BuildChainPath returns the list of zones in the chain from leaf to root.
func BuildChainPath(zone string) []string {
	zone = dns.Fqdn(zone)
	path := []string{zone}

	current := zone
	for current != "." {
		parent := getParentZone(current)
		if parent == "" {
			break
		}
		path = append(path, parent)
		current = parent
	}

	return path
}
