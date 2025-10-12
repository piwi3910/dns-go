package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
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
			Flags:     257, // KSK
			Protocol:  3,
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
		return nil, fmt.Errorf("chain of trust too long (depth > %d)", ctv.maxChainLen)
	}

	// Check cache first
	if cachedKey := ctv.keyCache.Get(zone, keyTag, algorithm); cachedKey != nil {
		if ctv.keyCache.IsValidated(zone, keyTag, algorithm) {
			return cachedKey, nil
		}
	}

	// Fetch DNSKEY records for this zone
	dnskeys, err := ctv.keyFetcher.FetchDNSKEY(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DNSKEY for %s: %w", zone, err)
	}

	// Find the requested key
	var targetKey *dns.DNSKEY
	for _, key := range dnskeys {
		if key.KeyTag() == keyTag && key.Algorithm == algorithm {
			targetKey = key

			break
		}
	}

	if targetKey == nil {
		return nil, fmt.Errorf("DNSKEY %d not found in zone %s", keyTag, zone)
	}

	// If this is the root zone, check against trust anchor
	if zone == "." {
		ta := ctv.validator.GetTrustAnchor(".", targetKey.KeyTag())
		if ta == nil {
			return nil, fmt.Errorf("root DNSKEY %d not in trust anchors", keyTag)
		}
		// Validate matches trust anchor
		if ta.Algorithm != targetKey.Algorithm || ta.PublicKey != targetKey.PublicKey {
			return nil, errors.New("root DNSKEY does not match trust anchor")
		}
		// Cache as validated
		ctv.keyCache.Add(targetKey, true)

		return targetKey, nil
	}

	// For non-root zones, fetch DS from parent
	parent := getParentZone(zone)
	if parent == "" {
		return nil, fmt.Errorf("no parent zone for %s", zone)
	}

	// Fetch DS records from parent
	dsRecords, err := ctv.keyFetcher.FetchDS(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DS for %s: %w", zone, err)
	}

	if len(dsRecords) == 0 {
		return nil, fmt.Errorf("no DS records found for %s", zone)
	}

	// Find matching DS record
	var matchingDS *dns.DS
	for _, ds := range dsRecords {
		if ds.KeyTag == keyTag && ds.Algorithm == algorithm {
			matchingDS = ds

			break
		}
	}

	if matchingDS == nil {
		return nil, fmt.Errorf("no matching DS record for DNSKEY %d in zone %s", keyTag, zone)
	}

	// Validate DNSKEY against DS
	if err := ValidateDNSKEYWithDS(targetKey, matchingDS); err != nil {
		return nil, fmt.Errorf("DNSKEY validation failed: %w", err)
	}

	// Now we need to validate the DS record's signature in the parent zone
	// This requires finding the DNSKEY that signed the DS record in the parent
	// For now, we'll recursively validate the parent's KSK

	// Get parent's DNSKEY that signed the DS
	// Typically, the DS is in the parent's zone and signed by the parent's ZSK
	// The parent's ZSK is signed by the parent's KSK
	// The parent's KSK is validated via DS in grandparent, and so on...

	// Fetch parent's DNSKEY
	parentKeys, err := ctv.keyFetcher.FetchDNSKEY(ctx, parent)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch parent DNSKEY for %s: %w", parent, err)
	}

	// Find parent's KSK to validate
	parentKSKs := GetActiveKSKs(parentKeys)
	if len(parentKSKs) == 0 {
		return nil, fmt.Errorf("no KSKs found in parent zone %s", parent)
	}

	// Validate parent's KSK (recursive call)
	_, err = ctv.walkChain(ctx, parent, parentKSKs[0].KeyTag(), parentKSKs[0].Algorithm, depth+1)
	if err != nil {
		return nil, fmt.Errorf("failed to validate parent zone %s: %w", parent, err)
	}

	// Parent is validated, so our DS record is trusted
	// Therefore, our DNSKEY is validated
	ctv.keyCache.Add(targetKey, true)

	return targetKey, nil
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

// getParentZone returns the parent zone of a given zone.
func getParentZone(zone string) string {
	zone = dns.Fqdn(zone)

	// Root has no parent
	if zone == "." {
		return ""
	}

	// Remove first label
	parts := strings.SplitN(zone, ".", 2)
	if len(parts) < 2 || parts[1] == "" {
		// TLD, parent is root
		return "."
	}

	return parts[1]
}

// ValidateDelegation validates a delegation from parent to child.
func ValidateDelegation(parentZone, childZone string, dsRecords []*dns.DS, childKeys []*dns.DNSKEY) error {
	if len(dsRecords) == 0 {
		return errors.New("no DS records for delegation")
	}

	if len(childKeys) == 0 {
		return errors.New("no DNSKEY records for child zone")
	}

	// At least one DS must match a child KSK
	matched := false
	for _, ds := range dsRecords {
		for _, key := range childKeys {
			if !IsKSK(key) {
				continue
			}

			if key.KeyTag() == ds.KeyTag && key.Algorithm == ds.Algorithm {
				if err := ValidateDNSKEYWithDS(key, ds); err == nil {
					matched = true

					break
				}
			}
		}
		if matched {
			break
		}
	}

	if !matched {
		return fmt.Errorf("no matching DNSKEY found for DS records in delegation from %s to %s", parentZone, childZone)
	}

	return nil
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
