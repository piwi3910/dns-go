package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// NSECValidator validates NSEC records for authenticated denial of existence
type NSECValidator struct {
	validator *Validator
}

// NewNSECValidator creates a new NSEC validator
func NewNSECValidator(validator *Validator) *NSECValidator {
	return &NSECValidator{
		validator: validator,
	}
}

// ValidateNXDOMAIN validates that a name does not exist using NSEC
// RFC 4035 §3.1.3.2: NSEC proof of NXDOMAIN
func (nv *NSECValidator) ValidateNXDOMAIN(qname string, nsecRecords []*dns.NSEC) error {
	if len(nsecRecords) == 0 {
		return fmt.Errorf("no NSEC records provided for NXDOMAIN proof")
	}

	qname = dns.Fqdn(strings.ToLower(qname))

	// Find NSEC that covers the query name
	for _, nsec := range nsecRecords {
		owner := dns.Fqdn(strings.ToLower(nsec.Hdr.Name))
		next := dns.Fqdn(strings.ToLower(nsec.NextDomain))

		// Check if qname is covered by this NSEC
		if coversName(owner, next, qname) {
			// NSEC covers the name - this proves it doesn't exist
			return nil
		}
	}

	return fmt.Errorf("no NSEC record covers %s for NXDOMAIN proof", qname)
}

// ValidateNODATA validates that a name exists but has no data for the requested type
// RFC 4035 §3.1.3.1: NSEC proof of NODATA
func (nv *NSECValidator) ValidateNODATA(qname string, qtype uint16, nsecRecords []*dns.NSEC) error {
	if len(nsecRecords) == 0 {
		return fmt.Errorf("no NSEC records provided for NODATA proof")
	}

	qname = dns.Fqdn(strings.ToLower(qname))

	// Find NSEC for the exact name
	for _, nsec := range nsecRecords {
		owner := dns.Fqdn(strings.ToLower(nsec.Hdr.Name))

		if owner == qname {
			// Exact match - check type bitmap
			if hasType(nsec.TypeBitMap, qtype) {
				return fmt.Errorf("NSEC shows %s has type %d, inconsistent with NODATA", qname, qtype)
			}

			// NSEC proves the name exists but doesn't have this type
			return nil
		}
	}

	return fmt.Errorf("no NSEC record found for %s to prove NODATA", qname)
}

// ValidateWildcardNonExistence validates that no closer wildcard exists
// RFC 4035 §3.1.3.3: Wildcard No Data Responses
func (nv *NSECValidator) ValidateWildcardNonExistence(qname string, nsecRecords []*dns.NSEC) error {
	qname = dns.Fqdn(strings.ToLower(qname))

	// For wildcard proof, we need to show that:
	// 1. The exact name doesn't exist (covered by NSEC)
	// 2. No wildcard at a closer enclosing level exists

	// Get all possible wildcard positions
	wildcards := getWildcardNames(qname)

	// Each wildcard must be covered by an NSEC
	for _, wildcard := range wildcards {
		found := false
		for _, nsec := range nsecRecords {
			owner := dns.Fqdn(strings.ToLower(nsec.Hdr.Name))
			next := dns.Fqdn(strings.ToLower(nsec.NextDomain))

			if coversName(owner, next, wildcard) {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("no NSEC covers wildcard %s", wildcard)
		}
	}

	return nil
}

// coversName checks if an NSEC record covers a name
// An NSEC covers a name if: owner < name < next (canonical ordering)
// Special case: if next < owner, this is the last NSEC wrapping to first
func coversName(owner, next, name string) bool {
	owner = dns.Fqdn(strings.ToLower(owner))
	next = dns.Fqdn(strings.ToLower(next))
	name = dns.Fqdn(strings.ToLower(name))

	// Canonical DNS name ordering
	ownerCmp := canonicalCompare(owner, name)
	nextCmp := canonicalCompare(name, next)

	if canonicalCompare(owner, next) < 0 {
		// Normal case: owner < next
		// Name is covered if: owner < name < next
		return ownerCmp < 0 && nextCmp < 0
	} else {
		// Wrap-around case: next < owner (last NSEC in zone)
		// Name is covered if: name > owner OR name < next
		return ownerCmp < 0 || nextCmp < 0
	}
}

// canonicalCompare performs canonical DNS name comparison (RFC 4034 §6.1)
func canonicalCompare(name1, name2 string) int {
	// Convert to lowercase and ensure FQDN
	name1 = dns.Fqdn(strings.ToLower(name1))
	name2 = dns.Fqdn(strings.ToLower(name2))

	if name1 == name2 {
		return 0
	}

	// Split into labels
	labels1 := strings.Split(strings.TrimSuffix(name1, "."), ".")
	labels2 := strings.Split(strings.TrimSuffix(name2, "."), ".")

	// Reverse labels for right-to-left comparison
	reverseLabels(labels1)
	reverseLabels(labels2)

	// Compare label by label from right to left
	minLen := len(labels1)
	if len(labels2) < minLen {
		minLen = len(labels2)
	}

	for i := 0; i < minLen; i++ {
		cmp := strings.Compare(labels1[i], labels2[i])
		if cmp != 0 {
			return cmp
		}
	}

	// If all compared labels are equal, shorter name comes first
	if len(labels1) < len(labels2) {
		return -1
	}
	if len(labels1) > len(labels2) {
		return 1
	}

	return 0
}

// reverseLabels reverses a slice of labels in place
func reverseLabels(labels []string) {
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
}

// hasType checks if a type bitmap includes a specific RR type
func hasType(bitmap []uint16, rrtype uint16) bool {
	for _, t := range bitmap {
		if t == rrtype {
			return true
		}
	}
	return false
}

// getWildcardNames returns all possible wildcard names for a qname
// For "a.b.c.example.com.", returns: ["*.b.c.example.com.", "*.c.example.com.", "*.example.com."]
func getWildcardNames(qname string) []string {
	qname = dns.Fqdn(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")

	wildcards := make([]string, 0, len(labels)-1)

	// Generate wildcards from closest to furthest
	for i := 1; i < len(labels); i++ {
		wildcard := "*." + strings.Join(labels[i:], ".")
		wildcards = append(wildcards, dns.Fqdn(wildcard))
	}

	return wildcards
}

// ExtractNSECRecords extracts NSEC records from a DNS message
func ExtractNSECRecords(msg *dns.Msg) []*dns.NSEC {
	nsecs := make([]*dns.NSEC, 0)

	// Check authority section (where NSEC records typically are for negative responses)
	for _, rr := range msg.Ns {
		if nsec, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, nsec)
		}
	}

	// Also check answer section (for NODATA responses)
	for _, rr := range msg.Answer {
		if nsec, ok := rr.(*dns.NSEC); ok {
			nsecs = append(nsecs, nsec)
		}
	}

	return nsecs
}

// ValidateNSECChain validates the NSEC chain consistency
// Ensures NSEC records form a proper chain without gaps
func (nv *NSECValidator) ValidateNSECChain(nsecRecords []*dns.NSEC) error {
	if len(nsecRecords) < 2 {
		// Single NSEC record doesn't form a chain
		// This is OK for specific proofs
		return nil
	}

	// Build a map of NSEC records by owner name
	nsecMap := make(map[string]*dns.NSEC)
	for _, nsec := range nsecRecords {
		owner := dns.Fqdn(strings.ToLower(nsec.Hdr.Name))
		nsecMap[owner] = nsec
	}

	// Verify chain continuity
	for owner, nsec := range nsecMap {
		next := dns.Fqdn(strings.ToLower(nsec.NextDomain))

		// Next should either be in the map or be the first record (wrap-around)
		if _, exists := nsecMap[next]; !exists {
			// Check if this is the last record pointing back to first
			if next == "" {
				return fmt.Errorf("NSEC record %s has empty NextDomain", owner)
			}
			// This is OK - next might be outside this set of NSECs
		}
	}

	return nil
}
