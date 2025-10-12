package dnssec

import (
	"crypto/sha1" //nolint:gosec // SHA1 required for NSEC3 per RFC 5155
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// NSEC3Validator validates NSEC3 records for authenticated denial of existence.
type NSEC3Validator struct {
	validator *Validator
}

// NewNSEC3Validator creates a new NSEC3 validator.
func NewNSEC3Validator(validator *Validator) *NSEC3Validator {
	return &NSEC3Validator{
		validator: validator,
	}
}

// ValidateNXDOMAIN validates that a name does not exist using NSEC3
// RFC 5155 §8.4: Closest Encloser Proof.
func (n3v *NSEC3Validator) ValidateNXDOMAIN(qname string, nsec3Records []*dns.NSEC3) error {
	if len(nsec3Records) == 0 {
		return errors.New("no NSEC3 records provided for NXDOMAIN proof")
	}

	qname = dns.Fqdn(strings.ToLower(qname))

	// Get the first NSEC3 record to use for hashing
	firstNSEC3 := nsec3Records[0]

	// NXDOMAIN proof requires:
	// 1. Closest encloser proof (name exists)
	// 2. Next closer name proof (name doesn't exist)
	// 3. Wildcard proof (no wildcard match)

	// Find closest encloser
	closestEncloser, err := n3v.findClosestEncloser(qname, nsec3Records, firstNSEC3)
	if err != nil {
		return fmt.Errorf("failed to find closest encloser: %w", err)
	}

	// Verify next closer doesn't exist
	nsec3param := extractNSEC3Params(firstNSEC3)
	nextCloser := getNextCloser(qname, closestEncloser)
	if err := n3v.proveNameDoesNotExist(nextCloser, nsec3Records, nsec3param); err != nil {
		return fmt.Errorf("failed to prove next closer doesn't exist: %w", err)
	}

	// Verify wildcard doesn't exist
	wildcard := ".*" + closestEncloser
	if err := n3v.proveNameDoesNotExist(wildcard, nsec3Records, nsec3param); err != nil {
		return fmt.Errorf("failed to prove wildcard doesn't exist: %w", err)
	}

	return nil
}

// ValidateNODATA validates that a name exists but has no data for the requested type
// RFC 5155 §8.5-8.7: NODATA proofs.
func (n3v *NSEC3Validator) ValidateNODATA(qname string, qtype uint16, nsec3Records []*dns.NSEC3) error {
	if len(nsec3Records) == 0 {
		return errors.New("no NSEC3 records provided for NODATA proof")
	}

	qname = dns.Fqdn(strings.ToLower(qname))

	// Hash the query name using first NSEC3 record parameters
	hashedName := hashName(qname, nsec3Records[0])

	// Find NSEC3 record matching the hashed name
	for _, nsec3 := range nsec3Records {
		owner := extractHashFromNSEC3Owner(nsec3.Hdr.Name)

		if owner == hashedName {
			// Exact match - check type bitmap
			if hasType(nsec3.TypeBitMap, qtype) {
				return fmt.Errorf("NSEC3 shows %s has type %d, inconsistent with NODATA", qname, qtype)
			}

			// NSEC3 proves the name exists but doesn't have this type
			return nil
		}
	}

	return fmt.Errorf("no matching NSEC3 record found for %s (hash: %s)", qname, hashedName)
}

// proveNameDoesNotExist proves a name doesn't exist using NSEC3.
func (n3v *NSEC3Validator) proveNameDoesNotExist(name string, nsec3Records []*dns.NSEC3, param *nsec3Params) error {
	name = dns.Fqdn(strings.ToLower(name))
	hashedName := hashNameWithParams(name, param)

	// Find NSEC3 that covers the hashed name
	for _, nsec3 := range nsec3Records {
		owner := extractHashFromNSEC3Owner(nsec3.Hdr.Name)
		next := nsec3.NextDomain // Already a base32hex string

		if coversHash(owner, next, hashedName) {
			// This NSEC3 covers the name - proves it doesn't exist
			return nil
		}
	}

	return fmt.Errorf("no NSEC3 covers hashed name %s", hashedName)
}

// findClosestEncloser finds the closest enclosing name that exists.
func (n3v *NSEC3Validator) findClosestEncloser(
	qname string,
	nsec3Records []*dns.NSEC3,
	nsec3 *dns.NSEC3,
) (string, error) {
	qname = dns.Fqdn(strings.ToLower(qname))

	// Start from the query name and walk up the tree
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")

	for i := range labels {
		testName := strings.Join(labels[i:], ".") + "."
		hashedName := hashName(testName, nsec3)

		// Check if this name exists (has an exact NSEC3 match)
		for _, rec := range nsec3Records {
			owner := extractHashFromNSEC3Owner(rec.Hdr.Name)
			if owner == hashedName {
				// Found closest encloser
				return testName, nil
			}
		}
	}

	return "", fmt.Errorf("no closest encloser found for %s", qname)
}

// getNextCloser returns the next closer name to the closest encloser.
func getNextCloser(qname, closestEncloser string) string {
	qname = dns.Fqdn(strings.ToLower(qname))
	closestEncloser = dns.Fqdn(strings.ToLower(closestEncloser))

	// The next closer is one label longer than closest encloser
	qLabels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	ceLabels := strings.Split(strings.TrimSuffix(closestEncloser, "."), ".")

	if len(qLabels) <= len(ceLabels) {
		return qname
	}

	// Take one more label from qname
	return strings.Join(qLabels[len(qLabels)-len(ceLabels)-1:], ".") + "."
}

// coversHash checks if an NSEC3 record covers a hashed name.
func coversHash(owner, next, hash string) bool {
	// NSEC3 uses base32hex encoding (no padding)
	// Comparison is lexicographic on the hash values

	if owner == hash {
		return false // Exact match, not covered
	}

	if owner < next {
		// Normal case: owner < next
		return owner < hash && hash < next
	}
	// Wrap-around case: next < owner (last NSEC3 in zone)
	return hash > owner || hash < next
}

// nsec3Params holds NSEC3 hash parameters.
type nsec3Params struct {
	HashAlg    uint8
	Flags      uint8
	Iterations uint16
	Salt       string
}

// extractNSEC3Params extracts hash parameters from an NSEC3 record.
func extractNSEC3Params(nsec3 *dns.NSEC3) *nsec3Params {
	return &nsec3Params{
		HashAlg:    nsec3.Hash,
		Flags:      nsec3.Flags,
		Iterations: nsec3.Iterations,
		Salt:       nsec3.Salt,
	}
}

// hashName hashes a domain name using NSEC3 parameters from an NSEC3 record.
func hashName(name string, nsec3 *dns.NSEC3) string {
	param := extractNSEC3Params(nsec3)

	return hashNameWithParams(name, param)
}

// hashNameWithParams hashes a domain name using NSEC3 parameters.
func hashNameWithParams(name string, param *nsec3Params) string {
	name = dns.Fqdn(strings.ToLower(name))

	// Convert name to wire format
	wireData := canonicalName(name)

	// Decode salt from hex
	salt := []byte{}
	if param.Salt != "-" && param.Salt != "" {
		// Salt is hex-encoded
		salt = []byte(param.Salt)
	}

	// Hash according to algorithm (only SHA-1 is currently defined)
	var hash []byte
	switch param.HashAlg {
	case dns.SHA1:
		hash = nsec3Hash(wireData, salt, param.Iterations)
	default:
		// Unsupported algorithm, return empty
		return ""
	}

	// Encode hash in base32hex (no padding)
	return base32Encode(hash)
}

// nsec3Hash performs NSEC3 hash with iterations (RFC 5155 §5).
func nsec3Hash(data, salt []byte, iterations uint16) []byte {
	// IH(salt, x, 0) = H(x || salt)
	// IH(salt, x, k) = H(IH(salt, x, k-1) || salt), k > 0

	h := sha1.New() //nolint:gosec // SHA1 required for NSEC3 per RFC 5155
	h.Write(data)
	h.Write(salt)
	digest := h.Sum(nil)

	// Iterate
	for range iterations {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}

	return digest
}

// base32Encode encodes data in base32hex without padding.
func base32Encode(data []byte) string {
	// RFC 4648 base32hex alphabet (extended hex)
	encoder := base32.HexEncoding.WithPadding(base32.NoPadding)

	return strings.ToUpper(encoder.EncodeToString(data))
}

// extractHashFromNSEC3Owner extracts the hash portion from an NSEC3 owner name
// NSEC3 owner format: <hash>.<zone>.
func extractHashFromNSEC3Owner(owner string) string {
	owner = dns.Fqdn(strings.ToLower(owner))
	parts := strings.SplitN(owner, ".", 2)
	if len(parts) < 1 {
		return ""
	}

	return strings.ToUpper(parts[0])
}

// ExtractNSEC3Records extracts NSEC3 records from a DNS message.
func ExtractNSEC3Records(msg *dns.Msg) []*dns.NSEC3 {
	nsec3s := make([]*dns.NSEC3, 0)

	// Check authority section
	for _, rr := range msg.Ns {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, nsec3)
		}
	}

	// Check answer section
	for _, rr := range msg.Answer {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, nsec3)
		}
	}

	return nsec3s
}

// IsOptOut checks if NSEC3 opt-out is enabled.
func IsOptOut(nsec3 *dns.NSEC3) bool {
	// Bit 0 of flags is opt-out flag
	return nsec3.Flags&0x01 == 0x01
}

// ValidateNSEC3Params validates NSEC3 parameters are acceptable.
func ValidateNSEC3Params(nsec3 *dns.NSEC3) error {
	// Check hash algorithm (only SHA-1 is defined)
	if nsec3.Hash != dns.SHA1 {
		return fmt.Errorf("unsupported NSEC3 hash algorithm: %d", nsec3.Hash)
	}

	// Check iteration count (should be reasonable to prevent DoS)
	maxIterations := uint16(150) // Common limit
	if nsec3.Iterations > maxIterations {
		return fmt.Errorf("NSEC3 iteration count too high: %d > %d", nsec3.Iterations, maxIterations)
	}

	// Salt length should be reasonable
	maxSaltLen := 255
	if len(nsec3.Salt) > maxSaltLen {
		return fmt.Errorf("NSEC3 salt too long: %d > %d", len(nsec3.Salt), maxSaltLen)
	}

	return nil
}
