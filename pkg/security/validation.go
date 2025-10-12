package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// QueryValidator validates DNS queries for security issues.
type QueryValidator struct {
	config ValidationConfig
}

// ValidationConfig holds validation configuration.
type ValidationConfig struct {
	// MaxQuestionCount limits number of questions per query
	MaxQuestionCount int

	// MaxDomainLength limits domain name length (RFC 1035: 255)
	MaxDomainLength int

	// MaxLabelLength limits individual label length (RFC 1035: 63)
	MaxLabelLength int

	// MaxQuerySize limits total query size in bytes
	MaxQuerySize int

	// RejectPrivateAddresses rejects queries for private IP ranges
	RejectPrivateAddresses bool

	// RandomizeSourcePort enables source port randomization (RFC 5452)
	RandomizeSourcePort bool

	// ValidateQNAME validates query names
	ValidateQNAME bool
}

// DefaultValidationConfig returns sensible defaults.
func DefaultValidationConfig() ValidationConfig {
	return ValidationConfig{
		MaxQuestionCount:       1,     // RFC 1035: typically 1 question
		MaxDomainLength:        255,   // RFC 1035 limit
		MaxLabelLength:         63,    // RFC 1035 limit
		MaxQuerySize:           4096,  // Reasonable max
		RejectPrivateAddresses: false, // Allow by default (for internal DNS)
		RandomizeSourcePort:    true,  // RFC 5452 recommendation
		ValidateQNAME:          true,  // Validate domain names
	}
}

// NewQueryValidator creates a new query validator.
func NewQueryValidator(config ValidationConfig) *QueryValidator {
	return &QueryValidator{
		config: config,
	}
}

// ValidateQuery validates a DNS query for security issues.
func (qv *QueryValidator) ValidateQuery(msg *dns.Msg) error {
	if msg == nil {
		return errors.New("nil message")
	}

	// Validate question count
	if len(msg.Question) > qv.config.MaxQuestionCount {
		return fmt.Errorf("too many questions: %d (max: %d)",
			len(msg.Question), qv.config.MaxQuestionCount)
	}

	if len(msg.Question) == 0 {
		return errors.New("no questions in query")
	}

	// Validate each question
	for i, q := range msg.Question {
		if err := qv.validateQuestion(&q); err != nil {
			return fmt.Errorf("question %d invalid: %w", i, err)
		}
	}

	return nil
}

// validateQuestion validates a single question.
func (qv *QueryValidator) validateQuestion(q *dns.Question) error {
	if !qv.config.ValidateQNAME {
		return nil
	}

	// Validate domain name length
	if len(q.Name) > qv.config.MaxDomainLength {
		return fmt.Errorf("domain name too long: %d bytes (max: %d)",
			len(q.Name), qv.config.MaxDomainLength)
	}

	// Validate individual labels
	labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
	for _, label := range labels {
		if len(label) > qv.config.MaxLabelLength {
			return fmt.Errorf("label too long: %s (%d bytes, max: %d)",
				label, len(label), qv.config.MaxLabelLength)
		}

		// Validate label characters (basic validation)
		if !isValidLabel(label) {
			return fmt.Errorf("invalid label: %s", label)
		}
	}

	// Check for private address queries if configured
	if qv.config.RejectPrivateAddresses && q.Qtype == dns.TypePTR {
		if isPrivateReverseQuery(q.Name) {
			return fmt.Errorf("private address query rejected: %s", q.Name)
		}
	}

	return nil
}

// isValidLabel checks if a DNS label contains valid characters.
func isValidLabel(label string) bool {
	if len(label) == 0 {
		return true // Empty labels are OK (for root)
	}

	// RFC 1035: labels can contain letters, digits, and hyphens
	// Must not start or end with hyphen
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, c := range label {
		if (c < 'a' || c > 'z') &&
			(c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') &&
			c != '-' && c != '_' {
			return false
		}
	}

	return true
}

// isPrivateReverseQuery checks if a PTR query is for a private IP range.
func isPrivateReverseQuery(name string) bool {
	// Check for common private IP reverse zones
	privateZones := []string{
		"10.in-addr.arpa.",
		"168.192.in-addr.arpa.", // 192.168.x.x
		"16.172.in-addr.arpa.",  // 172.16.x.x - 172.31.x.x
		"d.f.ip6.arpa.",         // IPv6 fd00::/8
	}

	for _, zone := range privateZones {
		if strings.HasSuffix(name, zone) {
			return true
		}
	}

	return false
}

// CachePoisoningProtector implements protections against cache poisoning.
type CachePoisoningProtector struct {
	config CachePoisoningConfig
}

// CachePoisoningConfig holds cache poisoning protection configuration.
type CachePoisoningConfig struct {
	// ValidateResponseIDs checks that response IDs match queries
	ValidateResponseIDs bool

	// ValidateQuestionSection ensures question matches in responses
	ValidateQuestionSection bool

	// RejectMismatchedResponses rejects responses that don't match queries
	RejectMismatchedResponses bool

	// RandomizeQueryIDs enables query ID randomization
	RandomizeQueryIDs bool

	// ValidateBailiwick checks that responses are authoritative for the domain
	ValidateBailiwick bool
}

// DefaultCachePoisoningConfig returns sensible defaults.
func DefaultCachePoisoningConfig() CachePoisoningConfig {
	return CachePoisoningConfig{
		ValidateResponseIDs:       true,
		ValidateQuestionSection:   true,
		RejectMismatchedResponses: true,
		RandomizeQueryIDs:         true,
		ValidateBailiwick:         false, // More complex, disabled by default
	}
}

// NewCachePoisoningProtector creates a new cache poisoning protector.
func NewCachePoisoningProtector(config CachePoisoningConfig) *CachePoisoningProtector {
	return &CachePoisoningProtector{
		config: config,
	}
}

// ValidateResponse validates a DNS response against the original query.
func (cpp *CachePoisoningProtector) ValidateResponse(query, response *dns.Msg) error {
	if query == nil || response == nil {
		return errors.New("nil query or response")
	}

	// Validate response ID matches query ID
	if cpp.config.ValidateResponseIDs && query.Id != response.Id {
		return fmt.Errorf("response ID mismatch: query=%d, response=%d",
			query.Id, response.Id)
	}

	// Validate question section matches
	if cpp.config.ValidateQuestionSection {
		if len(query.Question) != len(response.Question) {
			return fmt.Errorf("question count mismatch: query=%d, response=%d",
				len(query.Question), len(response.Question))
		}

		if len(query.Question) > 0 && len(response.Question) > 0 {
			if err := cpp.validateQuestionMatch(&query.Question[0], &response.Question[0]); err != nil {
				return err
			}
		}
	}

	// Validate bailiwick if configured
	if cpp.config.ValidateBailiwick && len(query.Question) > 0 {
		if err := cpp.validateBailiwick(&query.Question[0], response); err != nil {
			return fmt.Errorf("bailiwick validation failed: %w", err)
		}
	}

	return nil
}

// validateQuestionMatch validates that query and response questions match.
func (cpp *CachePoisoningProtector) validateQuestionMatch(q1, q2 *dns.Question) error {
	if !strings.EqualFold(q1.Name, q2.Name) {
		return fmt.Errorf("question name mismatch: query=%s, response=%s",
			q1.Name, q2.Name)
	}

	if q1.Qtype != q2.Qtype {
		return fmt.Errorf("question type mismatch: query=%d, response=%d",
			q1.Qtype, q2.Qtype)
	}

	if q1.Qclass != q2.Qclass {
		return fmt.Errorf("question class mismatch: query=%d, response=%d",
			q1.Qclass, q2.Qclass)
	}

	return nil
}

// validateBailiwick checks that response records are within the queried domain's authority.
func (cpp *CachePoisoningProtector) validateBailiwick(question *dns.Question, response *dns.Msg) error {
	qname := strings.ToLower(question.Name)

	// Check all answer records
	for _, rr := range response.Answer {
		rrName := strings.ToLower(rr.Header().Name)
		if !isSubdomainOf(rrName, qname) {
			return fmt.Errorf("answer record %s not in bailiwick of %s", rrName, qname)
		}
	}

	return nil
}

// isSubdomainOf checks if name is a subdomain of (or equal to) parent.
func isSubdomainOf(name, parent string) bool {
	if name == parent {
		return true
	}

	return strings.HasSuffix(name, "."+parent)
}

// RandomizeQueryID generates a random query ID for DNS messages.
// Panics if random number generation fails (crypto failure).
func RandomizeQueryID() uint16 {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		// Crypto RNG failure is a critical security issue
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}

	return uint16(id[0])<<8 | uint16(id[1])
}

// RandomizeSourcePort generates a random source port (RFC 5452)
// Returns a port in the range 1024-65535.
// Panics if random number generation fails (crypto failure).
func RandomizeSourcePort() int {
	var port [2]byte
	if _, err := rand.Read(port[:]); err != nil {
		// Crypto RNG failure is a critical security issue
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	p := int(port[0])<<8 | int(port[1])

	// Ensure port is in ephemeral range (1024-65535)
	if p < 1024 {
		p += 1024
	}

	return p
}

// ValidateResponseSize checks if a response size is reasonable.
func ValidateResponseSize(size int, maxSize int) error {
	if size > maxSize {
		return fmt.Errorf("response too large: %d bytes (max: %d)", size, maxSize)
	}
	if size < 12 {
		return fmt.Errorf("response too small: %d bytes (min: 12)", size)
	}

	return nil
}
