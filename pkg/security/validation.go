package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DNS validation constants (RFC 1035).
const (
	maxDomainNameLength  = 255  // RFC 1035 Section 2.3.4: max domain name length
	maxLabelLength       = 63   // RFC 1035 Section 2.3.4: max label length
	maxQuerySizeBytes    = 4096 // Reasonable maximum query size
	minDNSHeaderSize     = 12   // DNS header minimum size in bytes
	minEphemeralPort     = 1024 // Minimum ephemeral port number (RFC 6056)
	byteShift8           = 8    // Shift for second byte (bits 8-15)
)

// Package-level errors for DNS validation.
var (
	ErrNilMessage              = errors.New("nil message")
	ErrTooManyQuestions        = errors.New("too many questions")
	ErrNoQuestions             = errors.New("no questions in query")
	ErrDomainNameTooLong       = errors.New("domain name too long")
	ErrLabelTooLong            = errors.New("label too long")
	ErrInvalidLabel            = errors.New("invalid label")
	ErrPrivateAddressRejected  = errors.New("private address query rejected")
	ErrNilQueryOrResponse      = errors.New("nil query or response")
	ErrResponseIDMismatch      = errors.New("response ID mismatch")
	ErrQuestionCountMismatch   = errors.New("question count mismatch")
	ErrQuestionNameMismatch    = errors.New("question name mismatch")
	ErrQuestionTypeMismatch    = errors.New("question type mismatch")
	ErrQuestionClassMismatch   = errors.New("question class mismatch")
	ErrAnswerNotInBailiwick    = errors.New("answer record not in bailiwick")
	ErrResponseTooLarge        = errors.New("response too large")
	ErrResponseTooSmall        = errors.New("response too small")
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
		MaxQuestionCount:       1,                  // RFC 1035: typically 1 question
		MaxDomainLength:        maxDomainNameLength, // RFC 1035 limit
		MaxLabelLength:         maxLabelLength,     // RFC 1035 limit
		MaxQuerySize:           maxQuerySizeBytes,  // Reasonable max
		RejectPrivateAddresses: false,              // Allow by default (for internal DNS)
		RandomizeSourcePort:    true,               // RFC 5452 recommendation
		ValidateQNAME:          true,               // Validate domain names
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
		return ErrNilMessage
	}

	// Validate question count
	if len(msg.Question) > qv.config.MaxQuestionCount {
		return fmt.Errorf("%w: %d (max: %d)",
			ErrTooManyQuestions, len(msg.Question), qv.config.MaxQuestionCount)
	}

	if len(msg.Question) == 0 {
		return ErrNoQuestions
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
		return fmt.Errorf("%w: %d bytes (max: %d)",
			ErrDomainNameTooLong, len(q.Name), qv.config.MaxDomainLength)
	}

	// Validate individual labels
	labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
	for _, label := range labels {
		if len(label) > qv.config.MaxLabelLength {
			return fmt.Errorf("%w: %s (%d bytes, max: %d)",
				ErrLabelTooLong, label, len(label), qv.config.MaxLabelLength)
		}

		// Validate label characters (basic validation)
		if !isValidLabel(label) {
			return fmt.Errorf("%w: %s", ErrInvalidLabel, label)
		}
	}

	// Check for private address queries if configured
	if qv.config.RejectPrivateAddresses && q.Qtype == dns.TypePTR {
		if isPrivateReverseQuery(q.Name) {
			return fmt.Errorf("%w: %s", ErrPrivateAddressRejected, q.Name)
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
	if !isValidLabelBoundary(label) {
		return false
	}

	return containsOnlyValidLabelChars(label)
}

// isValidLabelBoundary checks that label doesn't start or end with hyphen.
func isValidLabelBoundary(label string) bool {
	return label[0] != '-' && label[len(label)-1] != '-'
}

// containsOnlyValidLabelChars checks if all characters in label are valid DNS characters.
func containsOnlyValidLabelChars(label string) bool {
	for _, c := range label {
		if !isValidDNSChar(c) {
			return false
		}
	}

	return true
}

// isValidDNSChar checks if a character is valid in a DNS label.
func isValidDNSChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_'
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
		return ErrNilQueryOrResponse
	}

	// Validate response ID
	if err := cpp.validateResponseID(query, response); err != nil {
		return err
	}

	// Validate question section
	if err := cpp.validateQuestionSection(query, response); err != nil {
		return err
	}

	// Validate bailiwick
	if err := cpp.validateBailiwickIfEnabled(query, response); err != nil {
		return err
	}

	return nil
}

// validateResponseID checks that response ID matches query ID.
func (cpp *CachePoisoningProtector) validateResponseID(query, response *dns.Msg) error {
	if cpp.config.ValidateResponseIDs && query.Id != response.Id {
		return fmt.Errorf("%w: query=%d, response=%d",
			ErrResponseIDMismatch, query.Id, response.Id)
	}

	return nil
}

// validateQuestionSection checks that question sections match.
func (cpp *CachePoisoningProtector) validateQuestionSection(query, response *dns.Msg) error {
	if !cpp.config.ValidateQuestionSection {
		return nil
	}

	if len(query.Question) != len(response.Question) {
		return fmt.Errorf("%w: query=%d, response=%d",
			ErrQuestionCountMismatch, len(query.Question), len(response.Question))
	}

	if len(query.Question) > 0 && len(response.Question) > 0 {
		if err := cpp.validateQuestionMatch(&query.Question[0], &response.Question[0]); err != nil {
			return err
		}
	}

	return nil
}

// validateBailiwickIfEnabled validates bailiwick if enabled in config.
func (cpp *CachePoisoningProtector) validateBailiwickIfEnabled(query, response *dns.Msg) error {
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
		return fmt.Errorf("%w: query=%s, response=%s",
			ErrQuestionNameMismatch, q1.Name, q2.Name)
	}

	if q1.Qtype != q2.Qtype {
		return fmt.Errorf("%w: query=%d, response=%d",
			ErrQuestionTypeMismatch, q1.Qtype, q2.Qtype)
	}

	if q1.Qclass != q2.Qclass {
		return fmt.Errorf("%w: query=%d, response=%d",
			ErrQuestionClassMismatch, q1.Qclass, q2.Qclass)
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
			return fmt.Errorf("%w: %s not in bailiwick of %s", ErrAnswerNotInBailiwick, rrName, qname)
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
	p := int(port[0])<<byteShift8 | int(port[1])

	// Ensure port is in ephemeral range (1024-65535)
	if p < minEphemeralPort {
		p += minEphemeralPort
	}

	return p
}

// ValidateResponseSize checks if a response size is reasonable.
func ValidateResponseSize(size int, maxSize int) error {
	if size > maxSize {
		return fmt.Errorf("%w: %d bytes (max: %d)", ErrResponseTooLarge, size, maxSize)
	}
	if size < minDNSHeaderSize {
		return fmt.Errorf("%w: %d bytes (min: %d)", ErrResponseTooSmall, size, minDNSHeaderSize)
	}

	return nil
}
