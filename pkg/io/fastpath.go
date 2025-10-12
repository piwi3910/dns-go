// Package io provides high-performance I/O handling for DNS queries with per-core optimizations.
package io

import (
	"fmt"

	"github.com/miekg/dns"
)

// DNS wire format constants (RFC 1035).
const (
	dnsHeaderSize            = 12  // DNS header size in bytes
	dnsMessageIDSize         = 2   // DNS message ID size in bytes
	dnsCompressionMask       = 192 // 0xC0 - DNS name compression pointer mask
	dnsCompressionPtrSize    = 2   // Size of compression pointer in bytes
	dnsQTypeClassSize        = 4   // QTYPE (2 bytes) + QCLASS (2 bytes)
	dnsRRHeaderSize          = 10  // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2)
	dnsByteShift8            = 8   // Bit shift for network byte order (big endian)
	dnsNameBufferSize        = 128 // Default buffer size for domain name parsing
	dnsOPTType               = 41  // OPT pseudo-RR type (RFC 6891)
	dnsDOBitMask             = 0x80 // DNSSEC OK bit mask in EDNS0 flags
	dnsTTLSize               = 4   // TTL field size in bytes
	dnsTypeClassTTLSize      = 8   // TYPE (2) + CLASS (2) + TTL (4)
	dnsTTLFlagsHighOffset    = 2   // Offset to flags high byte within TTL field
)

// FastPathQuery represents a query that can use the fast path
// Fast path criteria:
// - Common query types (A, AAAA, PTR, MX, TXT, CNAME, NS)
// - No DNSSEC required (DO bit not set)
// - Standard query (QR=0, OPCODE=QUERY)
// - Single question
// - Response size likely < 512 bytes (fits in single UDP packet).
type FastPathQuery struct {
	Name  string
	Type  uint16
	Class uint16
}

// CanUseFastPath determines if a DNS query can use the fast path
// This function MUST be allocation-free and extremely fast (<50ns)
// It's called inline for every query before any other processing.
func CanUseFastPath(query []byte) bool {
	// Validate DNS header
	if !validateDNSHeaderForFastPath(query) {
		return false
	}

	// Skip QNAME and get offset to QTYPE/QCLASS
	offset, ok := skipQNAMEForFastPath(query, dnsHeaderSize)
	if !ok {
		return false
	}

	// Validate query type and class
	return validateQueryTypeAndClass(query, offset)
}

// validateDNSHeaderForFastPath validates DNS header for fast path eligibility.
// Must be inlineable for zero overhead.
func validateDNSHeaderForFastPath(query []byte) bool {
	// Minimum DNS header size
	if len(query) < dnsHeaderSize {
		return false
	}

	// Parse DNS header (no allocations)
	// Byte 2-3: Flags
	flags := uint16(query[2])<<dnsByteShift8 | uint16(query[3])

	// Check QR bit (bit 15): must be 0 (query, not response)
	if flags&0x8000 != 0 {
		return false
	}

	// Check OPCODE (bits 11-14): must be 0 (standard query)
	if flags&0x7800 != 0 {
		return false
	}

	// Check QDCOUNT (question count): must be 1
	qdcount := uint16(query[4])<<dnsByteShift8 | uint16(query[5])
	if qdcount != 1 {
		return false
	}

	// Check if EDNS0 with DO (DNSSEC OK) bit is set
	// If DO bit is set, this requires DNSSEC validation (slow path)
	// ARCOUNT (additional records count)
	arcount := uint16(query[10])<<dnsByteShift8 | uint16(query[11])
	if arcount > 0 {
		// Additional records present - check if it's EDNS0 with DO bit
		// We need to parse the OPT record to check the DO bit
		// For now, we'll do a fast check: if there's exactly 1 additional record
		// at the end that looks like OPT, and DO bit is NOT set, allow fast path
		if !canUseFastPathWithEDNS0(query, arcount) {
			return false
		}
	}

	return true
}

// skipQNAMEForFastPath skips the QNAME field and returns offset to QTYPE/QCLASS.
// Must be inlineable for zero overhead.
func skipQNAMEForFastPath(query []byte, offset int) (int, bool) {
	// Skip QNAME (variable length domain name)
	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			// End of QNAME
			return offset + 1, true
		}
		if labelLen >= dnsCompressionMask {
			// Compression pointer (2 bytes)
			return offset + dnsCompressionPtrSize, true
		}
		// Regular label
		offset += 1 + labelLen
		if offset >= len(query) {
			return 0, false
		}
	}

	return 0, false
}

// validateQueryTypeAndClass validates QTYPE and QCLASS for fast path.
// Must be inlineable for zero overhead.
func validateQueryTypeAndClass(query []byte, offset int) bool {
	// Check if we have enough bytes for QTYPE and QCLASS
	if offset+dnsQTypeClassSize > len(query) {
		return false
	}

	// Parse QTYPE (2 bytes)
	qtype := uint16(query[offset])<<dnsByteShift8 | uint16(query[offset+1])

	// Check if query type is common (fast path eligible)
	if !isCommonQueryType(qtype) {
		return false
	}

	// Parse QCLASS (2 bytes)
	qclass := uint16(query[offset+2])<<dnsByteShift8 | uint16(query[offset+3])

	// Must be IN (Internet) class
	return qclass == dns.ClassINET
}

// isCommonQueryType checks if the query type is common and cache-friendly
// Common types that should use fast path:
// - A (1), AAAA (28): Address records (most common)
// - PTR (12): Reverse DNS
// - MX (15): Mail exchange
// - TXT (16): Text records
// - CNAME (5): Canonical name
// - NS (2): Name server
// - SOA (6): Start of authority.
func isCommonQueryType(qtype uint16) bool {
	switch qtype {
	case dns.TypeA, // 1
		dns.TypeNS,    // 2
		dns.TypeCNAME, // 5
		dns.TypeSOA,   // 6
		dns.TypePTR,   // 12
		dns.TypeMX,    // 15
		dns.TypeTXT,   // 16
		dns.TypeAAAA:  // 28
		return true
	default:
		return false
	}
}

// ParseFastPathQuery extracts query information with minimal allocations
// Only call this after CanUseFastPath returns true.
func ParseFastPathQuery(query []byte) (*FastPathQuery, error) {
	if len(query) < dnsHeaderSize {
		return nil, dns.ErrShortRead
	}

	// Parse QNAME starting after header (offset 12)
	nameBytes, offset, err := parseQNAME(query, dnsHeaderSize)
	if err != nil {
		return nil, err
	}

	// Handle compression pointer fallback
	if offset < 0 {
		return parseQueryWithFullUnpack(query)
	}

	// Parse QTYPE and QCLASS
	return parseQueryTypeAndClass(query, offset, nameBytes)
}

// parseQNAME parses a domain name from wire format.
// Returns (nameBytes, newOffset, error). If newOffset < 0, caller should use full unpack.
func parseQNAME(query []byte, offset int) ([]byte, int, error) {
	nameBytes := make([]byte, 0, dnsNameBufferSize)

	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			// End of QNAME
			if len(nameBytes) == 0 || nameBytes[len(nameBytes)-1] != '.' {
				nameBytes = append(nameBytes, '.')
			}

			return nameBytes, offset + 1, nil
		}

		if labelLen >= dnsCompressionMask {
			// Compression pointer - signal to use full unpack
			return nil, -1, nil
		}

		// Regular label
		offset++
		if offset+labelLen > len(query) {
			return nil, 0, dns.ErrShortRead
		}

		nameBytes = append(nameBytes, query[offset:offset+labelLen]...)
		nameBytes = append(nameBytes, '.')
		offset += labelLen
	}

	return nameBytes, offset, nil
}

// parseQueryWithFullUnpack falls back to full DNS message unpacking.
func parseQueryWithFullUnpack(query []byte) (*FastPathQuery, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, dns.ErrId
	}

	q := msg.Question[0]

	return &FastPathQuery{
		Name:  q.Name,
		Type:  q.Qtype,
		Class: q.Qclass,
	}, nil
}

// parseQueryTypeAndClass extracts QTYPE and QCLASS from the query.
func parseQueryTypeAndClass(query []byte, offset int, nameBytes []byte) (*FastPathQuery, error) {
	if offset+dnsQTypeClassSize > len(query) {
		return nil, dns.ErrShortRead
	}

	qtype := uint16(query[offset])<<dnsByteShift8 | uint16(query[offset+1])
	qclass := uint16(query[offset+2])<<dnsByteShift8 | uint16(query[offset+3])

	return &FastPathQuery{
		Name:  string(nameBytes),
		Type:  qtype,
		Class: qclass,
	}, nil
}

// canUseFastPathWithEDNS0 checks if a query with additional records can use fast path
// Returns true if the additional record is EDNS0 without DO bit set.
func canUseFastPathWithEDNS0(query []byte, arcount uint16) bool {
	// Only handle single additional record (typical for EDNS0)
	if arcount != 1 {
		return false
	}

	// Skip to the additional section
	offset, ok := skipToAdditionalSection(query)
	if !ok {
		return false
	}

	// Parse OPT record and check DO bit
	return parseOPTRecordForFastPath(query, offset)
}

// skipToAdditionalSection skips header, question, answer, and authority sections.
func skipToAdditionalSection(query []byte) (int, bool) {
	offset := dnsHeaderSize // Start after header

	// Skip question section
	qdcount := uint16(query[4])<<dnsByteShift8 | uint16(query[5])
	offset = skipQuestionSection(query, offset, qdcount)
	if offset < 0 {
		return 0, false
	}

	// Skip answer and authority sections
	ancount := uint16(query[6])<<dnsByteShift8 | uint16(query[7])
	nscount := uint16(query[8])<<dnsByteShift8 | uint16(query[9])
	offset = skipRRSections(query, offset, ancount+nscount)
	if offset < 0 {
		return 0, false
	}

	return offset, offset < len(query)
}

// skipQuestionSection skips the question section of a DNS message.
func skipQuestionSection(query []byte, offset int, qdcount uint16) int {
	for range qdcount {
		// Skip QNAME
		offset = skipDNSName(query, offset)
		if offset < 0 {
			return -1
		}

		// Skip QTYPE (2) + QCLASS (2)
		offset += dnsQTypeClassSize
		if offset > len(query) {
			return -1
		}
	}

	return offset
}

// skipDNSName skips a DNS name in wire format.
func skipDNSName(query []byte, offset int) int {
	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			return offset + 1
		}
		if labelLen >= dnsCompressionMask {
			// Compression pointer
			return offset + dnsCompressionPtrSize
		}
		offset += 1 + labelLen
		if offset >= len(query) {
			return -1
		}
	}

	return -1
}

// skipRRSections skips multiple resource record sections.
func skipRRSections(query []byte, offset int, count uint16) int {
	for range count {
		offset = skipRR(query, offset)
		if offset < 0 || offset > len(query) {
			return -1
		}
	}

	return offset
}

// parseOPTRecordForFastPath checks if the OPT record allows fast path (DO bit not set).
func parseOPTRecordForFastPath(query []byte, offset int) bool {
	// OPT record has NAME = "." (root) = 0x00
	if offset >= len(query) || query[offset] != 0 {
		return false
	}
	offset++

	// Check we have enough bytes for TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2)
	if offset+dnsRRHeaderSize > len(query) {
		return false
	}

	// Check TYPE = OPT (41)
	rrtype := uint16(query[offset])<<dnsByteShift8 | uint16(query[offset+1])
	if rrtype != dnsOPTType {
		return false
	}
	offset += dnsQTypeClassSize // Skip TYPE (2) + CLASS (2)

	// Parse TTL field which contains extended RCODE and flags
	// DO bit is bit 7 of the flags high byte (offset+2)
	if offset+dnsTTLSize > len(query) {
		return false
	}

	flagsHigh := query[offset+dnsTTLFlagsHighOffset] // Flags high byte
	doBit := (flagsHigh & dnsDOBitMask) != 0

	// EDNS0 without DO bit can use fast path
	return !doBit
}

// skipRR skips over a resource record in the wire format
// Returns new offset, or -1 on error.
func skipRR(query []byte, offset int) int {
	// Skip NAME
	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			offset++

			break
		}
		if labelLen >= dnsCompressionMask {
			// Compression pointer
			offset += dnsCompressionPtrSize

			break
		}
		offset += 1 + labelLen
		if offset >= len(query) {
			return -1
		}
	}

	// Check we have: TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
	if offset+dnsRRHeaderSize > len(query) {
		return -1
	}

	// Skip TYPE (2) + CLASS (2) + TTL (4)
	offset += dnsTypeClassTTLSize

	// Read RDLENGTH
	rdlength := uint16(query[offset])<<dnsByteShift8 | uint16(query[offset+1])
	offset += 2

	// Skip RDATA
	offset += int(rdlength)
	if offset > len(query) {
		return -1
	}

	return offset
}

// GetMessageID extracts the message ID from a DNS message
// DNS message ID is at bytes 0-1 in network byte order (big endian).
func GetMessageID(msg []byte) uint16 {
	if len(msg) < dnsMessageIDSize {
		return 0
	}

	return uint16(msg[0])<<dnsByteShift8 | uint16(msg[1])
}

// SetMessageID sets the message ID in a DNS message
// DNS message ID is at bytes 0-1 in network byte order (big endian).
func SetMessageID(msg []byte, id uint16) {
	if len(msg) < dnsMessageIDSize {
		return
	}
	msg[0] = byte(id >> dnsByteShift8)
	msg[1] = byte(id)
}
