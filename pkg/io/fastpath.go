package io

import (
	"github.com/miekg/dns"
)

// FastPathQuery represents a query that can use the fast path
// Fast path criteria:
// - Common query types (A, AAAA, PTR, MX, TXT, CNAME, NS)
// - No DNSSEC required (DO bit not set)
// - Standard query (QR=0, OPCODE=QUERY)
// - Single question
// - Response size likely < 512 bytes (fits in single UDP packet)
type FastPathQuery struct {
	Name  string
	Type  uint16
	Class uint16
}

// CanUseFastPath determines if a DNS query can use the fast path
// This function MUST be allocation-free and extremely fast (<50ns)
// It's called inline for every query before any other processing
func CanUseFastPath(query []byte) bool {
	// Minimum DNS header is 12 bytes
	if len(query) < 12 {
		return false
	}

	// Parse DNS header (no allocations)
	// Byte 2-3: Flags
	flags := uint16(query[2])<<8 | uint16(query[3])

	// Check QR bit (bit 15): must be 0 (query, not response)
	if flags&0x8000 != 0 {
		return false
	}

	// Check OPCODE (bits 11-14): must be 0 (standard query)
	if flags&0x7800 != 0 {
		return false
	}

	// Check QDCOUNT (question count): must be 1
	qdcount := uint16(query[4])<<8 | uint16(query[5])
	if qdcount != 1 {
		return false
	}

	// Check if EDNS0 with DO (DNSSEC OK) bit is set
	// If DO bit is set, this requires DNSSEC validation (slow path)
	// We'll check this by looking for OPT record in additional section
	// ARCOUNT (additional records count)
	arcount := uint16(query[10])<<8 | uint16(query[11])
	if arcount > 0 {
		// Additional records present, might be EDNS0 with DO bit
		// For simplicity, send to slow path if any additional records
		// More sophisticated check could parse OPT record
		return false
	}

	// Parse question section to check query type
	// Skip to question section (after 12-byte header)
	offset := 12

	// Skip QNAME (variable length domain name)
	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			// End of QNAME
			offset++
			break
		}
		if labelLen >= 192 {
			// Compression pointer (2 bytes)
			offset += 2
			break
		}
		// Regular label
		offset += 1 + labelLen
		if offset >= len(query) {
			return false
		}
	}

	// Check if we have enough bytes for QTYPE and QCLASS
	if offset+4 > len(query) {
		return false
	}

	// Parse QTYPE (2 bytes)
	qtype := uint16(query[offset])<<8 | uint16(query[offset+1])

	// Check if query type is common (fast path eligible)
	if !isCommonQueryType(qtype) {
		return false
	}

	// Parse QCLASS (2 bytes)
	qclass := uint16(query[offset+2])<<8 | uint16(query[offset+3])

	// Must be IN (Internet) class
	if qclass != dns.ClassINET {
		return false
	}

	return true
}

// isCommonQueryType checks if the query type is common and cache-friendly
// Common types that should use fast path:
// - A (1), AAAA (28): Address records (most common)
// - PTR (12): Reverse DNS
// - MX (15): Mail exchange
// - TXT (16): Text records
// - CNAME (5): Canonical name
// - NS (2): Name server
// - SOA (6): Start of authority
func isCommonQueryType(qtype uint16) bool {
	switch qtype {
	case dns.TypeA,     // 1
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
// Only call this after CanUseFastPath returns true
func ParseFastPathQuery(query []byte) (*FastPathQuery, error) {
	// We already validated the query in CanUseFastPath
	// Parse directly from wire format to avoid dns.Msg.Unpack() allocations

	if len(query) < 12 {
		return nil, dns.ErrShortRead
	}

	// Skip DNS header (12 bytes) to question section
	offset := 12

	// Parse QNAME (domain name)
	// Most domain names are < 100 chars, pre-allocate buffer
	nameBytes := make([]byte, 0, 128)

	for offset < len(query) {
		labelLen := int(query[offset])
		if labelLen == 0 {
			// End of QNAME
			if len(nameBytes) == 0 || nameBytes[len(nameBytes)-1] != '.' {
				nameBytes = append(nameBytes, '.')
			}
			offset++
			break
		}
		if labelLen >= 192 {
			// Compression pointer - shouldn't happen in question section
			// Fall back to full parse
			msg := dns.Msg{}
			if err := msg.Unpack(query); err != nil {
				return nil, err
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

		// Regular label
		offset++
		if offset+labelLen > len(query) {
			return nil, dns.ErrShortRead
		}

		// Append label
		nameBytes = append(nameBytes, query[offset:offset+labelLen]...)
		nameBytes = append(nameBytes, '.')
		offset += labelLen
	}

	// Check if we have enough bytes for QTYPE and QCLASS
	if offset+4 > len(query) {
		return nil, dns.ErrShortRead
	}

	// Parse QTYPE (2 bytes)
	qtype := uint16(query[offset])<<8 | uint16(query[offset+1])

	// Parse QCLASS (2 bytes)
	qclass := uint16(query[offset+2])<<8 | uint16(query[offset+3])

	return &FastPathQuery{
		Name:  string(nameBytes),
		Type:  qtype,
		Class: qclass,
	}, nil
}

// GetMessageID extracts the message ID from a DNS message
// DNS message ID is at bytes 0-1 in network byte order (big endian)
func GetMessageID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return uint16(msg[0])<<8 | uint16(msg[1])
}

// SetMessageID sets the message ID in a DNS message
// DNS message ID is at bytes 0-1 in network byte order (big endian)
func SetMessageID(msg []byte, id uint16) {
	if len(msg) < 2 {
		return
	}
	msg[0] = byte(id >> 8)
	msg[1] = byte(id)
}
