package edns0

import (
	"github.com/miekg/dns"
)

// EDNS0Info holds EDNS0 parameters from a query
type EDNS0Info struct {
	Present       bool   // Whether EDNS0 is present in the query
	UDPSize       uint16 // Client's UDP payload size
	DO            bool   // DNSSEC OK bit
	ExtendedRcode uint8  // Extended RCODE
	Version       uint8  // EDNS version
}

// Default values per RFC 6891
const (
	DefaultUDPSize    = 1232 // RFC 6891 recommends 1232 for IPv4, 1220 for IPv6
	MinimumUDPSize    = 512  // RFC 1035 minimum
	MaximumUDPSize    = 4096 // Reasonable maximum for our implementation
	EDNS0Version      = 0    // We support EDNS version 0
)

// ParseEDNS0 extracts EDNS0 information from a DNS query
func ParseEDNS0(msg *dns.Msg) *EDNS0Info {
	info := &EDNS0Info{
		Present: false,
		UDPSize: MinimumUDPSize, // Default to minimum if no EDNS0
	}

	// Look for OPT record in additional section
	opt := msg.IsEdns0()
	if opt == nil {
		return info
	}

	info.Present = true
	info.UDPSize = opt.UDPSize()
	info.DO = opt.Do()
	info.Version = opt.Version()

	// Extended RCODE is stored in TTL field (upper 8 bits)
	// Lower 4 bits combine with message RCODE to form extended RCODE
	info.ExtendedRcode = uint8(opt.Hdr.Ttl >> 24)

	// Validate and clamp UDP size to reasonable limits
	if info.UDPSize < MinimumUDPSize {
		info.UDPSize = MinimumUDPSize
	}
	if info.UDPSize > MaximumUDPSize {
		info.UDPSize = MaximumUDPSize
	}

	return info
}

// AddOPTRecord adds an EDNS0 OPT record to a response message
// bufferSize: the UDP payload size to advertise
// dnssecOK: whether to set the DO (DNSSEC OK) bit
func AddOPTRecord(msg *dns.Msg, bufferSize uint16, dnssecOK bool) {
	// Remove any existing OPT records (there should only be one)
	msg.Extra = removeOPTRecords(msg.Extra)

	// Validate and clamp buffer size
	if bufferSize < MinimumUDPSize {
		bufferSize = MinimumUDPSize
	}
	if bufferSize > MaximumUDPSize {
		bufferSize = MaximumUDPSize
	}

	// Create OPT record
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  bufferSize, // UDP payload size in CLASS field
			Ttl:    0,          // Extended RCODE and flags (we use 0 for now)
		},
	}

	// Set DNSSEC OK bit if requested
	if dnssecOK {
		opt.SetDo()
	}

	// Set EDNS version to 0
	opt.SetVersion(EDNS0Version)

	// Add to additional section
	msg.Extra = append(msg.Extra, opt)
}

// removeOPTRecords removes all OPT records from a slice of RRs
// There should only be one OPT record per message per RFC 6891
func removeOPTRecords(rrs []dns.RR) []dns.RR {
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); !ok {
			result = append(result, rr)
		}
	}
	return result
}

// NegotiateBufferSize determines the appropriate buffer size for a response
// clientSize: the UDP payload size from the client's OPT record
// serverSize: the server's maximum UDP payload size
// Returns the smaller of the two (negotiated size)
func NegotiateBufferSize(clientSize, serverSize uint16) uint16 {
	// Use the minimum of client and server sizes
	if clientSize < serverSize {
		return clientSize
	}
	return serverSize
}

// ShouldTruncate checks if a response should be truncated based on EDNS0 buffer size
// responseSize: the size of the packed response in bytes
// ednsInfo: EDNS0 info from the query
// Returns true if the response should be truncated
func ShouldTruncate(responseSize int, ednsInfo *EDNS0Info) bool {
	maxSize := int(MinimumUDPSize)

	if ednsInfo.Present {
		maxSize = int(ednsInfo.UDPSize)
	}

	return responseSize > maxSize
}
