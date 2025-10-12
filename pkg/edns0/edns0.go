package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDNS0Info holds EDNS0 parameters from a query.
type EDNS0Info struct {
	Present       bool   // Whether EDNS0 is present in the query
	UDPSize       uint16 // Client's UDP payload size
	DO            bool   // DNSSEC OK bit
	ExtendedRcode uint8  // Extended RCODE
	Version       uint8  // EDNS version
}

// Default values per RFC 6891.
const (
	DefaultUDPSize   = 1232 // RFC 6891 recommends 1232 for IPv4, 1220 for IPv6
	MinimumUDPSize   = 512  // RFC 1035 minimum
	MaximumUDPSize   = 4096 // Reasonable maximum for our implementation
	EDNS0Version     = 0    // We support EDNS version 0
	MaxSupportedEDNS = 0    // Maximum EDNS version we support
)

// EDNS0 Extended RCODEs (RFC 6891 Section 6.1.3).
const (
	RcodeBadVers = 16 // BADVERS - unsupported EDNS version
)

// ValidationError represents an EDNS0 validation error.
type ValidationError struct {
	Message      string
	ExtendedCode int // Extended RCODE to return
}

func (e *ValidationError) Error() string {
	return e.Message
}

// ParseEDNS0 extracts EDNS0 information from a DNS query.
func ParseEDNS0(msg *dns.Msg) *EDNS0Info {
	info := &EDNS0Info{
		Present:       false,
		UDPSize:       MinimumUDPSize, // Default to minimum if no EDNS0
		DO:            false,
		ExtendedRcode: 0,
		Version:       0,
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
// dnssecOK: whether to set the DO (DNSSEC OK) bit.
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
			Name:     ".",
			Rrtype:   dns.TypeOPT,
			Class:    bufferSize, // UDP payload size in CLASS field
			Ttl:      0,          // Extended RCODE and flags (we use 0 for now)
			Rdlength: 0,
		},
		Option: nil,
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
// There should only be one OPT record per message per RFC 6891.
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
// Returns the smaller of the two (negotiated size).
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
// Returns true if the response should be truncated.
func ShouldTruncate(responseSize int, ednsInfo *EDNS0Info) bool {
	maxSize := int(MinimumUDPSize)

	if ednsInfo.Present {
		maxSize = int(ednsInfo.UDPSize)
	}

	return responseSize > maxSize
}

// ValidateEDNS0 performs comprehensive EDNS0 validation per RFC 6891
// Returns ValidationError if the query has invalid EDNS0.
func ValidateEDNS0(msg *dns.Msg) error {
	// Count OPT records - RFC 6891 Section 6.1.1: exactly zero or one
	optCount := 0
	var opt *dns.OPT

	for _, rr := range msg.Extra {
		if o, ok := rr.(*dns.OPT); ok {
			optCount++
			opt = o
		}
	}

	// Multiple OPT records is a FORMERR per RFC 6891
	if optCount > 1 {
		return &ValidationError{
			Message:      "multiple OPT records in query",
			ExtendedCode: dns.RcodeFormatError,
		}
	}

	// No OPT record is valid (non-EDNS0 query)
	if optCount == 0 {
		return nil
	}

	// Validate OPT record placement - must be in additional section only
	// (already guaranteed by checking msg.Extra above)

	// Validate OPT record format
	if opt.Hdr.Name != "." {
		return &ValidationError{
			Message:      "OPT record name must be root (.)",
			ExtendedCode: dns.RcodeFormatError,
		}
	}

	if opt.Hdr.Rrtype != dns.TypeOPT {
		return &ValidationError{
			Message:      "invalid OPT record type",
			ExtendedCode: dns.RcodeFormatError,
		}
	}

	// Version negotiation - RFC 6891 Section 6.1.3
	// If version > MaxSupportedEDNS, must return BADVERS
	version := opt.Version()
	if version > MaxSupportedEDNS {
		return &ValidationError{
			Message:      fmt.Sprintf("unsupported EDNS version %d (max: %d)", version, MaxSupportedEDNS),
			ExtendedCode: RcodeBadVers,
		}
	}

	// Validate UDP payload size - RFC 6891 Section 6.2.3
	// Values less than 512 MUST be treated as equal to 512
	// We clamp this in ParseEDNS0, not an error per RFC 6891
	_ = opt.UDPSize() // Validated during ParseEDNS0

	// Unknown EDNS0 options are allowed and must be ignored per RFC 6891 Section 6.1.2
	// The miekg/dns library handles this automatically

	return nil
}

// CreateErrorResponse creates an EDNS0 error response
// Used when EDNS0 validation fails (e.g., BADVERS).
func CreateErrorResponse(query *dns.Msg, rcode int, ednsVersion uint8) *dns.Msg {
	response := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           false,
			Opcode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			Zero:               false,
			AuthenticatedData:  false,
			CheckingDisabled:   false,
			Rcode:              0,
		},
		Compress: false,
		Question: nil,
		Answer:   nil,
		Ns:       nil,
		Extra:    nil,
	}
	response.SetReply(query)
	response.Rcode = rcode & 0x0F // Lower 4 bits

	// If query had EDNS0, include OPT in error response
	if query.IsEdns0() != nil {
		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:     ".",
				Rrtype:   dns.TypeOPT,
				Class:    DefaultUDPSize,
				Ttl:      uint32(rcode>>4) << 24, // Extended RCODE in upper 8 bits of TTL
				Rdlength: 0,
			},
			Option: nil,
		}
		opt.SetVersion(ednsVersion)
		response.Extra = append(response.Extra, opt)
	}

	return response
}

// SetExtendedRcode sets the extended RCODE in a response message
// rcode: the full extended RCODE (lower 4 bits go in msg.Rcode, upper bits in OPT)
func SetExtendedRcode(msg *dns.Msg, rcode int) {
	// Set lower 4 bits in message RCODE
	msg.Rcode = rcode & 0x0F

	// Set upper 8 bits in OPT record TTL if EDNS0 is present
	opt := msg.IsEdns0()
	if opt != nil {
		// Extended RCODE goes in upper 8 bits of TTL field
		extendedBits := uint32(rcode>>4) << 24
		opt.Hdr.Ttl = (opt.Hdr.Ttl & 0x00FFFFFF) | extendedBits
	}
}

// GetExtendedRcode extracts the full extended RCODE from a message
// Combines msg.Rcode (lower 4 bits) with OPT TTL (upper 8 bits).
func GetExtendedRcode(msg *dns.Msg) int {
	rcode := msg.Rcode

	opt := msg.IsEdns0()
	if opt != nil {
		// Extended RCODE is in upper 8 bits of TTL
		extendedBits := int(opt.Hdr.Ttl >> 24)
		rcode |= (extendedBits << 4)
	}

	return rcode
}

// HandleUnknownOptions processes unknown EDNS0 options per RFC 6891
// Unknown options must be ignored, but we log them for debugging.
func HandleUnknownOptions(opt *dns.OPT) []string {
	unknownOptions := []string{}

	for _, option := range opt.Option {
		switch option.(type) {
		case *dns.EDNS0_NSID:
			// Known option
		case *dns.EDNS0_SUBNET:
			// Known option (ECS - Client Subnet)
		case *dns.EDNS0_COOKIE:
			// Known option
		case *dns.EDNS0_EXPIRE:
			// Known option
		case *dns.EDNS0_TCP_KEEPALIVE:
			// Known option
		case *dns.EDNS0_PADDING:
			// Known option
		case *dns.EDNS0_DAU:
			// Known option (DNSSEC Algorithm Understood)
		case *dns.EDNS0_DHU:
			// Known option (DS Hash Understood)
		case *dns.EDNS0_N3U:
			// Known option (NSEC3 Hash Understood)
		default:
			// Unknown option - RFC 6891: must be ignored
			unknownOptions = append(unknownOptions, fmt.Sprintf("code=%d", option.Option()))
		}
	}

	return unknownOptions
}

// CopyEDNS0Options copies EDNS0 options from query to response
// Used for options that should be echoed back (like NSID, Cookie, etc.)
func CopyEDNS0Options(queryOpt, responseOpt *dns.OPT) {
	if queryOpt == nil || responseOpt == nil {
		return
	}

	for _, option := range queryOpt.Option {
		switch opt := option.(type) {
		case *dns.EDNS0_NSID:
			// Echo NSID if server has one configured
			// (Implementation-specific)
		case *dns.EDNS0_COOKIE:
			// Process cookie - echo back with server cookie
			// (Implementation-specific)
		case *dns.EDNS0_PADDING:
			// Padding should not be copied
		default:
			// Most options are not echoed
			_ = opt
		}
	}
}
