package zone

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// ZoneDelta represents changes between two zone versions
// Used for IXFR (incremental zone transfer).
type ZoneDelta struct {
	// FromSerial is the starting serial number
	FromSerial uint32

	// ToSerial is the ending serial number
	ToSerial uint32

	// Deleted are records removed in this delta
	Deleted []dns.RR

	// Added are records added in this delta
	Added []dns.RR
}

// IXFRHandler handles IXFR (incremental zone transfer) requests per RFC 1995.
type IXFRHandler struct {
	zone *Zone

	// deltaLog stores zone deltas for incremental transfers
	// Map: serial number -> delta to reach that serial
	deltaLog map[uint32]*ZoneDelta
}

// NewIXFRHandler creates a new IXFR handler for a zone.
func NewIXFRHandler(zone *Zone) *IXFRHandler {
	return &IXFRHandler{
		zone:     zone,
		deltaLog: make(map[uint32]*ZoneDelta),
	}
}

// HandleIXFR handles an IXFR query
// RFC 1995 Section 2: If incremental transfer is not available, fall back to AXFR.
func (h *IXFRHandler) HandleIXFR(query *dns.Msg, clientIP string, clientSerial uint32) ([]*dns.Msg, bool, error) {
	// Validate query
	if len(query.Question) != 1 {
		return nil, false, errors.New("IXFR query must have exactly one question")
	}

	q := query.Question[0]
	if q.Qtype != dns.TypeIXFR {
		return nil, false, errors.New("not an IXFR query")
	}

	// Check ACL
	if !h.zone.IsTransferAllowed(clientIP) {
		return nil, false, fmt.Errorf("zone transfer not allowed for %s", clientIP)
	}

	currentSerial := h.zone.GetSerial()

	// RFC 1995 Section 2: If client is up-to-date, send single SOA
	if clientSerial == currentSerial {
		return h.createUpToDateResponse(query), false, nil
	}

	// RFC 1995 Section 2: If client is ahead, send current SOA
	// (Serial number arithmetic per RFC 1982)
	if serialCompare(clientSerial, currentSerial) > 0 {
		return h.createUpToDateResponse(query), false, nil
	}

	// Try to find deltas from client serial to current
	deltas, canDoIXFR := h.findDeltas(clientSerial, currentSerial)

	if !canDoIXFR {
		// Fall back to AXFR per RFC 1995 Section 2
		return nil, true, nil // true = needs AXFR fallback
	}

	// Build IXFR response messages
	messages := h.buildIXFRMessages(query, deltas)

	return messages, false, nil
}

// findDeltas finds the sequence of deltas from oldSerial to newSerial.
func (h *IXFRHandler) findDeltas(oldSerial, newSerial uint32) ([]*ZoneDelta, bool) {
	var deltas []*ZoneDelta

	currentSerial := oldSerial
	for currentSerial != newSerial {
		// Find delta to next serial
		nextSerial := currentSerial + 1
		delta, exists := h.deltaLog[nextSerial]
		if !exists {
			// Delta not available - must fall back to AXFR
			return nil, false
		}

		deltas = append(deltas, delta)
		currentSerial = nextSerial
	}

	return deltas, true
}

// buildIXFRMessages builds IXFR response messages from deltas
// RFC 1995 Section 2: IXFR response format.
func (h *IXFRHandler) buildIXFRMessages(query *dns.Msg, deltas []*ZoneDelta) []*dns.Msg {
	msg := &dns.Msg{
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
	msg.SetReply(query)
	msg.Authoritative = true
	msg.Compress = true

	// Start with current SOA
	if h.zone.SOA != nil {
		msg.Answer = append(msg.Answer, dns.Copy(h.zone.SOA))
	}

	// Add deltas in order
	// RFC 1995 Section 2: Each delta is:
	// - SOA (old serial)
	// - Deleted RRs
	// - SOA (new serial)
	// - Added RRs
	for _, delta := range deltas {
		// Old SOA
		oldSOA := h.createSOAWithSerial(delta.FromSerial)
		msg.Answer = append(msg.Answer, oldSOA)

		// Deleted records
		for _, rr := range delta.Deleted {
			msg.Answer = append(msg.Answer, dns.Copy(rr))
		}

		// New SOA
		newSOA := h.createSOAWithSerial(delta.ToSerial)
		msg.Answer = append(msg.Answer, newSOA)

		// Added records
		for _, rr := range delta.Added {
			msg.Answer = append(msg.Answer, dns.Copy(rr))
		}
	}

	// End with current SOA
	if h.zone.SOA != nil {
		msg.Answer = append(msg.Answer, dns.Copy(h.zone.SOA))
	}

	return []*dns.Msg{msg}
}

// createSOAWithSerial creates a copy of the zone SOA with a specific serial.
func (h *IXFRHandler) createSOAWithSerial(serial uint32) *dns.SOA {
	if h.zone.SOA == nil {
		return nil
	}

	soa := dns.Copy(h.zone.SOA).(*dns.SOA)
	soa.Serial = serial

	return soa
}

// createUpToDateResponse creates a response when client is up-to-date
// RFC 1995 Section 2: Send single SOA to indicate no changes.
func (h *IXFRHandler) createUpToDateResponse(query *dns.Msg) []*dns.Msg {
	msg := &dns.Msg{
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
	msg.SetReply(query)
	msg.Authoritative = true

	if h.zone.SOA != nil {
		msg.Answer = append(msg.Answer, dns.Copy(h.zone.SOA))
	}

	return []*dns.Msg{msg}
}

// RecordDelta records a zone delta for IXFR
// Call this whenever the zone is updated.
func (h *IXFRHandler) RecordDelta(fromSerial, toSerial uint32, deleted, added []dns.RR) {
	delta := &ZoneDelta{
		FromSerial: fromSerial,
		ToSerial:   toSerial,
		Deleted:    make([]dns.RR, len(deleted)),
		Added:      make([]dns.RR, len(added)),
	}

	// Deep copy records
	for i, rr := range deleted {
		delta.Deleted[i] = dns.Copy(rr)
	}
	for i, rr := range added {
		delta.Added[i] = dns.Copy(rr)
	}

	h.deltaLog[toSerial] = delta
}

// PruneDeltaLog removes old deltas to limit memory usage
// Keeps only the last N deltas.
func (h *IXFRHandler) PruneDeltaLog(keepCount int) {
	if len(h.deltaLog) <= keepCount {
		return
	}

	// Find serials to keep (most recent N)
	currentSerial := h.zone.GetSerial()
	minSerial := currentSerial - uint32(keepCount) + 1

	// Remove old deltas
	for serial := range h.deltaLog {
		if serialCompare(serial, minSerial) < 0 {
			delete(h.deltaLog, serial)
		}
	}
}

// ServeIXFR serves an IXFR zone transfer over TCP.
func (h *IXFRHandler) ServeIXFR(ctx context.Context, query *dns.Msg, conn net.Conn, clientSerial uint32, axfrHandler *AXFRHandler) error {
	// Extract client IP
	clientAddr := conn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	// Try IXFR
	messages, needsAXFR, err := h.HandleIXFR(query, clientIP, clientSerial)
	if err != nil {
		// Send error response
		errorMsg := &dns.Msg{
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
		errorMsg.SetReply(query)
		errorMsg.Rcode = dns.RcodeRefused

		return h.writeMessage(conn, errorMsg)
	}

	if needsAXFR {
		// Fall back to AXFR per RFC 1995
		axfrQuery := query.Copy()
		axfrQuery.Question[0].Qtype = dns.TypeAXFR

		return axfrHandler.ServeAXFR(ctx, axfrQuery, conn)
	}

	// Send IXFR response
	for _, msg := range messages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := h.writeMessage(conn, msg); err != nil {
				return fmt.Errorf("failed to write IXFR message: %w", err)
			}
		}
	}

	return nil
}

// writeMessage writes a DNS message to a TCP connection.
func (h *IXFRHandler) writeMessage(conn net.Conn, msg *dns.Msg) error {
	dnsConn := &dns.Conn{Conn: conn}

	return dnsConn.WriteMsg(msg)
}

// serialCompare compares two serial numbers using RFC 1982 serial number arithmetic
// Returns: -1 if s1 < s2, 0 if s1 == s2, 1 if s1 > s2.
func serialCompare(s1, s2 uint32) int {
	if s1 == s2 {
		return 0
	}

	// RFC 1982 serial number arithmetic
	// s1 < s2 if:
	//   (i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1)) or
	//   (i1 > i2 and i1 - i2 > 2^(SERIAL_BITS - 1))
	// For 32-bit serials, 2^31 = 2147483648
	const halfRange = uint32(1 << 31)

	diff := s2 - s1

	// If diff < halfRange, s1 is less than s2 (s2 is newer)
	// If diff >= halfRange, s1 is greater than s2 (s1 is newer)
	if diff < halfRange {
		return -1 // s1 < s2
	}

	return 1 // s1 > s2
}

// ValidateIXFRQuery validates an IXFR query per RFC 1995.
func ValidateIXFRQuery(query *dns.Msg) error {
	// Must be a query
	if query.Response {
		return errors.New("IXFR request must be a query, not a response")
	}

	// Must have exactly one question
	if len(query.Question) != 1 {
		return errors.New("IXFR query must have exactly one question")
	}

	q := query.Question[0]

	// Must be IXFR type
	if q.Qtype != dns.TypeIXFR {
		return errors.New("question type must be IXFR")
	}

	// Class must be IN (or ANY)
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		return errors.New("IXFR class must be IN or ANY")
	}

	// IXFR query should have SOA in authority section with client's serial
	// This is optional validation - the serial can be extracted if present
	if len(query.Ns) > 0 {
		if soa, ok := query.Ns[0].(*dns.SOA); !ok {
			return errors.New("IXFR authority section should contain SOA")
		} else if soa.Header().Rrtype != dns.TypeSOA {
			return errors.New("first record in authority section must be SOA")
		}
	}

	return nil
}

// ExtractClientSerial extracts the client's serial number from an IXFR query
// RFC 1995 Section 2: Client puts its current SOA in the authority section.
func ExtractClientSerial(query *dns.Msg) (uint32, bool) {
	if len(query.Ns) == 0 {
		return 0, false
	}

	if soa, ok := query.Ns[0].(*dns.SOA); ok {
		return soa.Serial, true
	}

	return 0, false
}
