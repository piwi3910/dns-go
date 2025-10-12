package zone

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// AXFRHandler handles AXFR (full zone transfer) requests per RFC 5936.
type AXFRHandler struct {
	zone *Zone
}

// NewAXFRHandler creates a new AXFR handler for a zone.
func NewAXFRHandler(zone *Zone) *AXFRHandler {
	return &AXFRHandler{
		zone: zone,
	}
}

// HandleAXFR handles an AXFR query and returns the complete zone
// Returns multiple DNS messages (zone transfer is multi-message).
func (h *AXFRHandler) HandleAXFR(query *dns.Msg, clientIP string) ([]*dns.Msg, error) {
	// Validate query
	if len(query.Question) != 1 {
		return nil, errors.New("AXFR query must have exactly one question")
	}

	q := query.Question[0]
	if q.Qtype != dns.TypeAXFR {
		return nil, errors.New("not an AXFR query")
	}

	// Check ACL
	if !h.zone.IsTransferAllowed(clientIP) {
		return nil, fmt.Errorf("zone transfer not allowed for %s", clientIP)
	}

	// Get all records in order
	records := h.zone.GetAllRecordsOrdered()

	if len(records) == 0 {
		return nil, errors.New("zone is empty")
	}

	// Split records into multiple messages
	// RFC 5936: AXFR responses should be sent in multiple messages
	messages := h.splitIntoMessages(query, records)

	return messages, nil
}

// splitIntoMessages splits zone records into multiple DNS messages
// RFC 5936 Section 2.2: Split large zones across multiple messages.
func (h *AXFRHandler) splitIntoMessages(query *dns.Msg, records []dns.RR) []*dns.Msg {
	var messages []*dns.Msg

	// Maximum records per message (to stay under UDP/TCP size limits)
	const maxRecordsPerMsg = 100

	currentMsg := h.createAXFRMessage(query)
	recordsInMsg := 0

	for _, rr := range records {
		// Start new message if current is full
		if recordsInMsg >= maxRecordsPerMsg && currentMsg.Answer[0].Header().Rrtype == dns.TypeSOA {
			// Only split after first SOA is sent
			messages = append(messages, currentMsg)
			currentMsg = h.createAXFRMessage(query)
			recordsInMsg = 0
		}

		currentMsg.Answer = append(currentMsg.Answer, rr)
		recordsInMsg++
	}

	// Add final message
	if len(currentMsg.Answer) > 0 {
		messages = append(messages, currentMsg)
	}

	return messages
}

// createAXFRMessage creates a base AXFR response message.
func (h *AXFRHandler) createAXFRMessage(query *dns.Msg) *dns.Msg {
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
	msg.Compress = true // Enable compression for efficiency

	return msg
}

// ServeAXFR serves an AXFR zone transfer over TCP
// RFC 5936 Section 2.2: AXFR must use TCP.
func (h *AXFRHandler) ServeAXFR(ctx context.Context, query *dns.Msg, conn net.Conn) error {
	// Extract client IP
	clientAddr := conn.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	// Generate zone transfer messages
	messages, err := h.HandleAXFR(query, clientIP)
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

	// Send all messages in sequence
	for _, msg := range messages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := h.writeMessage(conn, msg); err != nil {
				return fmt.Errorf("failed to write AXFR message: %w", err)
			}
		}
	}

	return nil
}

// writeMessage writes a DNS message to a TCP connection with length prefix
// RFC 5936 Section 2.2.1: TCP messages are prefixed with 2-byte length.
func (h *AXFRHandler) writeMessage(conn net.Conn, msg *dns.Msg) error {
	// Write with length prefix using dns.Conn
	dnsConn := &dns.Conn{Conn: conn}

	return dnsConn.WriteMsg(msg)
}

// ValidateAXFRQuery validates an AXFR query per RFC 5936.
func ValidateAXFRQuery(query *dns.Msg) error {
	// Must be a query
	if query.Response {
		return errors.New("AXFR request must be a query, not a response")
	}

	// Must have exactly one question
	if len(query.Question) != 1 {
		return errors.New("AXFR query must have exactly one question")
	}

	q := query.Question[0]

	// Must be AXFR type
	if q.Qtype != dns.TypeAXFR {
		return errors.New("question type must be AXFR")
	}

	// Class must be IN (or ANY)
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		return errors.New("AXFR class must be IN or ANY")
	}

	return nil
}
