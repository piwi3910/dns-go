package edns0_test

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/edns0"
)

// createTestMessage creates a basic test DNS message.
func createTestMessage(question string, qtype uint16) *dns.Msg {
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
	msg.SetQuestion(question, qtype)

	return msg
}

// createTestOPT creates a basic OPT record.
func createTestOPT(class uint16) *dns.OPT {
	return &dns.OPT{
		Hdr: dns.RR_Header{
			Name:     ".",
			Rrtype:   dns.TypeOPT,
			Class:    class,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
}

func TestValidateEDNS0_NoOPT(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	err := edns0.ValidateEDNS0(msg)
	if err != nil {
		t.Errorf("ValidateEDNS0 with no OPT should succeed, got: %v", err)
	}
}

func TestValidateEDNS0_SingleOPT(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	opt.SetVersion(0)
	msg.Extra = append(msg.Extra, opt)

	err := edns0.ValidateEDNS0(msg)
	if err != nil {
		t.Errorf("ValidateEDNS0 with valid OPT should succeed, got: %v", err)
	}
}

func TestValidateEDNS0_MultipleOPT(t *testing.T) {
	t.Parallel()
	msg := createTestMessage("example.com.", dns.TypeA)

	// Add two OPT records (invalid per RFC 6891)
	opt1 := createTestOPT(4096)
	opt2 := createTestOPT(4096)
	msg.Extra = append(msg.Extra, opt1, opt2)

	err := edns0.ValidateEDNS0(msg)
	if err == nil {
		t.Error("ValidateEDNS0 should fail with multiple OPT records")
	}

	valErr := &edns0.ValidationError{
		Message:      "",
		ExtendedCode: 0,
	}
	ok := errors.As(err, &valErr)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
	if valErr.ExtendedCode != dns.RcodeFormatError {
		t.Errorf("Expected FORMERR, got %d", valErr.ExtendedCode)
	}
}

func TestValidateEDNS0_BadVersion(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	opt.SetVersion(1) // Unsupported version
	msg.Extra = append(msg.Extra, opt)

	err := edns0.ValidateEDNS0(msg)
	if err == nil {
		t.Error("ValidateEDNS0 should fail with unsupported version")
	}

	valErr := &edns0.ValidationError{
		Message:      "",
		ExtendedCode: 0,
	}
	ok := errors.As(err, &valErr)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
	if valErr.ExtendedCode != edns0.RcodeBadVers {
		t.Errorf("Expected BADVERS (%d), got %d", edns0.RcodeBadVers, valErr.ExtendedCode)
	}
}

func TestValidateEDNS0_InvalidOPTName(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   "example.com.", // Invalid - must be "."
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	msg.Extra = append(msg.Extra, opt)

	err := edns0.ValidateEDNS0(msg)
	if err == nil {
		t.Error("ValidateEDNS0 should fail with non-root OPT name")
	}

	valErr := &edns0.ValidationError{
		Message:      "",
		ExtendedCode: 0,
	}
	ok := errors.As(err, &valErr)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}
	if valErr.ExtendedCode != dns.RcodeFormatError {
		t.Errorf("Expected FORMERR, got %d", valErr.ExtendedCode)
	}
}

func TestSetExtendedRcode(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	// Add OPT record
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	msg.Extra = append(msg.Extra, opt)

	// Set BADVERS (extended RCODE 16)
	edns0.SetExtendedRcode(msg, edns0.RcodeBadVers)

	// Check lower 4 bits in msg.Rcode
	if msg.Rcode != 0 {
		t.Errorf("Expected msg.Rcode=0, got %d", msg.Rcode)
	}

	// Check extended RCODE
	extRcode := edns0.GetExtendedRcode(msg)
	if extRcode != edns0.RcodeBadVers {
		t.Errorf("Expected extended RCODE %d, got %d", edns0.RcodeBadVers, extRcode)
	}
}

func TestGetExtendedRcode_NoEDNS(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeServerFailure

	rcode := edns0.GetExtendedRcode(msg)
	if rcode != dns.RcodeServerFailure {
		t.Errorf("Expected RCODE %d, got %d", dns.RcodeServerFailure, rcode)
	}
}

func TestGetExtendedRcode_WithEDNS(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	// Add OPT with extended RCODE
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:     ".",
			Rrtype:   dns.TypeOPT,
			Class:    4096,
			Ttl:      uint32(1) << 24, // Extended RCODE 1 in upper 8 bits
			Rdlength: 0,
		},
		Option: nil,
	}
	msg.Extra = append(msg.Extra, opt)
	msg.Rcode = 0 // Lower 4 bits

	rcode := edns0.GetExtendedRcode(msg)
	expected := 1 << 4 // Extended: 1, Base: 0 = 16
	if rcode != expected {
		t.Errorf("Expected extended RCODE %d, got %d", expected, rcode)
	}
}

func TestCreateErrorResponse_BADVERS(t *testing.T) {
	t.Parallel()
	query := &dns.Msg{
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
	query.SetQuestion("example.com.", dns.TypeA)

	// Query with EDNS version 1
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	opt.SetVersion(1)
	query.Extra = append(query.Extra, opt)

	response := edns0.CreateErrorResponse(query, edns0.RcodeBadVers, edns0.MaxSupportedEDNS)

	// Check response has OPT
	responseOpt := response.IsEdns0()
	if responseOpt == nil {
		t.Fatal("Response should have OPT record")
	}

	// Check version is set to our max supported
	if responseOpt.Version() != edns0.MaxSupportedEDNS {
		t.Errorf("Expected version %d, got %d", edns0.MaxSupportedEDNS, responseOpt.Version())
	}

	// Check extended RCODE
	extRcode := edns0.GetExtendedRcode(response)
	if extRcode != edns0.RcodeBadVers {
		t.Errorf("Expected BADVERS (%d), got %d", edns0.RcodeBadVers, extRcode)
	}
}

func TestHandleUnknownOptions(t *testing.T) {
	t.Parallel()
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}

	// Add known option
	nsid := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
		Nsid: "test-server",
	}
	opt.Option = append(opt.Option, nsid)

	// Add unknown option (using local/experimental code)
	local := &dns.EDNS0_LOCAL{
		Code: 65001, // Local/experimental range
		Data: []byte{1, 2, 3, 4},
	}
	opt.Option = append(opt.Option, local)

	unknowns := edns0.HandleUnknownOptions(opt)
	if len(unknowns) != 1 {
		t.Errorf("Expected 1 unknown option, got %d", len(unknowns))
	}
}

func TestNegotiateBufferSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		clientSize   uint16
		serverSize   uint16
		expectedSize uint16
	}{
		{1232, 4096, 1232}, // Client smaller
		{4096, 1232, 1232}, // Server smaller
		{2048, 2048, 2048}, // Equal
		{512, 4096, 512},   // Minimum client
	}

	for _, tt := range tests {
		result := edns0.NegotiateBufferSize(tt.clientSize, tt.serverSize)
		if result != tt.expectedSize {
			t.Errorf("NegotiateBufferSize(%d, %d) = %d, want %d",
				tt.clientSize, tt.serverSize, result, tt.expectedSize)
		}
	}
}

func TestShouldTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		responseSize int
		ednsInfo     *edns0.Info
		shouldTrunc  bool
	}{
		{400, &edns0.Info{Present: false, UDPSize: 0, DO: false, ExtendedRcode: 0, Version: 0},
			false}, // < 512, no EDNS
		{600, &edns0.Info{Present: false, UDPSize: 0, DO: false, ExtendedRcode: 0, Version: 0},
			true}, // > 512, no EDNS
		{600, &edns0.Info{Present: true, UDPSize: 1024, DO: false, ExtendedRcode: 0, Version: 0},
			false}, // < EDNS limit
		{1100, &edns0.Info{Present: true, UDPSize: 1024, DO: false, ExtendedRcode: 0, Version: 0},
			true}, // > EDNS limit
		{4000, &edns0.Info{Present: true, UDPSize: 4096, DO: false, ExtendedRcode: 0, Version: 0},
			false}, // < large EDNS
	}

	for _, tt := range tests {
		result := edns0.ShouldTruncate(tt.responseSize, tt.ednsInfo)
		if result != tt.shouldTrunc {
			t.Errorf("ShouldTruncate(%d, edns=%v) = %v, want %v",
				tt.responseSize, tt.ednsInfo.Present, result, tt.shouldTrunc)
		}
	}
}

func TestParseEDNS0_ClampUDPSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		optClass     uint16
		expectedSize uint16
	}{
		{
			name:         "ClampToMinimum",
			optClass:     256, // Too small
			expectedSize: edns0.MinimumUDPSize,
		},
		{
			name:         "ClampToMaximum",
			optClass:     65000, // Too large
			expectedSize: edns0.MaximumUDPSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
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
			msg.SetQuestion("example.com.", dns.TypeA)

			// OPT with size that should be clamped
			opt := &dns.OPT{
				Hdr: dns.RR_Header{
					Name:     ".",
					Rrtype:   dns.TypeOPT,
					Class:    tt.optClass,
					Ttl:      0,
					Rdlength: 0,
				},
				Option: nil,
			}
			msg.Extra = append(msg.Extra, opt)

			info := edns0.ParseEDNS0(msg)
			if info.UDPSize != tt.expectedSize {
				t.Errorf("Expected UDP size to be clamped to %d, got %d", tt.expectedSize, info.UDPSize)
			}
		})
	}
}

func TestParseEDNS0_DOBit(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  4096,
			Ttl:      0,
			Rdlength: 0,
		},
		Option: nil,
	}
	opt.SetDo() // Set DNSSEC OK bit
	msg.Extra = append(msg.Extra, opt)

	info := edns0.ParseEDNS0(msg)
	if !info.DO {
		t.Error("Expected DO bit to be set")
	}
}

func TestAddOPTRecord(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	edns0.AddOPTRecord(msg, 4096, true)

	opt := msg.IsEdns0()
	if opt == nil {
		t.Fatal("Expected OPT record to be added")
	}

	if opt.UDPSize() != 4096 {
		t.Errorf("Expected UDP size 4096, got %d", opt.UDPSize())
	}

	if !opt.Do() {
		t.Error("Expected DO bit to be set")
	}

	if opt.Version() != edns0.EDNS0Version {
		t.Errorf("Expected version %d, got %d", edns0.EDNS0Version, opt.Version())
	}
}

func TestAddOPTRecord_RemovesExisting(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	// Add first OPT
	edns0.AddOPTRecord(msg, 1024, false)

	// Add second OPT - should replace first
	edns0.AddOPTRecord(msg, 4096, true)

	// Count OPT records
	optCount := 0
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			optCount++
		}
	}

	if optCount != 1 {
		t.Errorf("Expected exactly 1 OPT record, got %d", optCount)
	}

	opt := msg.IsEdns0()
	if opt.UDPSize() != 4096 {
		t.Errorf("Expected UDP size 4096 (latest), got %d", opt.UDPSize())
	}
}

func TestAddOPTRecord_ClampSize(t *testing.T) {
	t.Parallel()
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
	msg.SetQuestion("example.com.", dns.TypeA)

	// Try to add with size < minimum
	edns0.AddOPTRecord(msg, 256, false)

	opt := msg.IsEdns0()
	if opt.UDPSize() != edns0.MinimumUDPSize {
		t.Errorf("Expected clamped size %d, got %d", edns0.MinimumUDPSize, opt.UDPSize())
	}

	// Try with size > maximum
	msg.Extra = nil
	edns0.AddOPTRecord(msg, 65000, false)

	opt = msg.IsEdns0()
	if opt.UDPSize() != edns0.MaximumUDPSize {
		t.Errorf("Expected clamped size %d, got %d", edns0.MaximumUDPSize, opt.UDPSize())
	}
}
