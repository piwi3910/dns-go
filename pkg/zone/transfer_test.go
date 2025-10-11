package zone

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// Helper function to create a test zone.
func createTestZone() *Zone {
	zone := NewZone(ZoneConfig{
		Origin:      "example.com",
		TransferACL: []string{"192.0.2.1", "192.0.2.2"},
	})

	// Add SOA
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	zone.AddRecord(soa)

	// Add A record
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 10},
	}
	zone.AddRecord(a)

	// Add MX record
	mx := &dns.MX{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	zone.AddRecord(mx)

	return zone
}

// AXFR Tests

func TestValidateAXFRQuery(t *testing.T) {
	t.Parallel()
	// Valid AXFR query
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAXFR)

	err := ValidateAXFRQuery(query)
	if err != nil {
		t.Errorf("Valid AXFR query failed validation: %v", err)
	}

	// Response instead of query
	query.Response = true
	err = ValidateAXFRQuery(query)
	if err == nil {
		t.Error("Expected error for response instead of query")
	}

	// Wrong type
	query = &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	err = ValidateAXFRQuery(query)
	if err == nil {
		t.Error("Expected error for non-AXFR type")
	}

	// Multiple questions
	query = &dns.Msg{}
	query.Question = []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeAXFR, Qclass: dns.ClassINET},
		{Name: "example.com.", Qtype: dns.TypeAXFR, Qclass: dns.ClassINET},
	}
	err = ValidateAXFRQuery(query)
	if err == nil {
		t.Error("Expected error for multiple questions")
	}
}

func TestAXFRHandler_HandleAXFR(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewAXFRHandler(zone)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAXFR)

	// Allowed client
	messages, err := handler.HandleAXFR(query, "192.0.2.1")
	if err != nil {
		t.Fatalf("HandleAXFR failed: %v", err)
	}

	if len(messages) == 0 {
		t.Fatal("Expected at least one message")
	}

	// Check first message has records
	if len(messages[0].Answer) == 0 {
		t.Error("Expected answer section to have records")
	}

	// Check first record is SOA
	if messages[0].Answer[0].Header().Rrtype != dns.TypeSOA {
		t.Error("First record should be SOA")
	}

	// Check last record is SOA
	lastMsg := messages[len(messages)-1]
	lastRecord := lastMsg.Answer[len(lastMsg.Answer)-1]
	if lastRecord.Header().Rrtype != dns.TypeSOA {
		t.Error("Last record should be SOA")
	}
}

func TestAXFRHandler_HandleAXFR_ACLDenied(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewAXFRHandler(zone)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAXFR)

	// Not allowed client
	_, err := handler.HandleAXFR(query, "192.0.2.99")
	if err == nil {
		t.Error("Expected ACL denial for unauthorized client")
	}
}

func TestAXFRHandler_HandleAXFR_EmptyZone(t *testing.T) {
	t.Parallel()
	zone := NewZone(ZoneConfig{
		Origin:      "example.com",
		TransferACL: []string{"any"},
	})
	handler := NewAXFRHandler(zone)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAXFR)

	_, err := handler.HandleAXFR(query, "192.0.2.1")
	if err == nil {
		t.Error("Expected error for empty zone")
	}
}

// IXFR Tests

func TestValidateIXFRQuery(t *testing.T) {
	t.Parallel()
	// Valid IXFR query
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeIXFR)

	// Add client SOA in authority section
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Serial: 2024010100,
	}
	query.Ns = append(query.Ns, soa)

	err := ValidateIXFRQuery(query)
	if err != nil {
		t.Errorf("Valid IXFR query failed validation: %v", err)
	}

	// Wrong type
	query = &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeA)
	err = ValidateIXFRQuery(query)
	if err == nil {
		t.Error("Expected error for non-IXFR type")
	}
}

func TestExtractClientSerial(t *testing.T) {
	t.Parallel()
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeIXFR)

	// No SOA in authority
	serial, ok := ExtractClientSerial(query)
	if ok {
		t.Error("Expected no serial without SOA")
	}

	// Add SOA
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Serial: 2024010100,
	}
	query.Ns = append(query.Ns, soa)

	serial, ok = ExtractClientSerial(query)
	if !ok {
		t.Fatal("Expected to extract serial")
	}

	if serial != 2024010100 {
		t.Errorf("Expected serial 2024010100, got %d", serial)
	}
}

func TestIXFRHandler_HandleIXFR_UpToDate(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewIXFRHandler(zone)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeIXFR)

	// Client has same serial
	currentSerial := zone.GetSerial()
	messages, needsAXFR, err := handler.HandleIXFR(query, "192.0.2.1", currentSerial)
	if err != nil {
		t.Fatalf("HandleIXFR failed: %v", err)
	}

	if needsAXFR {
		t.Error("Should not need AXFR when up-to-date")
	}

	if len(messages) != 1 {
		t.Errorf("Expected 1 message for up-to-date response, got %d", len(messages))
	}

	// Should contain single SOA
	if len(messages[0].Answer) != 1 {
		t.Errorf("Expected 1 SOA in answer, got %d", len(messages[0].Answer))
	}
}

func TestIXFRHandler_HandleIXFR_NeedsDelta(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewIXFRHandler(zone)

	oldSerial := zone.GetSerial()

	// Simulate zone update
	zone.IncrementSerial()
	newSerial := zone.GetSerial()

	// Record delta
	deleted := []dns.RR{}
	added := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "new.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 20},
		},
	}
	handler.RecordDelta(oldSerial, newSerial, deleted, added)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeIXFR)

	// Client has old serial
	messages, needsAXFR, err := handler.HandleIXFR(query, "192.0.2.1", oldSerial)
	if err != nil {
		t.Fatalf("HandleIXFR failed: %v", err)
	}

	if needsAXFR {
		t.Error("Should not need AXFR when delta is available")
	}

	if len(messages) == 0 {
		t.Fatal("Expected IXFR response messages")
	}

	// Check structure includes SOAs and added record
	answerCount := len(messages[0].Answer)
	if answerCount < 4 { // Current SOA + old SOA + new SOA + added RR + current SOA
		t.Errorf("Expected at least 4 records in IXFR response, got %d", answerCount)
	}
}

func TestIXFRHandler_HandleIXFR_FallbackToAXFR(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewIXFRHandler(zone)

	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeIXFR)

	// Client has very old serial with no delta
	_, needsAXFR, err := handler.HandleIXFR(query, "192.0.2.1", 2024010000)
	if err != nil {
		t.Fatalf("HandleIXFR failed: %v", err)
	}

	if !needsAXFR {
		t.Error("Expected fallback to AXFR when delta unavailable")
	}
}

func TestIXFRHandler_RecordDelta(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewIXFRHandler(zone)

	oldSerial := uint32(100)
	newSerial := uint32(101)

	deleted := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "old.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 99},
		},
	}

	added := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "new.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 100},
		},
	}

	handler.RecordDelta(oldSerial, newSerial, deleted, added)

	// Verify delta was recorded
	delta, exists := handler.deltaLog[newSerial]
	if !exists {
		t.Fatal("Delta was not recorded")
	}

	if delta.FromSerial != oldSerial {
		t.Errorf("Expected FromSerial %d, got %d", oldSerial, delta.FromSerial)
	}

	if delta.ToSerial != newSerial {
		t.Errorf("Expected ToSerial %d, got %d", newSerial, delta.ToSerial)
	}

	if len(delta.Deleted) != 1 || len(delta.Added) != 1 {
		t.Error("Expected 1 deleted and 1 added record")
	}
}

func TestIXFRHandler_PruneDeltaLog(t *testing.T) {
	t.Parallel()
	zone := NewZone(ZoneConfig{
		Origin:      "example.com",
		TransferACL: []string{"any"},
	})

	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Serial: 100,
	}
	zone.AddRecord(soa)

	handler := NewIXFRHandler(zone)

	// Add multiple deltas
	for i := uint32(101); i <= 110; i++ {
		handler.RecordDelta(i-1, i, []dns.RR{}, []dns.RR{})
		zone.Serial.Store(i)
	}

	if len(handler.deltaLog) != 10 {
		t.Fatalf("Expected 10 deltas, got %d", len(handler.deltaLog))
	}

	// Prune to keep only 5
	handler.PruneDeltaLog(5)

	if len(handler.deltaLog) != 5 {
		t.Errorf("Expected 5 deltas after pruning, got %d", len(handler.deltaLog))
	}

	// Should keep most recent 5
	for serial := uint32(106); serial <= 110; serial++ {
		if _, exists := handler.deltaLog[serial]; !exists {
			t.Errorf("Expected to keep recent delta %d", serial)
		}
	}
}

func TestSerialCompare(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s1       uint32
		s2       uint32
		expected int
	}{
		{100, 100, 0},       // Equal
		{100, 101, -1},      // s1 < s2 (normal case)
		{101, 100, 1},       // s1 > s2 (normal case)
		{0, 1, -1},          // 0 < 1
		{1, 2147483647, -1}, // 1 < 2147483647 (maximum difference that's < half-range)
		{2147483648, 1, 1},  // 2147483648 > 1 (wrap-around)
		{4294967295, 0, -1}, // 4294967295 < 0 (wrap-around, 0 is newer)
		{0, 4294967295, 1},  // 0 > 4294967295 (0 is newer)
		{100, 1000, -1},     // 100 < 1000 (normal increment)
	}

	for _, tt := range tests {
		result := serialCompare(tt.s1, tt.s2)
		if result != tt.expected {
			t.Errorf("serialCompare(%d, %d) = %d, want %d", tt.s1, tt.s2, result, tt.expected)
		}
	}
}

func TestAXFRHandler_SplitIntoMessages(t *testing.T) {
	t.Parallel()
	zone := createTestZone()

	// Add many records to trigger splitting
	for i := range 150 {
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(fmt.Sprintf("host%d.example.com", i)),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, byte(i % 256)},
		}
		zone.AddRecord(a)
	}

	handler := NewAXFRHandler(zone)
	query := &dns.Msg{}
	query.SetQuestion("example.com.", dns.TypeAXFR)

	records := zone.GetAllRecordsOrdered()
	messages := handler.splitIntoMessages(query, records)

	// Should be split into multiple messages
	if len(messages) < 2 {
		t.Errorf("Expected multiple messages for large zone, got %d", len(messages))
	}

	// Check all messages are valid responses
	for i, msg := range messages {
		if !msg.Response {
			t.Errorf("Message %d is not marked as response", i)
		}
		if !msg.Authoritative {
			t.Errorf("Message %d is not marked as authoritative", i)
		}
	}
}

func TestIXFRHandler_FindDeltas(t *testing.T) {
	t.Parallel()
	zone := createTestZone()
	handler := NewIXFRHandler(zone)

	// Create chain of deltas
	for serial := uint32(101); serial <= 105; serial++ {
		handler.RecordDelta(serial-1, serial, []dns.RR{}, []dns.RR{})
	}

	// Should find deltas from 100 to 105
	deltas, ok := handler.findDeltas(100, 105)
	if !ok {
		t.Fatal("Expected to find delta chain")
	}

	if len(deltas) != 5 {
		t.Errorf("Expected 5 deltas, got %d", len(deltas))
	}

	// Missing delta in middle - should fail
	delete(handler.deltaLog, 103)
	_, ok = handler.findDeltas(100, 105)
	if ok {
		t.Error("Expected to fail with missing delta")
	}
}
