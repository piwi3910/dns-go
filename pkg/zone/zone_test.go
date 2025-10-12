package zone_test

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/zone"
)

func TestNewZone(t *testing.T) {
	t.Parallel()
	config := zone.Config{
		Origin:      "example.com",
		TransferACL: []string{"192.0.2.1"},
		UpdateACL:   nil,
	}

	z := zone.NewZone(config)

	if z.Origin != "example.com." {
		t.Errorf("Expected origin example.com., got %s", z.Origin)
	}

	if len(z.TransferACL) != 1 {
		t.Errorf("Expected 1 ACL entry, got %d", len(z.TransferACL))
	}
}

func TestZone_AddRecord(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	// Add A record
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
			Rdlength: 0,
		},
		A: []byte{192, 0, 2, 1},
	}

	err := z.AddRecord(a)
	if err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	// Retrieve it
	records := z.GetRecords("www.example.com.", dns.TypeA)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	aRecord, ok := records[0].(*dns.A)
	if !ok {
		t.Fatal("Expected A record")
	}

	if aRecord.A.String() != "192.0.2.1" {
		t.Errorf("Expected 192.0.2.1, got %s", aRecord.A.String())
	}
}

func TestZone_AddRecord_OutOfZone(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	// Try to add record outside zone
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.otherdomain.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
			Rdlength: 0,
		},
		A: []byte{192, 0, 2, 1},
	}

	err := z.AddRecord(a)
	if err == nil {
		t.Error("Expected error when adding out-of-zone record")
	}
}

func TestZone_AddSOA(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
			Rdlength: 0,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}

	err := z.AddRecord(soa)
	if err != nil {
		t.Fatalf("Failed to add SOA: %v", err)
	}

	if z.SOA == nil {
		t.Fatal("Expected SOA to be set")
	}

	if z.GetSerial() != 2024010101 {
		t.Errorf("Expected serial 2024010101, got %d", z.GetSerial())
	}
}

func TestZone_GetAllRecords(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	// Add multiple records for same owner
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
			Rdlength: 0,
		},
		A: []byte{192, 0, 2, 1},
	}
	aaaa := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   "www.example.com.",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    300,
			Rdlength: 0,
		},
		AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	_ = z.AddRecord(a)
	_ = z.AddRecord(aaaa)

	records := z.GetAllRecords("www.example.com.")
	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}
}

func TestZone_IncrementSerial(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
			Rdlength: 0,
		},
		Ns:      "",
		Mbox:    "",
		Serial:  2024010101,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	_ = z.AddRecord(soa)

	oldSerial := z.GetSerial()
	newSerial := z.IncrementSerial()

	if newSerial != oldSerial+1 {
		t.Errorf("Expected serial %d, got %d", oldSerial+1, newSerial)
	}

	if z.SOA.Serial != newSerial {
		t.Error("SOA serial not updated")
	}
}

func TestZone_IsTransferAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		acl      []string
		clientIP string
		allowed  bool
	}{
		{"Empty ACL", []string{}, "192.0.2.1", false},
		{"Explicit allow", []string{"192.0.2.1"}, "192.0.2.1", true},
		{"Not in ACL", []string{"192.0.2.1"}, "192.0.2.2", false},
		{"Any allowed", []string{"any"}, "192.0.2.1", true},
		{"Multiple ACL", []string{"192.0.2.1", "192.0.2.2"}, "192.0.2.2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			z := zone.NewZone(zone.Config{
				Origin:      "example.com",
				TransferACL: tt.acl,
				UpdateACL:   nil,
			})

			result := z.IsTransferAllowed(tt.clientIP)
			if result != tt.allowed {
				t.Errorf("Expected %v, got %v", tt.allowed, result)
			}
		})
	}
}

func TestZone_RecordCount(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	if z.RecordCount() != 0 {
		t.Error("Expected empty zone to have 0 records")
	}

	// Add records
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600, Rdlength: 0},
		Ns:      "",
		Mbox:    "",
		Serial:  1,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
		A:   []byte{192, 0, 2, 1},
	}

	_ = z.AddRecord(soa)
	_ = z.AddRecord(a)

	if z.RecordCount() != 2 {
		t.Errorf("Expected 2 records, got %d", z.RecordCount())
	}
}

func TestZone_Clear(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	// Add records
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600, Rdlength: 0},
		Ns:      "",
		Mbox:    "",
		Serial:  2024010101,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	_ = z.AddRecord(soa)

	// Clear
	z.Clear()

	if z.RecordCount() != 0 {
		t.Errorf("Expected 0 records after clear, got %d", z.RecordCount())
	}

	if z.SOA != nil {
		t.Error("Expected SOA to be nil after clear")
	}

	if z.GetSerial() != 0 {
		t.Error("Expected serial to be 0 after clear")
	}
}

func TestZone_Clone(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{
		Origin:      "example.com",
		TransferACL: []string{"192.0.2.1"},
		UpdateACL:   nil,
	})

	// Add SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600, Rdlength: 0},
		Ns:      "",
		Mbox:    "",
		Serial:  2024010101,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	_ = z.AddRecord(soa)

	// Add A record
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
		A:   []byte{192, 0, 2, 1},
	}
	_ = z.AddRecord(a)

	// Clone
	cloned := z.Clone()

	// Verify clone
	if cloned.Origin != z.Origin {
		t.Error("Cloned origin doesn't match")
	}

	if cloned.GetSerial() != z.GetSerial() {
		t.Error("Cloned serial doesn't match")
	}

	if cloned.RecordCount() != z.RecordCount() {
		t.Error("Cloned record count doesn't match")
	}

	// Verify deep copy - modify original shouldn't affect clone
	z.IncrementSerial()
	if cloned.GetSerial() == z.GetSerial() {
		t.Error("Clone was not deep copied - serial changed")
	}
}

func TestZone_GetAllRecordsOrdered(t *testing.T) {
	t.Parallel()
	z := zone.NewZone(zone.Config{Origin: "example.com", TransferACL: nil, UpdateACL: nil})

	// Add SOA
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600, Rdlength: 0},
		Ns:      "",
		Mbox:    "",
		Serial:  2024010101,
		Refresh: 0,
		Retry:   0,
		Expire:  0,
		Minttl:  0,
	}
	_ = z.AddRecord(soa)

	// Add other records
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
		A:   []byte{192, 0, 2, 1},
	}
	mx := &dns.MX{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300, Rdlength: 0},
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	_ = z.AddRecord(a)
	_ = z.AddRecord(mx)

	records := z.GetAllRecordsOrdered()

	// Should have SOA, A, MX, SOA (per RFC 5936)
	if len(records) != 4 {
		t.Fatalf("Expected 4 records (SOA, A, MX, SOA), got %d", len(records))
	}

	// First should be SOA
	if records[0].Header().Rrtype != dns.TypeSOA {
		t.Error("First record should be SOA")
	}

	// Last should be SOA
	if records[len(records)-1].Header().Rrtype != dns.TypeSOA {
		t.Error("Last record should be SOA")
	}
}
