package zone

import (
	"testing"

	"github.com/miekg/dns"
)

func TestManager_AddAndGetZone(t *testing.T) {
	m := NewManager()

	zone := NewZone(Config{Origin: "example.com."})
	m.AddZone(zone)

	retrieved := m.GetZone("example.com.")
	if retrieved == nil {
		t.Fatal("Expected to retrieve zone")
	}

	if retrieved.Origin != "example.com." {
		t.Errorf("Expected origin example.com., got %s", retrieved.Origin)
	}
}

func TestManager_FindZone(t *testing.T) {
	m := NewManager()

	// Add a zone
	zone := NewZone(Config{Origin: "example.com."})
	m.AddZone(zone)

	tests := []struct {
		name     string
		query    string
		expected string
	}{
		{"exact match", "example.com.", "example.com."},
		{"subdomain", "www.example.com.", "example.com."},
		{"deep subdomain", "a.b.c.example.com.", "example.com."},
		{"no match", "other.com.", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := m.FindZone(tt.query)
			if tt.expected == "" {
				if found != nil {
					t.Errorf("Expected no zone for %s, got %s", tt.query, found.Origin)
				}
			} else {
				if found == nil {
					t.Errorf("Expected zone %s for %s, got nil", tt.expected, tt.query)
				} else if found.Origin != tt.expected {
					t.Errorf("Expected zone %s for %s, got %s", tt.expected, tt.query, found.Origin)
				}
			}
		})
	}
}

func TestManager_Query_Success(t *testing.T) {
	m := NewManager()

	// Create zone with records
	zone := NewZone(Config{Origin: "example.com."})

	// Add SOA
	soa, _ := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400")
	_ = zone.AddRecord(soa)

	// Add A record
	a, _ := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	_ = zone.AddRecord(a)

	// Add NS record
	ns, _ := dns.NewRR("example.com. 3600 IN NS ns1.example.com.")
	_ = zone.AddRecord(ns)

	m.AddZone(zone)

	// Query for the A record
	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeA)

	response, handled := m.Query(query)

	if !handled {
		t.Fatal("Expected query to be handled")
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got rcode %d", response.Rcode)
	}

	if !response.Authoritative {
		t.Error("Expected authoritative response")
	}

	if len(response.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(response.Answer))
	}

	// Check the answer is correct
	if aRecord, ok := response.Answer[0].(*dns.A); ok {
		if aRecord.A.String() != "192.0.2.1" {
			t.Errorf("Expected 192.0.2.1, got %s", aRecord.A.String())
		}
	} else {
		t.Error("Expected A record in answer")
	}
}

func TestManager_Query_NXDOMAIN(t *testing.T) {
	m := NewManager()

	zone := NewZone(Config{Origin: "example.com."})
	soa, _ := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400")
	_ = zone.AddRecord(soa)
	m.AddZone(zone)

	// Query for non-existent name
	query := new(dns.Msg)
	query.SetQuestion("nonexistent.example.com.", dns.TypeA)

	response, handled := m.Query(query)

	if !handled {
		t.Fatal("Expected query to be handled (NXDOMAIN is still handled)")
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if response.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got rcode %d", response.Rcode)
	}

	// Should have SOA in authority section
	if len(response.Ns) == 0 {
		t.Error("Expected SOA in authority section")
	}
}

func TestManager_Query_NoData(t *testing.T) {
	m := NewManager()

	zone := NewZone(Config{Origin: "example.com."})
	soa, _ := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 1800 604800 86400")
	_ = zone.AddRecord(soa)

	// Add A record for www
	a, _ := dns.NewRR("www.example.com. 300 IN A 192.0.2.1")
	_ = zone.AddRecord(a)

	m.AddZone(zone)

	// Query for AAAA (which doesn't exist for www)
	query := new(dns.Msg)
	query.SetQuestion("www.example.com.", dns.TypeAAAA)

	response, handled := m.Query(query)

	if !handled {
		t.Fatal("Expected query to be handled (NODATA)")
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	// Should be NOERROR with empty answer (NODATA)
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR for NODATA, got rcode %d", response.Rcode)
	}

	if len(response.Answer) != 0 {
		t.Errorf("Expected empty answer for NODATA, got %d answers", len(response.Answer))
	}
}

func TestManager_Query_NotAuthoritative(t *testing.T) {
	m := NewManager()

	// Zone for example.com
	zone := NewZone(Config{Origin: "example.com."})
	m.AddZone(zone)

	// Query for different domain
	query := new(dns.Msg)
	query.SetQuestion("other.com.", dns.TypeA)

	response, handled := m.Query(query)

	if handled {
		t.Error("Expected query NOT to be handled for non-authoritative domain")
	}

	if response != nil {
		t.Error("Expected nil response for non-authoritative domain")
	}
}

func TestManager_RemoveZone(t *testing.T) {
	m := NewManager()

	zone := NewZone(Config{Origin: "example.com."})
	m.AddZone(zone)

	if m.ZoneCount() != 1 {
		t.Errorf("Expected 1 zone, got %d", m.ZoneCount())
	}

	m.RemoveZone("example.com.")

	if m.ZoneCount() != 0 {
		t.Errorf("Expected 0 zones after removal, got %d", m.ZoneCount())
	}

	if m.GetZone("example.com.") != nil {
		t.Error("Zone should be removed")
	}
}

func TestManager_GetAllZones(t *testing.T) {
	m := NewManager()

	zone1 := NewZone(Config{Origin: "example.com."})
	zone2 := NewZone(Config{Origin: "test.com."})

	m.AddZone(zone1)
	m.AddZone(zone2)

	origins := m.GetAllZones()

	if len(origins) != 2 {
		t.Errorf("Expected 2 zones, got %d", len(origins))
	}

	// Check both zones are present
	found := make(map[string]bool)
	for _, o := range origins {
		found[o] = true
	}

	if !found["example.com."] || !found["test.com."] {
		t.Errorf("Expected both zones, got %v", origins)
	}
}
