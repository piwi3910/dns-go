package zone

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Manager manages multiple DNS zones for authoritative responses.
type Manager struct {
	// zones maps zone origins to Zone objects
	zones map[string]*Zone

	// mu protects the zones map
	mu sync.RWMutex
}

// NewManager creates a new zone manager.
func NewManager() *Manager {
	return &Manager{
		zones: make(map[string]*Zone),
		mu:    sync.RWMutex{},
	}
}

// AddZone adds a zone to the manager.
func (m *Manager) AddZone(zone *Zone) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.zones[zone.Origin] = zone
}

// RemoveZone removes a zone from the manager.
func (m *Manager) RemoveZone(origin string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	origin = dns.Fqdn(origin)
	delete(m.zones, origin)
}

// GetZone returns the zone for a given origin.
func (m *Manager) GetZone(origin string) *Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	origin = dns.Fqdn(origin)
	return m.zones[origin]
}

// FindZone finds the most specific zone that contains the given name.
// Returns nil if no zone is found.
func (m *Manager) FindZone(name string) *Zone {
	m.mu.RLock()
	defer m.mu.RUnlock()

	name = dns.Fqdn(name)

	// Try exact match first
	if zone, ok := m.zones[name]; ok {
		return zone
	}

	// Walk up the domain tree to find a parent zone
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		parent := dns.Fqdn(strings.Join(labels[i:], "."))
		if zone, ok := m.zones[parent]; ok {
			return zone
		}
	}

	return nil
}

// Query queries for records in any managed zone.
// Returns the response message and a boolean indicating if the query was handled.
// If handled is false, the query should be forwarded to upstream resolvers.
func (m *Manager) Query(query *dns.Msg) (*dns.Msg, bool) {
	if len(query.Question) == 0 {
		return nil, false
	}

	q := query.Question[0]
	name := q.Name
	qtype := q.Qtype

	// Find the zone that contains this name
	zone := m.FindZone(name)
	if zone == nil {
		// No zone found - not authoritative
		return nil, false
	}

	// Build response
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true

	// Get records for the requested name and type
	records := zone.GetRecords(name, qtype)

	if len(records) > 0 {
		// Found records
		response.Answer = records

		// Add NS records to authority section if not querying for NS
		if qtype != dns.TypeNS {
			nsRecords := zone.GetRecords(zone.Origin, dns.TypeNS)
			response.Ns = nsRecords
		}

		return response, true
	}

	// Check if the name exists with other record types (NOERROR but empty answer)
	allRecords := zone.GetAllRecords(name)
	if len(allRecords) > 0 {
		// Name exists but no records of requested type
		// Return NOERROR with empty answer (handled)
		if zone.SOA != nil {
			response.Ns = []dns.RR{dns.Copy(zone.SOA)}
		}
		return response, true
	}

	// Check if name is under this zone (NXDOMAIN case)
	if dns.IsSubDomain(zone.Origin, name) {
		// Name doesn't exist - return NXDOMAIN
		response.Rcode = dns.RcodeNameError
		if zone.SOA != nil {
			response.Ns = []dns.RR{dns.Copy(zone.SOA)}
		}
		return response, true
	}

	// Not in our zone
	return nil, false
}

// LoadZoneFile loads a zone from a zone file.
func (m *Manager) LoadZoneFile(path string, origin string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open zone file: %w", err)
	}
	defer file.Close()

	origin = dns.Fqdn(origin)
	zone := NewZone(Config{Origin: origin})

	// Parse zone file
	zp := dns.NewZoneParser(bufio.NewReader(file), origin, path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zone.AddRecord(rr); err != nil {
			return fmt.Errorf("failed to add record: %w", err)
		}
	}

	if err := zp.Err(); err != nil {
		return fmt.Errorf("zone file parse error: %w", err)
	}

	m.AddZone(zone)
	return nil
}

// ZoneCount returns the number of zones managed.
func (m *Manager) ZoneCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.zones)
}

// GetAllZones returns a list of all zone origins.
func (m *Manager) GetAllZones() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	origins := make([]string, 0, len(m.zones))
	for origin := range m.zones {
		origins = append(origins, origin)
	}
	return origins
}

// GetOrCreateZone returns an existing zone or creates a new one.
func (m *Manager) GetOrCreateZone(origin string) *Zone {
	m.mu.Lock()
	defer m.mu.Unlock()

	origin = dns.Fqdn(origin)
	if zone, exists := m.zones[origin]; exists {
		return zone
	}

	zone := NewZone(Config{Origin: origin})
	m.zones[origin] = zone
	return zone
}

// DeleteZone removes a zone from the manager and returns an error if not found.
func (m *Manager) DeleteZone(origin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	origin = dns.Fqdn(origin)
	if _, exists := m.zones[origin]; !exists {
		return fmt.Errorf("zone %s not found", origin)
	}
	delete(m.zones, origin)
	return nil
}
