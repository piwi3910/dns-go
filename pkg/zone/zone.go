package zone

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Zone represents an authoritative DNS zone.
type Zone struct {
	// Origin is the zone's origin (e.g., "example.com.")
	Origin string

	// SOA is the Start of Authority record for this zone
	SOA *dns.SOA

	// Records holds all resource records in the zone
	// Map: owner name -> RR type -> []RR
	Records map[string]map[uint16][]dns.RR

	// Serial is the current zone serial number
	Serial atomic.Uint32

	// LastModified is when the zone was last updated
	LastModified time.Time

	// mu protects the zone data for copy-on-write updates
	mu sync.RWMutex

	// TransferACL lists allowed clients for zone transfers
	TransferACL []string

	// UpdateACL lists allowed clients for dynamic updates
	UpdateACL []string
}

// ZoneConfig holds configuration for a zone.
type ZoneConfig struct {
	Origin      string
	TransferACL []string
	UpdateACL   []string
}

// NewZone creates a new empty zone.
func NewZone(config ZoneConfig) *Zone {
	return &Zone{
		Origin:       dns.Fqdn(config.Origin),
		SOA:          nil,
		Records:      make(map[string]map[uint16][]dns.RR),
		Serial:       atomic.Uint32{},
		LastModified: time.Now(),
		mu:           sync.RWMutex{},
		TransferACL:  config.TransferACL,
		UpdateACL:    config.UpdateACL,
	}
}

// AddRecord adds a resource record to the zone
// Thread-safe with copy-on-write semantics.
func (z *Zone) AddRecord(rr dns.RR) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	// Normalize owner name
	owner := dns.Fqdn(rr.Header().Name)

	// Ensure owner is within zone
	if !dns.IsSubDomain(z.Origin, owner) {
		return fmt.Errorf("record %s is not within zone %s", owner, z.Origin)
	}

	// Initialize nested map if needed
	if z.Records[owner] == nil {
		z.Records[owner] = make(map[uint16][]dns.RR)
	}

	rrType := rr.Header().Rrtype

	// Handle SOA specially
	if rrType == dns.TypeSOA {
		if soa, ok := rr.(*dns.SOA); ok {
			z.SOA = soa
			z.Serial.Store(soa.Serial)
		}
	}

	// Add record
	z.Records[owner][rrType] = append(z.Records[owner][rrType], rr)
	z.LastModified = time.Now()

	return nil
}

// GetRecords retrieves all records for a given owner name and type.
func (z *Zone) GetRecords(owner string, rrType uint16) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()

	owner = dns.Fqdn(owner)

	if typeMap, ok := z.Records[owner]; ok {
		if records, ok := typeMap[rrType]; ok {
			// Return copy to prevent modification
			result := make([]dns.RR, len(records))
			for i, rr := range records {
				result[i] = dns.Copy(rr)
			}

			return result
		}
	}

	return nil
}

// GetAllRecords retrieves all records for a given owner name.
func (z *Zone) GetAllRecords(owner string) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()

	owner = dns.Fqdn(owner)

	typeMap, ok := z.Records[owner]
	if !ok {
		return nil
	}

	var result []dns.RR
	for _, records := range typeMap {
		for _, rr := range records {
			result = append(result, dns.Copy(rr))
		}
	}

	return result
}

// GetAllRecordsOrdered returns all records in the zone in a consistent order
// Used for zone transfers (AXFR).
func (z *Zone) GetAllRecordsOrdered() []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()

	var result []dns.RR

	// SOA first
	if z.SOA != nil {
		result = append(result, dns.Copy(z.SOA))
	}

	// All other records
	for _, typeMap := range z.Records {
		for rrType, records := range typeMap {
			if rrType == dns.TypeSOA {
				continue // Already added
			}
			for _, rr := range records {
				result = append(result, dns.Copy(rr))
			}
		}
	}

	// SOA last (per RFC 5936)
	if z.SOA != nil {
		result = append(result, dns.Copy(z.SOA))
	}

	return result
}

// IncrementSerial increments the zone's serial number.
func (z *Zone) IncrementSerial() uint32 {
	z.mu.Lock()
	defer z.mu.Unlock()

	// RFC 1982 serial number arithmetic
	newSerial := z.Serial.Add(1)

	// Update SOA
	if z.SOA != nil {
		z.SOA.Serial = newSerial
	}

	z.LastModified = time.Now()

	return newSerial
}

// GetSerial returns the current zone serial number.
func (z *Zone) GetSerial() uint32 {
	return z.Serial.Load()
}

// IsTransferAllowed checks if a client is allowed to perform zone transfers.
func (z *Zone) IsTransferAllowed(clientIP string) bool {
	z.mu.RLock()
	defer z.mu.RUnlock()

	// If no ACL, deny all
	if len(z.TransferACL) == 0 {
		return false
	}

	// Check if client is in ACL
	for _, allowed := range z.TransferACL {
		if allowed == clientIP || allowed == "any" {
			return true
		}
	}

	return false
}

// RecordCount returns the total number of resource records in the zone.
func (z *Zone) RecordCount() int {
	z.mu.RLock()
	defer z.mu.RUnlock()

	count := 0
	for _, typeMap := range z.Records {
		for _, records := range typeMap {
			count += len(records)
		}
	}

	return count
}

// Clear removes all records from the zone.
func (z *Zone) Clear() {
	z.mu.Lock()
	defer z.mu.Unlock()

	z.Records = make(map[string]map[uint16][]dns.RR)
	z.SOA = nil
	z.Serial.Store(0)
	z.LastModified = time.Now()
}

// Clone creates a deep copy of the zone.
func (z *Zone) Clone() *Zone {
	z.mu.RLock()
	defer z.mu.RUnlock()

	newZone := &Zone{
		Origin:       z.Origin,
		SOA:          nil,
		Records:      make(map[string]map[uint16][]dns.RR),
		Serial:       atomic.Uint32{},
		LastModified: z.LastModified,
		mu:           sync.RWMutex{},
		TransferACL:  make([]string, len(z.TransferACL)),
		UpdateACL:    make([]string, len(z.UpdateACL)),
	}

	// Copy ACLs
	copy(newZone.TransferACL, z.TransferACL)
	copy(newZone.UpdateACL, z.UpdateACL)

	// Copy SOA
	if z.SOA != nil {
		newZone.SOA = dns.Copy(z.SOA).(*dns.SOA)
	}
	newZone.Serial.Store(z.Serial.Load())

	// Deep copy records
	for owner, typeMap := range z.Records {
		newZone.Records[owner] = make(map[uint16][]dns.RR)
		for rrType, records := range typeMap {
			newZone.Records[owner][rrType] = make([]dns.RR, len(records))
			for i, rr := range records {
				newZone.Records[owner][rrType][i] = dns.Copy(rr)
			}
		}
	}

	return newZone
}
