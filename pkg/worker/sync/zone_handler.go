// Package sync provides zone synchronization for workers.
package sync

import (
	"fmt"
	"log"
	"sync"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/worker"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"github.com/piwi3910/dns-go/pkg/zone"
)

// ZoneHandler handles zone data management for the worker.
type ZoneHandler struct {
	mu          sync.RWMutex
	zoneManager *zone.Manager
	serials     map[string]uint32 // origin -> serial
}

// NewZoneHandler creates a new zone handler.
func NewZoneHandler(zoneManager *zone.Manager) *ZoneHandler {
	return &ZoneHandler{
		zoneManager: zoneManager,
		serials:     make(map[string]uint32),
	}
}

// ApplyZone applies zone data to the local zone manager.
func (h *ZoneHandler) ApplyZone(zoneData *pb.ZoneData) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if zoneData == nil {
		return fmt.Errorf("zone data is nil")
	}

	if zoneData.Origin == "" {
		return fmt.Errorf("zone origin is required")
	}

	// Normalize origin
	origin := dns.Fqdn(zoneData.Origin)

	// Create zone in manager
	z := h.zoneManager.GetOrCreateZone(origin)
	if z == nil {
		return fmt.Errorf("failed to get or create zone %s", origin)
	}

	// Apply SOA record if present
	if zoneData.Soa != nil {
		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   origin,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    zoneData.Soa.Minimum,
			},
			Ns:      dns.Fqdn(zoneData.Soa.PrimaryNs),
			Mbox:    dns.Fqdn(zoneData.Soa.AdminEmail),
			Serial:  zoneData.Soa.Serial,
			Refresh: zoneData.Soa.Refresh,
			Retry:   zoneData.Soa.Retry,
			Expire:  zoneData.Soa.Expire,
			Minttl:  zoneData.Soa.Minimum,
		}
		z.SetSOA(soa)
	}

	// Apply records
	for _, rec := range zoneData.Records {
		rr, err := parseRecord(rec, origin)
		if err != nil {
			log.Printf("Warning: failed to parse record %s %s: %v", rec.Name, rec.Type, err)
			continue
		}
		if err := z.AddRecord(rr); err != nil {
			log.Printf("Warning: failed to add record %s %s: %v", rec.Name, rec.Type, err)
		}
	}

	// Update serial tracking
	h.serials[origin] = zoneData.Serial

	log.Printf("Applied zone %s (serial %d, %d records)", origin, zoneData.Serial, len(zoneData.Records))

	return nil
}

// ApplyZoneUpdate applies an incremental zone update.
func (h *ZoneHandler) ApplyZoneUpdate(update *pb.ZoneUpdate) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if update == nil {
		return fmt.Errorf("update is nil")
	}

	origin := dns.Fqdn(update.Origin)

	switch update.Type {
	case pb.ZoneUpdate_FULL:
		// Full zone transfer - apply complete zone data
		if update.Data == nil {
			return fmt.Errorf("full update requires zone data")
		}
		h.mu.Unlock()
		err := h.ApplyZone(update.Data)
		h.mu.Lock()
		return err

	case pb.ZoneUpdate_INCREMENTAL:
		// Incremental update - apply changes
		z := h.zoneManager.GetZone(origin)
		if z == nil {
			return fmt.Errorf("zone %s not found for incremental update", origin)
		}

		for _, change := range update.Changes {
			if err := h.applyRecordChange(z, change, origin); err != nil {
				log.Printf("Warning: failed to apply change: %v", err)
			}
		}

		h.serials[origin] = update.Serial
		log.Printf("Applied incremental update to zone %s (serial %d, %d changes)",
			origin, update.Serial, len(update.Changes))

	case pb.ZoneUpdate_DELETE:
		// Zone deletion
		if err := h.zoneManager.DeleteZone(origin); err != nil {
			return fmt.Errorf("failed to delete zone %s: %w", origin, err)
		}
		delete(h.serials, origin)
		log.Printf("Deleted zone %s", origin)
	}

	return nil
}

// DeleteZone removes a zone from the local zone manager.
func (h *ZoneHandler) DeleteZone(origin string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	origin = dns.Fqdn(origin)

	if err := h.zoneManager.DeleteZone(origin); err != nil {
		return fmt.Errorf("failed to delete zone %s: %w", origin, err)
	}

	delete(h.serials, origin)
	log.Printf("Deleted zone %s", origin)

	return nil
}

// GetZoneSerial returns the current serial for a zone.
func (h *ZoneHandler) GetZoneSerial(origin string) (uint32, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	origin = dns.Fqdn(origin)

	serial, exists := h.serials[origin]
	if !exists {
		return 0, fmt.Errorf("zone %s not found", origin)
	}

	return serial, nil
}

// applyRecordChange applies a single record change to a zone.
func (h *ZoneHandler) applyRecordChange(z *zone.Zone, change *pb.RecordChange, origin string) error {
	switch change.Type {
	case pb.RecordChange_ADD:
		rr, err := parseRecord(change.Record, origin)
		if err != nil {
			return fmt.Errorf("failed to parse record for add: %w", err)
		}
		return z.AddRecord(rr)

	case pb.RecordChange_DELETE:
		rr, err := parseRecord(change.Record, origin)
		if err != nil {
			return fmt.Errorf("failed to parse record for delete: %w", err)
		}
		return z.RemoveRecord(rr)

	case pb.RecordChange_MODIFY:
		// Remove old record
		if change.OldRecord != nil {
			oldRR, err := parseRecord(change.OldRecord, origin)
			if err != nil {
				return fmt.Errorf("failed to parse old record: %w", err)
			}
			if err := z.RemoveRecord(oldRR); err != nil {
				log.Printf("Warning: failed to remove old record: %v", err)
			}
		}
		// Add new record
		newRR, err := parseRecord(change.Record, origin)
		if err != nil {
			return fmt.Errorf("failed to parse new record: %w", err)
		}
		return z.AddRecord(newRR)
	}

	return nil
}

// parseRecord parses a protobuf DNSRecord into a dns.RR.
func parseRecord(rec *pb.DNSRecord, origin string) (dns.RR, error) {
	if rec == nil {
		return nil, fmt.Errorf("record is nil")
	}

	// Construct the record string
	name := rec.Name
	if name == "@" || name == "" {
		name = origin
	} else if !dns.IsFqdn(name) {
		name = name + "." + origin
	}

	recordStr := fmt.Sprintf("%s %d IN %s %s", name, rec.Ttl, rec.Type, rec.Rdata)

	rr, err := dns.NewRR(recordStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse record string '%s': %w", recordStr, err)
	}

	return rr, nil
}

// Ensure ZoneHandler implements worker.ZoneHandler
var _ worker.ZoneHandler = (*ZoneHandler)(nil)
