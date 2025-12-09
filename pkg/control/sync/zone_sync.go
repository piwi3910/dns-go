// Package sync provides zone and configuration synchronization for the control plane.
package sync

import (
	"context"
	"fmt"
	"sync"

	"github.com/piwi3910/dns-go/pkg/control"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// ZoneSyncManager manages zone distribution and synchronization to workers.
type ZoneSyncManager struct {
	mu sync.RWMutex

	// assignments maps workerID -> origin -> assignment
	assignments map[string]map[string]*control.ZoneAssignment

	// zones stores the current zone data
	zones map[string]*pb.ZoneData

	// subscribers maps workerID -> update channel
	subscribers map[string]chan *pb.ZoneUpdate

	// subscriberMu protects subscribers map
	subscriberMu sync.RWMutex
}

// NewZoneSyncManager creates a new zone synchronization manager.
func NewZoneSyncManager() *ZoneSyncManager {
	return &ZoneSyncManager{
		assignments: make(map[string]map[string]*control.ZoneAssignment),
		zones:       make(map[string]*pb.ZoneData),
		subscribers: make(map[string]chan *pb.ZoneUpdate),
	}
}

// AssignZone assigns a zone to a worker.
func (m *ZoneSyncManager) AssignZone(ctx context.Context, workerID, origin string, primary bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if origin == "" {
		return fmt.Errorf("zone origin is required")
	}

	// Get or create worker's assignments
	workerAssignments, exists := m.assignments[workerID]
	if !exists {
		workerAssignments = make(map[string]*control.ZoneAssignment)
		m.assignments[workerID] = workerAssignments
	}

	// Check if already assigned
	if _, exists := workerAssignments[origin]; exists {
		return fmt.Errorf("zone %s already assigned to worker %s", origin, workerID)
	}

	// Get current serial from zone data
	var serial uint32
	if zone, exists := m.zones[origin]; exists {
		serial = zone.Serial
	}

	// Create assignment
	workerAssignments[origin] = &control.ZoneAssignment{
		Origin:  origin,
		Serial:  serial,
		Primary: primary,
	}

	return nil
}

// UnassignZone removes a zone assignment from a worker.
func (m *ZoneSyncManager) UnassignZone(ctx context.Context, workerID, origin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workerAssignments, exists := m.assignments[workerID]
	if !exists {
		return fmt.Errorf("worker %s has no zone assignments", workerID)
	}

	if _, exists := workerAssignments[origin]; !exists {
		return fmt.Errorf("zone %s not assigned to worker %s", origin, workerID)
	}

	delete(workerAssignments, origin)

	// Clean up empty map
	if len(workerAssignments) == 0 {
		delete(m.assignments, workerID)
	}

	return nil
}

// GetAssignments returns all zone assignments for a worker.
func (m *ZoneSyncManager) GetAssignments(ctx context.Context, workerID string) ([]*control.ZoneAssignment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	workerAssignments, exists := m.assignments[workerID]
	if !exists {
		return []*control.ZoneAssignment{}, nil
	}

	result := make([]*control.ZoneAssignment, 0, len(workerAssignments))
	for _, assignment := range workerAssignments {
		// Return a copy
		result = append(result, &control.ZoneAssignment{
			Origin:  assignment.Origin,
			Serial:  assignment.Serial,
			Primary: assignment.Primary,
		})
	}

	return result, nil
}

// GetZone returns zone data for a specific zone.
func (m *ZoneSyncManager) GetZone(ctx context.Context, origin string) (*pb.ZoneData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	zone, exists := m.zones[origin]
	if !exists {
		return nil, fmt.Errorf("zone %s not found", origin)
	}

	return zone, nil
}

// SetZone stores or updates zone data.
func (m *ZoneSyncManager) SetZone(ctx context.Context, zone *pb.ZoneData) error {
	if zone.Origin == "" {
		return fmt.Errorf("zone origin is required")
	}

	m.mu.Lock()
	m.zones[zone.Origin] = zone
	m.mu.Unlock()

	// Notify subscribers of the update
	update := &pb.ZoneUpdate{
		Type:   pb.ZoneUpdate_FULL,
		Origin: zone.Origin,
		Serial: zone.Serial,
		Data:   zone,
	}

	return m.NotifyZoneUpdate(ctx, update)
}

// DeleteZone removes zone data and notifies subscribers.
func (m *ZoneSyncManager) DeleteZone(ctx context.Context, origin string) error {
	m.mu.Lock()
	_, exists := m.zones[origin]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("zone %s not found", origin)
	}
	delete(m.zones, origin)
	m.mu.Unlock()

	// Notify subscribers of deletion
	update := &pb.ZoneUpdate{
		Type:   pb.ZoneUpdate_DELETE,
		Origin: origin,
	}

	return m.NotifyZoneUpdate(ctx, update)
}

// NotifyZoneUpdate sends a zone update to all subscribed workers.
func (m *ZoneSyncManager) NotifyZoneUpdate(ctx context.Context, update *pb.ZoneUpdate) error {
	m.subscriberMu.RLock()
	defer m.subscriberMu.RUnlock()

	// Update assignments with new serial
	if update.Type == pb.ZoneUpdate_FULL || update.Type == pb.ZoneUpdate_INCREMENTAL {
		m.mu.Lock()
		for _, workerAssignments := range m.assignments {
			if assignment, exists := workerAssignments[update.Origin]; exists {
				assignment.Serial = update.Serial
			}
		}
		m.mu.Unlock()
	}

	// Send to all subscribers (non-blocking)
	for workerID, ch := range m.subscribers {
		select {
		case ch <- update:
			// Successfully sent
		default:
			// Channel full, log warning (subscriber is slow)
			_ = workerID // Acknowledge we know about slow subscriber
		}
	}

	return nil
}

// Subscribe creates a subscription for zone updates for a worker.
func (m *ZoneSyncManager) Subscribe(workerID string) (<-chan *pb.ZoneUpdate, error) {
	m.subscriberMu.Lock()
	defer m.subscriberMu.Unlock()

	if _, exists := m.subscribers[workerID]; exists {
		return nil, fmt.Errorf("worker %s already subscribed to zone updates", workerID)
	}

	// Buffered channel to prevent blocking on slow consumers
	ch := make(chan *pb.ZoneUpdate, 100)
	m.subscribers[workerID] = ch

	return ch, nil
}

// Unsubscribe removes a worker's subscription and closes the channel.
func (m *ZoneSyncManager) Unsubscribe(workerID string) {
	m.subscriberMu.Lock()
	defer m.subscriberMu.Unlock()

	if ch, exists := m.subscribers[workerID]; exists {
		close(ch)
		delete(m.subscribers, workerID)
	}
}

// GetWorkersForZone returns all workers assigned to a zone.
func (m *ZoneSyncManager) GetWorkersForZone(origin string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var workers []string
	for workerID, assignments := range m.assignments {
		if _, exists := assignments[origin]; exists {
			workers = append(workers, workerID)
		}
	}

	return workers
}

// RemoveWorker removes all assignments and subscriptions for a worker.
func (m *ZoneSyncManager) RemoveWorker(workerID string) {
	m.mu.Lock()
	delete(m.assignments, workerID)
	m.mu.Unlock()

	m.Unsubscribe(workerID)
}

// Ensure ZoneSyncManager implements control.ZoneSyncManager
var _ control.ZoneSyncManager = (*ZoneSyncManager)(nil)
