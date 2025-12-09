// Package registry provides worker registration and discovery implementations.
package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/piwi3910/dns-go/pkg/control"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// MemoryRegistry is an in-memory implementation of WorkerRegistry.
type MemoryRegistry struct {
	mu      sync.RWMutex
	workers map[string]*control.WorkerInfo
}

// NewMemoryRegistry creates a new in-memory worker registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{
		workers: make(map[string]*control.WorkerInfo),
	}
}

// Register adds a new worker to the registry.
func (r *MemoryRegistry) Register(ctx context.Context, info *control.WorkerInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info.ID == "" {
		return fmt.Errorf("worker ID is required")
	}

	// Check if worker already exists
	if _, exists := r.workers[info.ID]; exists {
		return fmt.Errorf("worker %s already registered", info.ID)
	}

	// Set registration time
	info.RegisteredAt = time.Now()
	info.LastHeartbeat = time.Now()

	// Initialize health if not set
	if info.Health == nil {
		info.Health = &pb.HealthStatus{
			Status:    pb.HealthStatus_HEALTHY,
			Message:   "Just registered",
			LastCheck: nil,
		}
	}

	r.workers[info.ID] = info
	return nil
}

// Deregister removes a worker from the registry.
func (r *MemoryRegistry) Deregister(ctx context.Context, workerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.workers[workerID]; !exists {
		return fmt.Errorf("worker %s not found", workerID)
	}

	delete(r.workers, workerID)
	return nil
}

// Get retrieves information about a specific worker.
func (r *MemoryRegistry) Get(ctx context.Context, workerID string) (*control.WorkerInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.workers[workerID]
	if !exists {
		return nil, fmt.Errorf("worker %s not found", workerID)
	}

	// Return a copy to prevent external modification
	return copyWorkerInfo(info), nil
}

// List returns all registered workers, optionally filtered by labels.
func (r *MemoryRegistry) List(ctx context.Context, labelSelector map[string]string) ([]*control.WorkerInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*control.WorkerInfo
	for _, info := range r.workers {
		if matchesLabels(info.Labels, labelSelector) {
			result = append(result, copyWorkerInfo(info))
		}
	}

	return result, nil
}

// UpdateHeartbeat updates the last heartbeat time and stats for a worker.
func (r *MemoryRegistry) UpdateHeartbeat(ctx context.Context, workerID string, stats *pb.WorkerStats, health *pb.HealthStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, exists := r.workers[workerID]
	if !exists {
		return fmt.Errorf("worker %s not found", workerID)
	}

	info.LastHeartbeat = time.Now()
	if stats != nil {
		info.Stats = stats
	}
	if health != nil {
		info.Health = health
	}

	return nil
}

// GetStaleWorkers returns workers that haven't sent a heartbeat within the timeout.
func (r *MemoryRegistry) GetStaleWorkers(ctx context.Context, timeout time.Duration) ([]*control.WorkerInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cutoff := time.Now().Add(-timeout)
	var stale []*control.WorkerInfo

	for _, info := range r.workers {
		if info.LastHeartbeat.Before(cutoff) {
			stale = append(stale, copyWorkerInfo(info))
		}
	}

	return stale, nil
}

// matchesLabels checks if worker labels match the selector.
func matchesLabels(labels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}

	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}

	return true
}

// copyWorkerInfo creates a deep copy of WorkerInfo.
func copyWorkerInfo(info *control.WorkerInfo) *control.WorkerInfo {
	copy := &control.WorkerInfo{
		ID:            info.ID,
		Hostname:      info.Hostname,
		ListenAddress: info.ListenAddress,
		Version:       info.Version,
		RegisteredAt:  info.RegisteredAt,
		LastHeartbeat: info.LastHeartbeat,
		Health:        info.Health,
		Stats:         info.Stats,
	}

	// Copy slices
	if len(info.Capabilities) > 0 {
		copy.Capabilities = make([]string, len(info.Capabilities))
		for i, c := range info.Capabilities {
			copy.Capabilities[i] = c
		}
	}

	if len(info.Labels) > 0 {
		copy.Labels = make(map[string]string, len(info.Labels))
		for k, v := range info.Labels {
			copy.Labels[k] = v
		}
	}

	if len(info.AssignedZones) > 0 {
		copy.AssignedZones = make([]string, len(info.AssignedZones))
		for i, z := range info.AssignedZones {
			copy.AssignedZones[i] = z
		}
	}

	return copy
}

// Ensure MemoryRegistry implements WorkerRegistry
var _ control.WorkerRegistry = (*MemoryRegistry)(nil)
