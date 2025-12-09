// Package worker provides the DNS worker implementation that connects to a control plane.
package worker

import (
	"context"
	"time"

	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
)

// ControlPlaneClient is the interface for communicating with the control plane.
type ControlPlaneClient interface {
	// Connect establishes connection to the control plane.
	Connect(ctx context.Context) error

	// Disconnect closes the connection to the control plane.
	Disconnect() error

	// IsConnected returns true if connected to the control plane.
	IsConnected() bool

	// Register registers this worker with the control plane.
	Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error)

	// Deregister deregisters this worker from the control plane.
	Deregister(ctx context.Context, reason string) error

	// SendHeartbeat sends a heartbeat to the control plane.
	SendHeartbeat(ctx context.Context, stats *pb.WorkerStats, health *pb.HealthStatus) (*pb.HeartbeatResponse, error)

	// GetConfig retrieves configuration from the control plane.
	GetConfig(ctx context.Context) (*pb.WorkerConfig, error)

	// StreamConfigUpdates starts streaming configuration updates.
	StreamConfigUpdates(ctx context.Context) (<-chan *pb.ConfigUpdate, error)

	// GetZone retrieves zone data from the control plane.
	GetZone(ctx context.Context, origin string, currentSerial uint32) (*pb.ZoneData, error)

	// StreamZoneUpdates starts streaming zone updates.
	StreamZoneUpdates(ctx context.Context, zones []string) (<-chan *pb.ZoneUpdate, error)

	// ReportStats sends a stats report to the control plane.
	ReportStats(ctx context.Context, report *pb.StatsReport) error
}

// Engine wraps the DNS server components and manages their lifecycle.
type Engine interface {
	// Start starts the DNS engine.
	Start() error

	// Stop stops the DNS engine.
	Stop() error

	// ApplyConfig applies new configuration to the engine.
	ApplyConfig(config *pb.WorkerConfig) error

	// GetStats returns current engine statistics.
	GetStats() *pb.WorkerStats

	// GetHealth returns current health status.
	GetHealth() *pb.HealthStatus
}

// ZoneHandler handles zone data management for the worker.
type ZoneHandler interface {
	// ApplyZone applies zone data to the local zone manager.
	ApplyZone(zone *pb.ZoneData) error

	// ApplyZoneUpdate applies an incremental zone update.
	ApplyZoneUpdate(update *pb.ZoneUpdate) error

	// DeleteZone removes a zone from the local zone manager.
	DeleteZone(origin string) error

	// GetZoneSerial returns the current serial for a zone.
	GetZoneSerial(origin string) (uint32, error)
}

// WorkerConfig contains configuration for the worker.
type WorkerConfig struct {
	// WorkerID is a unique identifier for this worker.
	WorkerID string

	// Hostname is the hostname of this worker.
	Hostname string

	// ListenAddress is the DNS listen address.
	ListenAddress string

	// Version is the worker version.
	Version string

	// Capabilities lists supported features (e.g., "tcp", "udp", "dnssec").
	Capabilities []string

	// Labels are custom labels for routing/filtering.
	Labels map[string]string

	// ControlPlaneAddress is the address of the control plane.
	ControlPlaneAddress string

	// HeartbeatInterval is the interval between heartbeats.
	HeartbeatInterval time.Duration

	// ReconnectDelay is the delay before attempting to reconnect.
	ReconnectDelay time.Duration

	// MaxReconnectAttempts is the maximum number of reconnect attempts (0 = unlimited).
	MaxReconnectAttempts int
}

// DefaultWorkerConfig returns default worker configuration.
func DefaultWorkerConfig() *WorkerConfig {
	return &WorkerConfig{
		ListenAddress:        "0.0.0.0:53",
		Version:              "0.1.0-dev",
		Capabilities:         []string{"udp", "tcp"},
		HeartbeatInterval:    10 * time.Second,
		ReconnectDelay:       5 * time.Second,
		MaxReconnectAttempts: 0, // Unlimited
	}
}
