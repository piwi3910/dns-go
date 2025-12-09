// Package client provides the gRPC client for connecting to the control plane.
package client

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/piwi3910/dns-go/pkg/worker"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient implements ControlPlaneClient using gRPC.
type GRPCClient struct {
	address  string
	workerID string

	conn       *grpc.ClientConn
	client     pb.ControlPlaneClient
	connected  atomic.Bool
	mu         sync.RWMutex

	// Reconnection settings
	reconnectDelay       time.Duration
	maxReconnectAttempts int
	reconnectAttempts    int
}

// NewGRPCClient creates a new gRPC client for the control plane.
func NewGRPCClient(address, workerID string) *GRPCClient {
	return &GRPCClient{
		address:              address,
		workerID:             workerID,
		reconnectDelay:       5 * time.Second,
		maxReconnectAttempts: 0, // Unlimited
	}
}

// SetReconnectDelay sets the delay between reconnect attempts.
func (c *GRPCClient) SetReconnectDelay(delay time.Duration) {
	c.reconnectDelay = delay
}

// SetMaxReconnectAttempts sets the maximum number of reconnect attempts.
func (c *GRPCClient) SetMaxReconnectAttempts(max int) {
	c.maxReconnectAttempts = max
}

// Connect establishes connection to the control plane.
func (c *GRPCClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return nil
	}

	// TODO: Add TLS support for production
	conn, err := grpc.DialContext(
		ctx,
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to control plane at %s: %w", c.address, err)
	}

	c.conn = conn
	c.client = pb.NewControlPlaneClient(conn)
	c.connected.Store(true)
	c.reconnectAttempts = 0

	log.Printf("Connected to control plane at %s", c.address)
	return nil
}

// Disconnect closes the connection to the control plane.
func (c *GRPCClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected.Load() {
		return nil
	}

	c.connected.Store(false)
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("error closing connection: %w", err)
		}
		c.conn = nil
		c.client = nil
	}

	log.Printf("Disconnected from control plane")
	return nil
}

// IsConnected returns true if connected to the control plane.
func (c *GRPCClient) IsConnected() bool {
	return c.connected.Load()
}

// Register registers this worker with the control plane.
func (c *GRPCClient) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	resp, err := client.Register(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	return resp, nil
}

// Deregister deregisters this worker from the control plane.
func (c *GRPCClient) Deregister(ctx context.Context, reason string) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("not connected to control plane")
	}

	req := &pb.DeregisterRequest{
		WorkerId: c.workerID,
		Reason:   reason,
	}

	_, err := client.Deregister(ctx, req)
	if err != nil {
		return fmt.Errorf("deregistration failed: %w", err)
	}

	return nil
}

// SendHeartbeat sends a heartbeat to the control plane.
func (c *GRPCClient) SendHeartbeat(ctx context.Context, stats *pb.WorkerStats, health *pb.HealthStatus) (*pb.HeartbeatResponse, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	req := &pb.HeartbeatRequest{
		WorkerId: c.workerID,
		Stats:    stats,
		Health:   health,
	}

	resp, err := client.Heartbeat(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat failed: %w", err)
	}

	return resp, nil
}

// GetConfig retrieves configuration from the control plane.
func (c *GRPCClient) GetConfig(ctx context.Context) (*pb.WorkerConfig, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	req := &pb.GetConfigRequest{
		WorkerId: c.workerID,
	}

	config, err := client.GetConfig(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	return config, nil
}

// StreamConfigUpdates starts streaming configuration updates.
func (c *GRPCClient) StreamConfigUpdates(ctx context.Context) (<-chan *pb.ConfigUpdate, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	req := &pb.ConfigStreamRequest{
		WorkerId: c.workerID,
	}

	stream, err := client.StreamConfigUpdates(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to start config stream: %w", err)
	}

	updateCh := make(chan *pb.ConfigUpdate, 10)

	go func() {
		defer close(updateCh)
		for {
			update, err := stream.Recv()
			if err == io.EOF {
				log.Printf("Config stream closed by server")
				return
			}
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, normal shutdown
					return
				}
				log.Printf("Error receiving config update: %v", err)
				return
			}

			select {
			case updateCh <- update:
			case <-ctx.Done():
				return
			}
		}
	}()

	return updateCh, nil
}

// GetZone retrieves zone data from the control plane.
func (c *GRPCClient) GetZone(ctx context.Context, origin string, currentSerial uint32) (*pb.ZoneData, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	req := &pb.GetZoneRequest{
		WorkerId:      c.workerID,
		Origin:        origin,
		CurrentSerial: currentSerial,
	}

	zone, err := client.GetZone(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone %s: %w", origin, err)
	}

	return zone, nil
}

// StreamZoneUpdates starts streaming zone updates.
func (c *GRPCClient) StreamZoneUpdates(ctx context.Context, zones []string) (<-chan *pb.ZoneUpdate, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("not connected to control plane")
	}

	req := &pb.ZoneStreamRequest{
		WorkerId:    c.workerID,
		ZoneOrigins: zones,
	}

	stream, err := client.StreamZoneUpdates(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to start zone stream: %w", err)
	}

	updateCh := make(chan *pb.ZoneUpdate, 100)

	go func() {
		defer close(updateCh)
		for {
			update, err := stream.Recv()
			if err == io.EOF {
				log.Printf("Zone stream closed by server")
				return
			}
			if err != nil {
				if ctx.Err() != nil {
					// Context cancelled, normal shutdown
					return
				}
				log.Printf("Error receiving zone update: %v", err)
				return
			}

			select {
			case updateCh <- update:
			case <-ctx.Done():
				return
			}
		}
	}()

	return updateCh, nil
}

// ReportStats sends a stats report to the control plane.
func (c *GRPCClient) ReportStats(ctx context.Context, report *pb.StatsReport) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("not connected to control plane")
	}

	_, err := client.ReportStats(ctx, report)
	if err != nil {
		return fmt.Errorf("failed to report stats: %w", err)
	}

	return nil
}

// ConnectWithRetry connects to the control plane with automatic retry.
func (c *GRPCClient) ConnectWithRetry(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := c.Connect(ctx)
		if err == nil {
			return nil
		}

		c.reconnectAttempts++
		if c.maxReconnectAttempts > 0 && c.reconnectAttempts >= c.maxReconnectAttempts {
			return fmt.Errorf("max reconnect attempts (%d) reached: %w", c.maxReconnectAttempts, err)
		}

		log.Printf("Failed to connect to control plane (attempt %d): %v. Retrying in %v...",
			c.reconnectAttempts, err, c.reconnectDelay)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.reconnectDelay):
			continue
		}
	}
}

// Ensure GRPCClient implements ControlPlaneClient
var _ worker.ControlPlaneClient = (*GRPCClient)(nil)
