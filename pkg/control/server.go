// Package control provides the control plane implementation for distributed DNS workers.
package control

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements the gRPC control plane services.
type Server struct {
	pb.UnimplementedControlPlaneServer
	pb.UnimplementedWorkerManagementServer

	registry       WorkerRegistry
	zoneSyncMgr    ZoneSyncManager
	configSyncMgr  ConfigSyncManager
	statsAggregator StatsAggregator

	grpcServer *grpc.Server
	listener   net.Listener

	// Heartbeat timeout for marking workers stale
	heartbeatTimeout time.Duration

	// Shutdown handling
	shutdownMu sync.Mutex
	shutdown   bool
}

// ServerConfig contains configuration for the control plane server.
type ServerConfig struct {
	ListenAddress    string
	HeartbeatTimeout time.Duration
	GRPCOptions      []grpc.ServerOption
}

// DefaultServerConfig returns default server configuration.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddress:    ":9090",
		HeartbeatTimeout: 30 * time.Second,
	}
}

// NewServer creates a new control plane server.
func NewServer(
	cfg *ServerConfig,
	registry WorkerRegistry,
	zoneSyncMgr ZoneSyncManager,
	configSyncMgr ConfigSyncManager,
	statsAggregator StatsAggregator,
) *Server {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}

	s := &Server{
		registry:         registry,
		zoneSyncMgr:      zoneSyncMgr,
		configSyncMgr:    configSyncMgr,
		statsAggregator:  statsAggregator,
		heartbeatTimeout: cfg.HeartbeatTimeout,
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(cfg.GRPCOptions...)

	// Register services
	pb.RegisterControlPlaneServer(s.grpcServer, s)
	pb.RegisterWorkerManagementServer(s.grpcServer, s)

	return s
}

// Start starts the control plane gRPC server.
func (s *Server) Start(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	s.listener = listener

	log.Printf("Control plane gRPC server listening on %s", address)

	return s.grpcServer.Serve(listener)
}

// Stop gracefully stops the control plane server.
func (s *Server) Stop() {
	s.shutdownMu.Lock()
	s.shutdown = true
	s.shutdownMu.Unlock()

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
}

// ControlPlane service implementations

// Register handles worker registration.
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	workerInfo := &WorkerInfo{
		ID:            req.WorkerId,
		Hostname:      req.Hostname,
		ListenAddress: req.ListenAddress,
		Version:       req.Version,
		Capabilities:  req.Capabilities,
		Labels:        req.Labels,
	}

	if err := s.registry.Register(ctx, workerInfo); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "failed to register worker: %v", err)
	}

	// Get initial configuration for worker
	config, err := s.configSyncMgr.GetConfig(ctx, req.WorkerId)
	if err != nil {
		log.Printf("Warning: failed to get config for worker %s: %v", req.WorkerId, err)
	}

	// Get zone assignments
	assignments, err := s.zoneSyncMgr.GetAssignments(ctx, req.WorkerId)
	if err != nil {
		log.Printf("Warning: failed to get zone assignments for worker %s: %v", req.WorkerId, err)
	}

	// Convert assignments to proto format
	var protoAssignments []*pb.ZoneAssignment
	for _, a := range assignments {
		protoAssignments = append(protoAssignments, &pb.ZoneAssignment{
			Origin:  a.Origin,
			Serial:  a.Serial,
			Primary: a.Primary,
		})
	}

	log.Printf("Worker %s registered successfully from %s", req.WorkerId, req.Hostname)

	return &pb.RegisterResponse{
		Success:    true,
		Message:    "Registration successful",
		AssignedId: req.WorkerId,
		Config:     config,
		Zones:      protoAssignments,
	}, nil
}

// Deregister handles worker deregistration.
func (s *Server) Deregister(ctx context.Context, req *pb.DeregisterRequest) (*emptypb.Empty, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	if err := s.registry.Deregister(ctx, req.WorkerId); err != nil {
		return nil, status.Errorf(codes.NotFound, "failed to deregister worker: %v", err)
	}

	// Clean up subscriptions
	s.zoneSyncMgr.Unsubscribe(req.WorkerId)
	s.configSyncMgr.Unsubscribe(req.WorkerId)
	s.statsAggregator.RemoveWorker(req.WorkerId)

	log.Printf("Worker %s deregistered: %s", req.WorkerId, req.Reason)

	return &emptypb.Empty{}, nil
}

// Heartbeat handles worker heartbeats.
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	// Update heartbeat in registry
	if err := s.registry.UpdateHeartbeat(ctx, req.WorkerId, req.Stats, req.Health); err != nil {
		return nil, status.Errorf(codes.NotFound, "worker not found: %v", err)
	}

	// Record stats
	if req.Stats != nil || req.Health != nil {
		if err := s.statsAggregator.RecordStats(ctx, req.WorkerId, req.Stats, req.Health); err != nil {
			log.Printf("Warning: failed to record stats for worker %s: %v", req.WorkerId, err)
		}
	}

	// Build response with any pending commands
	// For now, we don't have a command queue implementation
	return &pb.HeartbeatResponse{
		Acknowledged: true,
		Commands:     nil,
	}, nil
}

// GetConfig returns the current configuration for a worker.
func (s *Server) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.WorkerConfig, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	config, err := s.configSyncMgr.GetConfig(ctx, req.WorkerId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get config: %v", err)
	}

	return config, nil
}

// StreamConfigUpdates streams configuration updates to a worker.
func (s *Server) StreamConfigUpdates(req *pb.ConfigStreamRequest, stream pb.ControlPlane_StreamConfigUpdatesServer) error {
	if req.WorkerId == "" {
		return status.Error(codes.InvalidArgument, "worker_id is required")
	}

	updateCh, err := s.configSyncMgr.Subscribe(req.WorkerId)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to subscribe: %v", err)
	}
	defer s.configSyncMgr.Unsubscribe(req.WorkerId)

	log.Printf("Worker %s subscribed to config updates", req.WorkerId)

	for {
		select {
		case <-stream.Context().Done():
			log.Printf("Worker %s config stream closed", req.WorkerId)
			return nil
		case update, ok := <-updateCh:
			if !ok {
				return nil
			}
			// Set timestamp
			update.Timestamp = timestamppb.Now()
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

// GetZone returns zone data for a specific zone.
func (s *Server) GetZone(ctx context.Context, req *pb.GetZoneRequest) (*pb.ZoneData, error) {
	if req.Origin == "" {
		return nil, status.Error(codes.InvalidArgument, "origin is required")
	}

	zone, err := s.zoneSyncMgr.GetZone(ctx, req.Origin)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}

	return zone, nil
}

// StreamZoneUpdates streams zone updates to a worker.
func (s *Server) StreamZoneUpdates(req *pb.ZoneStreamRequest, stream pb.ControlPlane_StreamZoneUpdatesServer) error {
	if req.WorkerId == "" {
		return status.Error(codes.InvalidArgument, "worker_id is required")
	}

	updateCh, err := s.zoneSyncMgr.Subscribe(req.WorkerId)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to subscribe: %v", err)
	}
	defer s.zoneSyncMgr.Unsubscribe(req.WorkerId)

	log.Printf("Worker %s subscribed to zone updates", req.WorkerId)

	for {
		select {
		case <-stream.Context().Done():
			log.Printf("Worker %s zone stream closed", req.WorkerId)
			return nil
		case update, ok := <-updateCh:
			if !ok {
				return nil
			}
			// Filter by requested zones if specified
			if len(req.ZoneOrigins) > 0 {
				found := false
				for _, origin := range req.ZoneOrigins {
					if origin == update.Origin {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			// Set timestamp
			update.Timestamp = timestamppb.Now()
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

// ReportStats handles stats reports from workers.
func (s *Server) ReportStats(ctx context.Context, req *pb.StatsReport) (*emptypb.Empty, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	// Record worker stats
	if err := s.statsAggregator.RecordStats(ctx, req.WorkerId, req.Stats, nil); err != nil {
		log.Printf("Warning: failed to record stats for worker %s: %v", req.WorkerId, err)
	}

	// Record zone stats
	if len(req.ZoneStats) > 0 {
		if err := s.statsAggregator.RecordZoneStats(ctx, req.WorkerId, req.ZoneStats); err != nil {
			log.Printf("Warning: failed to record zone stats for worker %s: %v", req.WorkerId, err)
		}
	}

	// Record upstream stats
	if len(req.UpstreamStats) > 0 {
		if err := s.statsAggregator.RecordUpstreamStats(ctx, req.WorkerId, req.UpstreamStats); err != nil {
			log.Printf("Warning: failed to record upstream stats for worker %s: %v", req.WorkerId, err)
		}
	}

	return &emptypb.Empty{}, nil
}

// WorkerManagement service implementations

// ListWorkers returns all registered workers.
func (s *Server) ListWorkers(ctx context.Context, req *pb.ListWorkersRequest) (*pb.ListWorkersResponse, error) {
	workers, err := s.registry.List(ctx, req.LabelSelector)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list workers: %v", err)
	}

	var protoWorkers []*pb.WorkerInfo
	for _, w := range workers {
		pw := &pb.WorkerInfo{
			WorkerId:      w.ID,
			Hostname:      w.Hostname,
			ListenAddress: w.ListenAddress,
			Version:       w.Version,
			Capabilities:  w.Capabilities,
			Labels:        w.Labels,
			Health:        w.Health,
			RegisteredAt:  timestamppb.New(w.RegisteredAt),
			LastHeartbeat: timestamppb.New(w.LastHeartbeat),
			AssignedZones: w.AssignedZones,
		}

		// Include stats if requested
		if req.IncludeStats {
			pw.Stats = w.Stats
		}

		protoWorkers = append(protoWorkers, pw)
	}

	return &pb.ListWorkersResponse{
		Workers: protoWorkers,
	}, nil
}

// GetWorker returns details about a specific worker.
func (s *Server) GetWorker(ctx context.Context, req *pb.GetWorkerRequest) (*pb.WorkerInfo, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	worker, err := s.registry.Get(ctx, req.WorkerId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "worker not found: %v", err)
	}

	return &pb.WorkerInfo{
		WorkerId:      worker.ID,
		Hostname:      worker.Hostname,
		ListenAddress: worker.ListenAddress,
		Version:       worker.Version,
		Capabilities:  worker.Capabilities,
		Labels:        worker.Labels,
		Health:        worker.Health,
		Stats:         worker.Stats,
		RegisteredAt:  timestamppb.New(worker.RegisteredAt),
		LastHeartbeat: timestamppb.New(worker.LastHeartbeat),
		AssignedZones: worker.AssignedZones,
	}, nil
}

// ReloadWorker forces a worker to reload its configuration and/or zones.
func (s *Server) ReloadWorker(ctx context.Context, req *pb.ReloadWorkerRequest) (*emptypb.Empty, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	// Verify worker exists
	if _, err := s.registry.Get(ctx, req.WorkerId); err != nil {
		return nil, status.Errorf(codes.NotFound, "worker not found: %v", err)
	}

	if req.ReloadConfig {
		if err := s.configSyncMgr.ReloadConfig(ctx, req.WorkerId); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to reload config: %v", err)
		}
	}

	// Zone reload would be handled through zone sync manager
	// For now, we just log the request
	if req.ReloadZones {
		log.Printf("Zone reload requested for worker %s", req.WorkerId)
	}

	return &emptypb.Empty{}, nil
}

// EvictWorker removes a worker from the control plane.
func (s *Server) EvictWorker(ctx context.Context, req *pb.EvictWorkerRequest) (*emptypb.Empty, error) {
	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	// Deregister the worker
	if err := s.registry.Deregister(ctx, req.WorkerId); err != nil {
		return nil, status.Errorf(codes.NotFound, "failed to evict worker: %v", err)
	}

	// Clean up subscriptions and stats
	s.zoneSyncMgr.Unsubscribe(req.WorkerId)
	s.configSyncMgr.Unsubscribe(req.WorkerId)
	s.statsAggregator.RemoveWorker(req.WorkerId)

	log.Printf("Worker %s evicted: %s (graceful=%v)", req.WorkerId, req.Reason, req.Graceful)

	return &emptypb.Empty{}, nil
}
