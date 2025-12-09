// Package main provides the DNS worker binary that connects to a control plane.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // pprof intentionally exposed for debugging/profiling
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"github.com/piwi3910/dns-go/pkg/worker"
	"github.com/piwi3910/dns-go/pkg/worker/client"
	workerSync "github.com/piwi3910/dns-go/pkg/worker/sync"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const version = "0.1.0-dev"

// Configuration constants.
const (
	pprofReadTimeoutSec       = 15
	pprofReadHeaderTimeoutSec = 10
	pprofWriteTimeoutSec      = 15
	pprofIdleTimeoutSec       = 60
	defaultHeartbeatInterval  = 10 * time.Second
	shutdownTimeout           = 30 * time.Second
)

type cliFlags struct {
	workerID     string
	controlAddr  string
	listenAddr   string
	pprofAddr    string
	numWorkers   int
}

func parseFlags() *cliFlags {
	cfg := &cliFlags{}
	flag.StringVar(&cfg.workerID, "id", "", "Worker ID (auto-generated if empty)")
	flag.StringVar(&cfg.controlAddr, "control", "localhost:9090", "Control plane address")
	flag.StringVar(&cfg.listenAddr, "listen", "0.0.0.0:53", "DNS listen address")
	flag.StringVar(&cfg.pprofAddr, "pprof", "", "Address for pprof HTTP server (disabled if empty)")
	flag.IntVar(&cfg.numWorkers, "workers", 0, "Number of I/O workers (0 = NumCPU)")
	flag.Parse()

	// Generate worker ID if not provided
	if cfg.workerID == "" {
		hostname, _ := os.Hostname()
		cfg.workerID = hostname + "-" + uuid.New().String()[:8]
	}

	return cfg
}

func main() {
	cli := parseFlags()

	log.Printf("Starting DNS Worker v%s", version)
	log.Printf("Worker ID: %s", cli.workerID)
	log.Printf("Go version: %s", runtime.Version())
	log.Printf("NumCPU: %d", runtime.NumCPU())

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get hostname
	hostname, _ := os.Hostname()

	// Create DNS engine
	engine := worker.NewDNSEngine(cli.listenAddr, cli.numWorkers)

	// Start the DNS engine
	if err := engine.Start(); err != nil {
		log.Fatalf("Failed to start DNS engine: %v", err)
	}

	// Create zone handler
	zoneHandler := workerSync.NewZoneHandler(engine.GetZoneManager())

	// Create control plane client
	cpClient := client.NewGRPCClient(cli.controlAddr, cli.workerID)

	// Start pprof server if enabled
	if cli.pprofAddr != "" {
		go startPprofServer(cli.pprofAddr)
	}

	// Connect to control plane
	log.Printf("Connecting to control plane at %s...", cli.controlAddr)
	if err := cpClient.ConnectWithRetry(ctx); err != nil {
		log.Printf("Failed to connect to control plane: %v", err)
		log.Printf("Running in standalone mode")
	} else {
		// Register with control plane
		registerReq := &pb.RegisterRequest{
			WorkerId:      cli.workerID,
			Hostname:      hostname,
			ListenAddress: cli.listenAddr,
			Version:       version,
			Capabilities:  []string{"udp", "tcp"},
			Labels: map[string]string{
				"os":   runtime.GOOS,
				"arch": runtime.GOARCH,
			},
		}

		resp, err := cpClient.Register(ctx, registerReq)
		if err != nil {
			log.Printf("Failed to register with control plane: %v", err)
		} else if resp.Success {
			log.Printf("Registered with control plane: %s", resp.Message)

			// Apply initial config if provided
			if resp.Config != nil {
				if err := engine.ApplyConfig(resp.Config); err != nil {
					log.Printf("Failed to apply initial config: %v", err)
				}
			}

			// Apply initial zones
			for _, assignment := range resp.Zones {
				zone, err := cpClient.GetZone(ctx, assignment.Origin, 0)
				if err != nil {
					log.Printf("Failed to get zone %s: %v", assignment.Origin, err)
					continue
				}
				if err := zoneHandler.ApplyZone(zone); err != nil {
					log.Printf("Failed to apply zone %s: %v", assignment.Origin, err)
				}
			}

			// Start background tasks
			go runHeartbeatLoop(ctx, cpClient, cli.workerID, engine)
			go runConfigUpdateLoop(ctx, cpClient, engine)
			go runZoneUpdateLoop(ctx, cpClient, zoneHandler)
		}
	}

	log.Printf("DNS worker started")
	log.Printf("  DNS listen: %s", cli.listenAddr)
	log.Printf("  Control plane: %s", cli.controlAddr)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal: %v", sig)

	// Graceful shutdown
	log.Println("Shutting down gracefully...")
	cancel() // Cancel context to stop background tasks

	// Deregister from control plane
	if cpClient.IsConnected() {
		deregCtx, deregCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := cpClient.Deregister(deregCtx, "shutdown"); err != nil {
			log.Printf("Failed to deregister: %v", err)
		}
		deregCancel()
		cpClient.Disconnect()
	}

	// Stop DNS engine
	if err := engine.Stop(); err != nil {
		log.Printf("Error stopping DNS engine: %v", err)
	}

	log.Println("DNS worker stopped")
}

// runHeartbeatLoop sends periodic heartbeats to the control plane.
func runHeartbeatLoop(ctx context.Context, cpClient *client.GRPCClient, workerID string, engine *worker.DNSEngine) {
	ticker := time.NewTicker(defaultHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !cpClient.IsConnected() {
				continue
			}

			stats := engine.GetStats()
			health := engine.GetHealth()

			resp, err := cpClient.SendHeartbeat(ctx, stats, health)
			if err != nil {
				log.Printf("Heartbeat failed: %v", err)
				continue
			}

			// Process any commands from control plane
			for _, cmd := range resp.Commands {
				processCommand(ctx, cmd, engine)
			}
		}
	}
}

// runConfigUpdateLoop listens for configuration updates from the control plane.
func runConfigUpdateLoop(ctx context.Context, cpClient *client.GRPCClient, engine *worker.DNSEngine) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !cpClient.IsConnected() {
			time.Sleep(time.Second)
			continue
		}

		updateCh, err := cpClient.StreamConfigUpdates(ctx)
		if err != nil {
			log.Printf("Failed to start config stream: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for {
			select {
			case <-ctx.Done():
				return
			case update, ok := <-updateCh:
				if !ok {
					// Channel closed, reconnect
					log.Printf("Config stream closed, reconnecting...")
					break
				}

				log.Printf("Received config update: version=%s, fullReload=%v",
					update.Version, update.FullReloadRequired)

				if update.Config != nil {
					if err := engine.ApplyConfig(update.Config); err != nil {
						log.Printf("Failed to apply config update: %v", err)
					}
				}
			}
		}
	}
}

// runZoneUpdateLoop listens for zone updates from the control plane.
func runZoneUpdateLoop(ctx context.Context, cpClient *client.GRPCClient, zoneHandler *workerSync.ZoneHandler) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !cpClient.IsConnected() {
			time.Sleep(time.Second)
			continue
		}

		updateCh, err := cpClient.StreamZoneUpdates(ctx, nil) // Subscribe to all zones
		if err != nil {
			log.Printf("Failed to start zone stream: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for {
			select {
			case <-ctx.Done():
				return
			case update, ok := <-updateCh:
				if !ok {
					// Channel closed, reconnect
					log.Printf("Zone stream closed, reconnecting...")
					break
				}

				log.Printf("Received zone update: origin=%s, type=%v, serial=%d",
					update.Origin, update.Type, update.Serial)

				if err := zoneHandler.ApplyZoneUpdate(update); err != nil {
					log.Printf("Failed to apply zone update: %v", err)
				}
			}
		}
	}
}

// processCommand processes a command from the control plane.
func processCommand(ctx context.Context, cmd *pb.WorkerCommand, engine *worker.DNSEngine) {
	switch cmd.Type {
	case pb.WorkerCommand_NOOP:
		// No operation
	case pb.WorkerCommand_RELOAD_CONFIG:
		log.Printf("Received RELOAD_CONFIG command")
		// Config reload will be handled by config update stream
	case pb.WorkerCommand_RELOAD_ZONES:
		log.Printf("Received RELOAD_ZONES command")
		// Zone reload will be handled by zone update stream
	case pb.WorkerCommand_CLEAR_CACHE:
		log.Printf("Received CLEAR_CACHE command")
		handler := engine.GetHandler()
		if handler != nil {
			handler.ClearCaches()
		}
	case pb.WorkerCommand_SHUTDOWN:
		log.Printf("Received SHUTDOWN command")
		// Trigger graceful shutdown
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(syscall.SIGTERM)
	}
}

// startPprofServer starts the pprof HTTP server.
func startPprofServer(addr string) {
	log.Printf("Starting pprof HTTP server on %s", addr)
	pprofServer := &http.Server{
		Addr:              addr,
		Handler:           nil, // Use DefaultServeMux for pprof
		ReadTimeout:       pprofReadTimeoutSec * time.Second,
		ReadHeaderTimeout: pprofReadHeaderTimeoutSec * time.Second,
		WriteTimeout:      pprofWriteTimeoutSec * time.Second,
		IdleTimeout:       pprofIdleTimeoutSec * time.Second,
	}
	if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("pprof HTTP server error: %v", err)
	}
}

// createStatsReport creates a stats report for the control plane.
func createStatsReport(workerID string, engine *worker.DNSEngine) *pb.StatsReport {
	stats := engine.GetStats()

	return &pb.StatsReport{
		WorkerId:  workerID,
		Timestamp: timestamppb.Now(),
		Stats:     stats,
	}
}
