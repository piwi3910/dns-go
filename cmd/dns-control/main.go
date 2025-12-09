// Package main provides the control plane binary for managing distributed DNS workers.
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

	"github.com/piwi3910/dns-go/pkg/control"
	"github.com/piwi3910/dns-go/pkg/control/registry"
	"github.com/piwi3910/dns-go/pkg/control/stats"
	"github.com/piwi3910/dns-go/pkg/control/sync"
)

const version = "0.1.0-dev"

// Configuration constants.
const (
	pprofReadTimeoutSec       = 15
	pprofReadHeaderTimeoutSec = 10
	pprofWriteTimeoutSec      = 15
	pprofIdleTimeoutSec       = 60
	defaultHeartbeatTimeout   = 30 * time.Second
	defaultStatsInterval      = 10 * time.Second
	defaultSnapshotInterval   = 60 * time.Second
	shutdownTimeout           = 30 * time.Second
)

type cliFlags struct {
	grpcAddr     string
	httpAddr     string
	pprofAddr    string
}

func parseFlags() *cliFlags {
	cfg := &cliFlags{}
	flag.StringVar(&cfg.grpcAddr, "grpc", ":9090", "gRPC listen address for worker communication")
	flag.StringVar(&cfg.httpAddr, "http", ":8080", "HTTP listen address for management API")
	flag.StringVar(&cfg.pprofAddr, "pprof", "", "Address for pprof HTTP server (disabled if empty)")
	flag.Parse()
	return cfg
}

func main() {
	cli := parseFlags()

	log.Printf("Starting DNS Control Plane v%s", version)
	log.Printf("Go version: %s", runtime.Version())
	log.Printf("NumCPU: %d", runtime.NumCPU())

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	workerRegistry := registry.NewMemoryRegistry()
	zoneSyncMgr := sync.NewZoneSyncManager()
	configSyncMgr := sync.NewConfigSyncManager()
	statsAggregator := stats.NewAggregator()

	// Create control plane server
	serverCfg := &control.ServerConfig{
		ListenAddress:    cli.grpcAddr,
		HeartbeatTimeout: defaultHeartbeatTimeout,
	}

	controlServer := control.NewServer(
		serverCfg,
		workerRegistry,
		zoneSyncMgr,
		configSyncMgr,
		statsAggregator,
	)

	// Start stats aggregator background tasks
	statsAggregator.StartPeriodicBroadcast(ctx, defaultStatsInterval)
	statsAggregator.StartPeriodicSnapshot(ctx, defaultSnapshotInterval)

	// Start pprof server if enabled
	if cli.pprofAddr != "" {
		go startPprofServer(cli.pprofAddr)
	}

	// Start gRPC server
	go func() {
		log.Printf("Starting gRPC server on %s", cli.grpcAddr)
		if err := controlServer.Start(cli.grpcAddr); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start HTTP management API (placeholder for future REST API)
	go func() {
		log.Printf("Starting HTTP management API on %s", cli.httpAddr)
		// TODO: Implement REST API for control plane management
		// This will expose endpoints for:
		// - Worker management (list, get, evict)
		// - Zone management (list, create, update, delete)
		// - Configuration management
		// - Stats aggregation
	}()

	log.Printf("Control plane started successfully")
	log.Printf("  gRPC (workers): %s", cli.grpcAddr)
	log.Printf("  HTTP (management): %s", cli.httpAddr)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal: %v", sig)

	// Graceful shutdown
	log.Println("Shutting down gracefully...")
	cancel() // Cancel context to stop background tasks

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Stop gRPC server
	controlServer.Stop()

	<-shutdownCtx.Done()
	log.Println("Control plane stopped")
}

// startPprofServer starts the pprof HTTP server.
func startPprofServer(addr string) {
	log.Printf("Starting pprof HTTP server on %s", addr)
	pprofServer := &http.Server{
		Addr:                         addr,
		Handler:                      nil, // Use DefaultServeMux for pprof
		ReadTimeout:                  pprofReadTimeoutSec * time.Second,
		ReadHeaderTimeout:            pprofReadHeaderTimeoutSec * time.Second,
		WriteTimeout:                 pprofWriteTimeoutSec * time.Second,
		IdleTimeout:                  pprofIdleTimeoutSec * time.Second,
	}
	if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("pprof HTTP server error: %v", err)
	}
}
