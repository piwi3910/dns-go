// Package main provides the main DNS server binary implementation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // pprof intentionally exposed for debugging/profiling
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	dnsio "github.com/piwi3910/dns-go/pkg/io"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/server"
)

const version = "0.1.0-dev"

// Package-level errors.
var (
	ErrInvalidMode = errors.New("invalid resolution mode")
)

// Configuration constants for the DNS server.
const (
	pprofReadTimeoutSec       = 15  // HTTP read timeout for pprof server
	pprofReadHeaderTimeoutSec = 10  // HTTP read header timeout for pprof server
	pprofWriteTimeoutSec      = 15  // HTTP write timeout for pprof server
	pprofIdleTimeoutSec       = 60  // HTTP idle timeout for pprof server
	gracefulShutdownTimeoutSec = 10  // Graceful shutdown timeout
	statsReportIntervalSec    = 30  // Stats reporting interval
	percentageMultiplier      = 100 // Convert fraction to percentage
)

type config struct {
	listenAddr string
	workers    int
	pprofAddr  string
	modeFlag   string
	enableTCP  bool
}

func parseFlags() *config {
	cfg := &config{
		listenAddr: "",
		workers:    0,
		pprofAddr:  "",
		modeFlag:   "",
		enableTCP:  false,
	}
	flag.StringVar(&cfg.listenAddr, "listen", ":8083", "Address to listen on (default :8083)")
	flag.IntVar(&cfg.workers, "workers", runtime.NumCPU(), "Number of I/O workers (default: NumCPU)")
	flag.StringVar(&cfg.pprofAddr, "pprof", ":6060", "Address for pprof HTTP server (empty to disable)")
	flag.StringVar(&cfg.modeFlag, "mode", "forwarding",
		"Resolution mode: 'forwarding' or 'recursive' (default: forwarding)")
	flag.BoolVar(&cfg.enableTCP, "tcp", true, "Enable TCP listener (default: true)")
	flag.Parse()

	return cfg
}

func main() {
	cfg := parseFlags()

	log.Printf("Starting DNS Server v%s", version)
	log.Printf("Go version: %s", runtime.Version())
	log.Printf("NumCPU: %d, Workers: %d", runtime.NumCPU(), cfg.workers)

	// Parse resolution mode
	resolverMode, err := parseResolutionMode(cfg.modeFlag)
	if err != nil {
		log.Fatal(err)
	}

	// Create DNS handler with configured mode
	handler := createHandler(resolverMode)

	// Start listeners
	udpListener, tcpListener := startListeners(cfg, handler)

	log.Printf("Fast-path optimization: enabled")
	log.Printf("Cache: enabled (Message + RRset + Infrastructure)")

	// Start pprof HTTP server if enabled
	startPprofServer(cfg.pprofAddr)

	// Start stats reporter
	go reportStats(handler)

	// Wait for shutdown signal and perform graceful shutdown
	waitAndShutdown(handler, udpListener, tcpListener)
}

// parseResolutionMode converts a mode string to RecursionMode.
func parseResolutionMode(modeFlag string) (resolver.RecursionMode, error) {
	switch modeFlag {
	case "forwarding":
		log.Printf("Resolution mode: Forwarding (fast)")

		return resolver.ForwardingMode, nil
	case "recursive":
		log.Printf("Resolution mode: Recursive (true resolution from root servers)")

		return resolver.RecursiveMode, nil
	default:
		return 0, fmt.Errorf("%w: %s (must be 'forwarding' or 'recursive')", ErrInvalidMode, modeFlag)
	}
}

// createHandler creates a DNS handler with the specified resolver mode.
func createHandler(resolverMode resolver.RecursionMode) *server.Handler {
	handlerConfig := server.DefaultHandlerConfig()
	handlerConfig.ResolverMode = resolverMode

	return server.NewHandler(handlerConfig)
}

// startListeners starts UDP and TCP listeners.
func startListeners(cfg *config, handler *server.Handler) (*dnsio.UDPListener, *dnsio.TCPListener) {
	// Start UDP listener
	udpListener := startUDPListener(cfg, handler)
	log.Printf("DNS server listening on UDP %s with %d workers", udpListener.Addr(), cfg.workers)

	// Start TCP listener if enabled
	var tcpListener *dnsio.TCPListener
	if cfg.enableTCP {
		tcpListener = startTCPListener(cfg, handler)
		log.Printf("DNS server listening on TCP %s (RFC 7766 compliant)", tcpListener.Addr())
	}

	return udpListener, tcpListener
}

// startUDPListener creates and starts a UDP listener.
func startUDPListener(cfg *config, handler *server.Handler) *dnsio.UDPListener {
	udpConfig := dnsio.DefaultListenerConfig(cfg.listenAddr)
	udpConfig.NumWorkers = cfg.workers
	udpConfig.ReusePort = true

	udpListener, err := dnsio.NewUDPListener(udpConfig, handler)
	if err != nil {
		log.Fatalf("Failed to create UDP listener: %v", err)
	}

	if err := udpListener.Start(); err != nil {
		log.Fatalf("Failed to start UDP listener: %v", err)
	}

	return udpListener
}

// startTCPListener creates and starts a TCP listener.
func startTCPListener(cfg *config, handler *server.Handler) *dnsio.TCPListener {
	tcpConfig := dnsio.DefaultListenerConfig(cfg.listenAddr)
	tcpConfig.ReusePort = true

	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		log.Fatalf("Failed to create TCP listener: %v", err)
	}

	if err := tcpListener.Start(); err != nil {
		log.Fatalf("Failed to start TCP listener: %v", err)
	}

	return tcpListener
}

// startPprofServer starts the pprof HTTP server if address is provided.
func startPprofServer(addr string) {
	if addr == "" {
		return
	}

	go func() {
		log.Printf("Starting pprof HTTP server on %s", addr)
		// Configure HTTP server with timeouts for security (gosec G114)
		pprofServer := &http.Server{
			Addr:                         addr,
			Handler:                      nil, // Use DefaultServeMux for pprof
			TLSConfig:                    nil,
			ReadTimeout:                  pprofReadTimeoutSec * time.Second,
			ReadHeaderTimeout:            pprofReadHeaderTimeoutSec * time.Second,
			WriteTimeout:                 pprofWriteTimeoutSec * time.Second,
			IdleTimeout:                  pprofIdleTimeoutSec * time.Second,
			MaxHeaderBytes:               0,
			TLSNextProto:                 nil,
			ConnState:                    nil,
			ErrorLog:                     nil,
			BaseContext:                  nil,
			ConnContext:                  nil,
			DisableGeneralOptionsHandler: false,
			HTTP2:                        nil,
			Protocols:                    nil,
		}
		if err := pprofServer.ListenAndServe(); err != nil {
			log.Printf("pprof HTTP server error: %v", err)
		}
	}()
}

// waitAndShutdown waits for shutdown signal and performs graceful shutdown.
func waitAndShutdown(handler *server.Handler, udpListener *dnsio.UDPListener, tcpListener *dnsio.TCPListener) {
	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal: %v", sig)

	// Graceful shutdown
	log.Println("Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeoutSec*time.Second)
	defer cancel()

	// Stop listeners
	stopListeners(udpListener, tcpListener)

	// Print final stats
	printFinalStats(handler)

	<-shutdownCtx.Done()
	log.Println("Server stopped")
}

// stopListeners stops UDP and TCP listeners.
func stopListeners(udpListener *dnsio.UDPListener, tcpListener *dnsio.TCPListener) {
	if err := udpListener.Stop(); err != nil {
		log.Printf("Error stopping UDP listener: %v", err)
	}

	if tcpListener != nil {
		if err := tcpListener.Stop(); err != nil {
			log.Printf("Error stopping TCP listener: %v", err)
		}
	}
}

// printFinalStats prints final cache statistics before shutdown.
func printFinalStats(handler *server.Handler) {
	stats := handler.GetStats()
	log.Printf("Final stats:")
	log.Printf("  Message Cache: %d hits, %d misses (%.2f%% hit rate), %d bytes",
		stats.MessageCache.Hits,
		stats.MessageCache.Misses,
		stats.MessageCache.HitRate*percentageMultiplier,
		stats.MessageCache.Size)
	log.Printf("  RRset Cache: %d hits, %d misses (%.2f%% hit rate), %d bytes",
		stats.RRsetCache.Hits,
		stats.RRsetCache.Misses,
		stats.RRsetCache.HitRate*percentageMultiplier,
		stats.RRsetCache.Size)
}

// reportStats periodically reports cache statistics.
func reportStats(handler *server.Handler) {
	ticker := time.NewTicker(statsReportIntervalSec * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := handler.GetStats()

		log.Printf("Stats: MsgCache[hits=%d miss=%d rate=%.1f%% size=%s] RRsetCache[hits=%d miss=%d rate=%.1f%% size=%s]",
			stats.MessageCache.Hits,
			stats.MessageCache.Misses,
			stats.MessageCache.HitRate*percentageMultiplier,
			formatBytes(stats.MessageCache.Size),
			stats.RRsetCache.Hits,
			stats.RRsetCache.Misses,
			stats.RRsetCache.HitRate*percentageMultiplier,
			formatBytes(stats.RRsetCache.Size))
	}
}

// formatBytes formats bytes into human-readable string.
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
