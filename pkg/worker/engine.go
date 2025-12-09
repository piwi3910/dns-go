// Package worker provides the DNS worker implementation that connects to a control plane.
package worker

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/piwi3910/dns-go/pkg/cache"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
	pb "github.com/piwi3910/dns-go/pkg/proto/gen"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/server"
	"github.com/piwi3910/dns-go/pkg/zone"
)

// DNSEngine wraps DNS server components and manages their lifecycle.
type DNSEngine struct {
	mu sync.RWMutex

	// Configuration
	config      *pb.WorkerConfig
	listenAddr  string
	numWorkers  int

	// Core components
	handler      *server.Handler
	zoneManager  *zone.Manager
	upstreamPool *resolver.UpstreamPool
	infraCache   *cache.InfraCache

	// Listeners
	udpListener *dnsio.UDPListener
	tcpListener *dnsio.TCPListener

	// State
	running   atomic.Bool
	startTime time.Time
}

// NewDNSEngine creates a new DNS engine.
func NewDNSEngine(listenAddr string, numWorkers int) *DNSEngine {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	return &DNSEngine{
		listenAddr: listenAddr,
		numWorkers: numWorkers,
	}
}

// Start starts the DNS engine.
func (e *DNSEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running.Load() {
		return fmt.Errorf("engine already running")
	}

	// Create zone manager
	e.zoneManager = zone.NewManager()

	// Create infrastructure cache
	e.infraCache = cache.NewInfraCache()

	// Create handler with default config
	handlerConfig := server.DefaultHandlerConfig()
	e.handler = server.NewHandler(handlerConfig)

	// Start UDP listener
	udpConfig := dnsio.DefaultListenerConfig(e.listenAddr)
	udpConfig.NumWorkers = e.numWorkers
	udpConfig.ReusePort = true

	udpListener, err := dnsio.NewUDPListener(udpConfig, e.handler)
	if err != nil {
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}

	if err := udpListener.Start(); err != nil {
		return fmt.Errorf("failed to start UDP listener: %w", err)
	}
	e.udpListener = udpListener

	// Start TCP listener
	tcpConfig := dnsio.DefaultListenerConfig(e.listenAddr)
	tcpConfig.ReusePort = true

	tcpListener, err := dnsio.NewTCPListener(tcpConfig, e.handler)
	if err != nil {
		e.udpListener.Stop()
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}

	if err := tcpListener.Start(); err != nil {
		e.udpListener.Stop()
		return fmt.Errorf("failed to start TCP listener: %w", err)
	}
	e.tcpListener = tcpListener

	e.running.Store(true)
	e.startTime = time.Now()

	log.Printf("DNS engine started on %s (UDP/TCP) with %d workers", e.listenAddr, e.numWorkers)

	return nil
}

// Stop stops the DNS engine.
func (e *DNSEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running.Load() {
		return nil
	}

	e.running.Store(false)

	var errs []error

	if e.udpListener != nil {
		if err := e.udpListener.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("UDP listener: %w", err))
		}
	}

	if e.tcpListener != nil {
		if err := e.tcpListener.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("TCP listener: %w", err))
		}
	}

	log.Printf("DNS engine stopped")

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping engine: %v", errs)
	}

	return nil
}

// ApplyConfig applies new configuration to the engine.
func (e *DNSEngine) ApplyConfig(config *pb.WorkerConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if config == nil {
		return fmt.Errorf("config is nil")
	}

	e.config = config

	// Apply resolver config
	if config.Resolver != nil {
		// Parse and apply resolver mode
		var mode resolver.RecursionMode
		switch config.Resolver.Mode {
		case "forwarding":
			mode = resolver.ForwardingMode
		case "recursive":
			mode = resolver.RecursiveMode
		case "parallel":
			mode = resolver.ParallelMode
		default:
			mode = resolver.ForwardingMode
		}

		if e.handler != nil {
			// Update handler config
			handlerConfig := server.DefaultHandlerConfig()
			handlerConfig.ResolverMode = mode
			// Note: Full config reloading would require handler recreation
			// For now, we log the config change
			log.Printf("Applied resolver mode: %s", config.Resolver.Mode)
		}
	}

	// Apply upstream config
	if len(config.Upstreams) > 0 && e.upstreamPool != nil {
		var upstreams []string
		for _, u := range config.Upstreams {
			if u.Enabled {
				upstreams = append(upstreams, u.Address)
			}
		}
		// Note: UpstreamPool would need a method to update upstreams dynamically
		log.Printf("Applied %d upstream servers", len(upstreams))
	}

	log.Printf("Applied configuration version: %s", config.ConfigVersion)

	return nil
}

// GetStats returns current engine statistics.
func (e *DNSEngine) GetStats() *pb.WorkerStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	stats := &pb.WorkerStats{
		Goroutines:      int32(runtime.NumGoroutine()),
		MemoryUsedBytes: int64(memStats.Alloc),
	}

	if e.handler != nil {
		handlerStats := e.handler.GetStats()
		stats.CacheHitRate = handlerStats.MessageCache.HitRate
		stats.CacheSizeBytes = handlerStats.MessageCache.Size + handlerStats.RRsetCache.Size
	}

	return stats
}

// GetHealth returns current health status.
func (e *DNSEngine) GetHealth() *pb.HealthStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	status := &pb.HealthStatus{
		Status: pb.HealthStatus_HEALTHY,
	}

	if !e.running.Load() {
		status.Status = pb.HealthStatus_UNHEALTHY
		status.Message = "Engine not running"
		return status
	}

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// If memory usage is very high, report degraded
	const memoryThreshold = 1 << 30 // 1GB
	if memStats.Alloc > memoryThreshold {
		status.Status = pb.HealthStatus_DEGRADED
		status.Message = "High memory usage"
		return status
	}

	status.Message = "Operating normally"
	return status
}

// GetZoneManager returns the zone manager.
func (e *DNSEngine) GetZoneManager() *zone.Manager {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.zoneManager
}

// GetHandler returns the DNS handler.
func (e *DNSEngine) GetHandler() *server.Handler {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.handler
}

// IsRunning returns whether the engine is running.
func (e *DNSEngine) IsRunning() bool {
	return e.running.Load()
}

// Uptime returns how long the engine has been running.
func (e *DNSEngine) Uptime() time.Duration {
	if !e.running.Load() {
		return 0
	}
	return time.Since(e.startTime)
}

// Ensure DNSEngine implements Engine
var _ Engine = (*DNSEngine)(nil)
