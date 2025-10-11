package io

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenerConfig holds configuration for DNS listeners
type ListenerConfig struct {
	// Address to listen on (e.g., ":53" or "0.0.0.0:53")
	Address string

	// NumWorkers is the number of worker goroutines (typically NumCPU)
	NumWorkers int

	// ReusePort enables SO_REUSEPORT for per-core load distribution
	ReusePort bool

	// ReadBufferSize is the size of the socket read buffer (default: 4MB)
	ReadBufferSize int

	// WriteBufferSize is the size of the socket write buffer (default: 4MB)
	WriteBufferSize int
}

// DefaultListenerConfig returns a configuration with sensible defaults
func DefaultListenerConfig(address string) *ListenerConfig {
	return &ListenerConfig{
		Address:         address,
		NumWorkers:      runtime.NumCPU(),
		ReusePort:       true,
		ReadBufferSize:  4 * 1024 * 1024,  // 4MB (handles traffic spikes)
		WriteBufferSize: 4 * 1024 * 1024,  // 4MB
	}
}

// UDPListener manages multiple UDP sockets with SO_REUSEPORT
type UDPListener struct {
	config  *ListenerConfig
	conns   []*net.UDPConn
	handler QueryHandler
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

// QueryHandler processes DNS queries
// Returns response bytes and error
type QueryHandler interface {
	HandleQuery(ctx context.Context, query []byte, addr net.Addr) ([]byte, error)
}

// NewUDPListener creates a new UDP listener with the given configuration
func NewUDPListener(config *ListenerConfig, handler QueryHandler) (*UDPListener, error) {
	if config == nil {
		config = DefaultListenerConfig(":53")
	}

	ctx, cancel := context.WithCancel(context.Background())

	listener := &UDPListener{
		config:  config,
		conns:   make([]*net.UDPConn, 0, config.NumWorkers),
		handler: handler,
		ctx:     ctx,
		cancel:  cancel,
	}

	return listener, nil
}

// Start begins listening and processing queries
// Creates one UDP socket per worker with SO_REUSEPORT for load distribution
func (ul *UDPListener) Start() error {
	addr, err := net.ResolveUDPAddr("udp", ul.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Create one socket per worker for per-core load distribution
	for i := 0; i < ul.config.NumWorkers; i++ {
		conn, err := ul.createUDPSocket(addr)
		if err != nil {
			// Clean up already created sockets
			ul.Stop()
			return fmt.Errorf("failed to create UDP socket %d: %w", i, err)
		}

		ul.conns = append(ul.conns, conn)

		// Start worker goroutine for this socket
		ul.wg.Add(1)
		go ul.worker(i, conn)
	}

	return nil
}

// createUDPSocket creates a UDP socket with SO_REUSEPORT and tuned buffer sizes
func (ul *UDPListener) createUDPSocket(addr *net.UDPAddr) (*net.UDPConn, error) {
	// Create socket with control options
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if ul.config.ReusePort {
					// Enable SO_REUSEPORT for per-core load distribution
					// This is critical for scaling beyond single-core performance
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						sockErr = fmt.Errorf("failed to set SO_REUSEPORT: %w", err)
						return
					}
				}

				// Set large receive buffer to handle traffic spikes
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, ul.config.ReadBufferSize); err != nil {
					sockErr = fmt.Errorf("failed to set SO_RCVBUF: %w", err)
					return
				}

				// Set large send buffer
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, ul.config.WriteBufferSize); err != nil {
					sockErr = fmt.Errorf("failed to set SO_SNDBUF: %w", err)
					return
				}
			})

			if err != nil {
				return err
			}
			return sockErr
		},
	}

	packetConn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}

	return packetConn.(*net.UDPConn), nil
}

// worker is the main processing loop for a single UDP socket
// This runs in its own goroutine, pinned to an OS thread for optimal performance
func (ul *UDPListener) worker(id int, conn *net.UDPConn) {
	defer ul.wg.Done()

	// Pin this goroutine to an OS thread for consistent performance
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Each worker has its own buffer pool to avoid contention
	bufferPool := NewBufferPool(DefaultBufferSize)

	for {
		select {
		case <-ul.ctx.Done():
			return
		default:
		}

		// Get buffer from pool (zero allocation)
		buf := bufferPool.Get()

		// Read DNS query
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(buf)
			if ul.ctx.Err() != nil {
				// Context cancelled, shutting down
				return
			}
			// Log error but continue processing
			continue
		}

		// Process query
		response, err := ul.handler.HandleQuery(ul.ctx, buf[:n], addr)
		if err != nil {
			bufferPool.Put(buf)
			// Log error but continue
			continue
		}

		// Send response
		if response != nil {
			_, err = conn.WriteToUDP(response, addr)
			if err != nil {
				// Log error but continue
			}
		}

		// Return buffer to pool
		bufferPool.Put(buf)
	}
}

// Stop gracefully stops all listeners
func (ul *UDPListener) Stop() error {
	ul.cancel()

	// Close all connections
	for _, conn := range ul.conns {
		if conn != nil {
			conn.Close()
		}
	}

	// Wait for all workers to finish
	ul.wg.Wait()

	return nil
}

// Addr returns the listener address
func (ul *UDPListener) Addr() net.Addr {
	if len(ul.conns) > 0 && ul.conns[0] != nil {
		return ul.conns[0].LocalAddr()
	}
	return nil
}
