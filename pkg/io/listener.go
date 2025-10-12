package io

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ListenerConfig holds configuration for DNS listeners.
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

// DefaultListenerConfig returns a configuration with sensible defaults.
func DefaultListenerConfig(address string) *ListenerConfig {
	return &ListenerConfig{
		Address:         address,
		NumWorkers:      runtime.NumCPU(),
		ReusePort:       true,
		ReadBufferSize:  4 * 1024 * 1024, // 4MB (handles traffic spikes)
		WriteBufferSize: 4 * 1024 * 1024, // 4MB
	}
}

// createSocketControlFunc creates a socket control function that configures SO_REUSEPORT and buffer sizes.
// This helper reduces code duplication between UDP and TCP socket creation.
func createSocketControlFunc(config *ListenerConfig) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if config.ReusePort {
				// Enable SO_REUSEPORT for per-core load distribution
				// This is critical for scaling beyond single-core performance
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					sockErr = fmt.Errorf("failed to set SO_REUSEPORT: %w", err)

					return
				}
			}

			// Set large receive buffer to handle traffic spikes
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, config.ReadBufferSize); err != nil {
				sockErr = fmt.Errorf("failed to set SO_RCVBUF: %w", err)

				return
			}

			// Set large send buffer
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, config.WriteBufferSize); err != nil {
				sockErr = fmt.Errorf("failed to set SO_SNDBUF: %w", err)

				return
			}
		})

		if err != nil {
			return err
		}

		return sockErr
	}
}

// UDPListener manages multiple UDP sockets with SO_REUSEPORT.
type UDPListener struct {
	config  *ListenerConfig
	conns   []*net.UDPConn
	handler QueryHandler
	wg      sync.WaitGroup
	done    chan struct{}
}

// QueryHandler processes DNS queries
// Returns response bytes and error.
type QueryHandler interface {
	HandleQuery(ctx context.Context, query []byte, addr net.Addr) ([]byte, error)
}

// NewUDPListener creates a new UDP listener with the given configuration.
func NewUDPListener(config *ListenerConfig, handler QueryHandler) (*UDPListener, error) {
	if config == nil {
		config = DefaultListenerConfig(":53")
	}

	listener := &UDPListener{
		config:  config,
		conns:   make([]*net.UDPConn, 0, config.NumWorkers),
		handler: handler,
		wg:      sync.WaitGroup{},
		done:    make(chan struct{}),
	}

	return listener, nil
}

// Start begins listening and processing queries
// Creates one UDP socket per worker with SO_REUSEPORT for load distribution.
func (ul *UDPListener) Start() error {
	addr, err := net.ResolveUDPAddr("udp", ul.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	// Create one socket per worker for per-core load distribution
	for i := range ul.config.NumWorkers {
		conn, err := ul.createUDPSocket(addr)
		if err != nil {
			// Clean up already created sockets
			_ = ul.Stop() // Ignore cleanup errors during initialization failure

			return fmt.Errorf("failed to create UDP socket %d: %w", i, err)
		}

		ul.conns = append(ul.conns, conn)

		// Start worker goroutine for this socket
		ul.wg.Add(1)
		go ul.worker(i, conn)
	}

	return nil
}

// createUDPSocket creates a UDP socket with SO_REUSEPORT and tuned buffer sizes.
func (ul *UDPListener) createUDPSocket(addr *net.UDPAddr) (*net.UDPConn, error) {
	// Create socket with control options
	lc := net.ListenConfig{
		Control:   createSocketControlFunc(ul.config),
		KeepAlive: 0,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   false,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
	}

	packetConn, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}

	// Type assert to *net.UDPConn with safety check
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("ListenPacket did not return *net.UDPConn (got %T)", packetConn)
	}

	return udpConn, nil
}

// worker is the main processing loop for a single UDP socket
// This runs in its own goroutine, pinned to an OS thread for optimal performance.
func (ul *UDPListener) worker(id int, conn *net.UDPConn) {
	defer ul.wg.Done()

	// Pin this goroutine to an OS thread for consistent performance
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Each worker has its own buffer pool to avoid contention
	bufferPool := NewBufferPool(DefaultBufferSize)

	for {
		select {
		case <-ul.done:
			return
		default:
		}

		// Get buffer from pool (zero allocation)
		buf := bufferPool.Get()

		// Read DNS query
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			bufferPool.Put(buf)
			select {
			case <-ul.done:
				// Shutting down
				return
			default:
			}
			// Log error but continue processing
			continue
		}

		// Process query
		response, err := ul.handler.HandleQuery(context.Background(), buf[:n], addr)
		if err != nil {
			bufferPool.Put(buf)
			// Log error but continue
			continue
		}

		// Send response
		if response != nil {
			// Ignore write errors - log in production
			_, _ = conn.WriteToUDP(response, addr)
		}

		// Return buffer to pool
		bufferPool.Put(buf)
	}
}

// Stop gracefully stops all listeners.
func (ul *UDPListener) Stop() error {
	close(ul.done)

	// Close all connections
	for _, conn := range ul.conns {
		if conn != nil {
			_ = conn.Close() // Ignore errors during shutdown
		}
	}

	// Wait for all workers to finish
	ul.wg.Wait()

	return nil
}

// Addr returns the listener address.
func (ul *UDPListener) Addr() net.Addr {
	if len(ul.conns) > 0 && ul.conns[0] != nil {
		return ul.conns[0].LocalAddr()
	}

	return nil
}

// TCPListener manages TCP connections for DNS queries
// RFC 7766: DNS Transport over TCP.
type TCPListener struct {
	config   *ListenerConfig
	listener net.Listener
	handler  QueryHandler
	wg       sync.WaitGroup
	done     chan struct{}

	// Connection management
	maxConnections int
	activeConns    int
	connMutex      sync.Mutex
}

// NewTCPListener creates a new TCP listener with the given configuration.
func NewTCPListener(config *ListenerConfig, handler QueryHandler) (*TCPListener, error) {
	if config == nil {
		config = DefaultListenerConfig(":53")
	}

	listener := &TCPListener{
		config:         config,
		listener:       nil,
		handler:        handler,
		wg:             sync.WaitGroup{},
		done:           make(chan struct{}),
		maxConnections: 1000, // RFC 7766 recommendation
		activeConns:    0,
		connMutex:      sync.Mutex{},
	}

	return listener, nil
}

// Start begins listening for TCP connections.
func (tl *TCPListener) Start() error {
	addr, err := net.ResolveTCPAddr("tcp", tl.config.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	// Create TCP listener with socket options
	lc := net.ListenConfig{
		Control:   createSocketControlFunc(tl.config),
		KeepAlive: 0,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   false,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
	}

	listener, err := lc.Listen(context.Background(), "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}

	tl.listener = listener

	// Start accept loop
	tl.wg.Add(1)
	go tl.acceptLoop()

	return nil
}

// acceptLoop accepts new TCP connections and spawns handlers.
func (tl *TCPListener) acceptLoop() {
	defer tl.wg.Done()

	for {
		select {
		case <-tl.done:
			return
		default:
		}

		conn, err := tl.listener.Accept()
		if err != nil {
			select {
			case <-tl.done:
				// Shutting down
				return
			default:
			}
			// Log error but continue
			continue
		}

		// Check connection limit
		tl.connMutex.Lock()
		if tl.activeConns >= tl.maxConnections {
			tl.connMutex.Unlock()
			_ = conn.Close() // Reject connection - ignore close error

			continue
		}
		tl.activeConns++
		tl.connMutex.Unlock()

		// Handle connection in separate goroutine
		tl.wg.Add(1)
		go tl.handleConnection(conn)
	}
}

// handleConnection processes a single TCP connection
// RFC 7766: DNS messages over TCP are prefixed with 2-byte length.
func (tl *TCPListener) handleConnection(conn net.Conn) {
	defer tl.wg.Done()
	defer func() { _ = conn.Close() }() // Ignore close error in defer
	defer func() {
		tl.connMutex.Lock()
		tl.activeConns--
		tl.connMutex.Unlock()
	}()

	// Set read/write timeouts
	// RFC 7766 recommends at least 10 seconds idle timeout
	const (
		readTimeout  = 10 * time.Second
		writeTimeout = 10 * time.Second
	)

	bufferPool := NewBufferPool(DefaultBufferSize)

	for {
		select {
		case <-tl.done:
			return
		default:
		}

		// Set read deadline
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout)) // Ignore deadline error

		// Read 2-byte length prefix (RFC 7766)
		lengthBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lengthBuf)
		if err != nil {
			// Connection closed or timeout
			return
		}

		// Parse message length (big endian)
		messageLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])

		// Validate message length (RFC 1035: max 65535 bytes)
		if messageLen == 0 || messageLen > 65535 {
			return // Invalid length, close connection
		}

		// Read DNS message
		queryBuf := bufferPool.Get()
		if len(queryBuf) < messageLen {
			// Need larger buffer
			queryBuf = make([]byte, messageLen)
		}

		_, err = io.ReadFull(conn, queryBuf[:messageLen])
		if err != nil {
			bufferPool.Put(queryBuf)

			return
		}

		// Process query
		response, err := tl.handler.HandleQuery(context.Background(), queryBuf[:messageLen], conn.RemoteAddr())
		if err != nil {
			bufferPool.Put(queryBuf)

			return
		}

		// Send response with 2-byte length prefix
		if response != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout)) // Ignore deadline error

			// Build response with length prefix
			responseLen := len(response)
			responseBuf := make([]byte, 2+responseLen)
			responseBuf[0] = byte(responseLen >> 8)   // High byte
			responseBuf[1] = byte(responseLen & 0xFF) // Low byte
			copy(responseBuf[2:], response)

			_, err = conn.Write(responseBuf)
			if err != nil {
				bufferPool.Put(queryBuf)

				return
			}
		}

		bufferPool.Put(queryBuf)

		// RFC 7766: TCP connections should be persistent
		// Continue reading more queries on same connection
	}
}

// Stop gracefully stops the TCP listener.
func (tl *TCPListener) Stop() error {
	close(tl.done)

	// Close listener (stops accepting new connections)
	if tl.listener != nil {
		_ = tl.listener.Close() // Ignore errors during shutdown
	}

	// Wait for all connection handlers to finish
	tl.wg.Wait()

	return nil
}

// Addr returns the listener address.
func (tl *TCPListener) Addr() net.Addr {
	if tl.listener != nil {
		return tl.listener.Addr()
	}

	return nil
}

// SetMaxConnections sets the maximum number of concurrent TCP connections.
func (tl *TCPListener) SetMaxConnections(max int) {
	tl.connMutex.Lock()
	defer tl.connMutex.Unlock()
	tl.maxConnections = max
}
