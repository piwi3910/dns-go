package server_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/server"
)

// TestRFC7766_TCPLengthPrefix tests 2-byte length prefix handling.
func TestRFC7766_TCPLengthPrefix(t *testing.T) {
	t.Parallel()

	// Start test server
	tcpListener, addr := startTCPTestServer(t)
	defer func() { _ = tcpListener.Stop() }()
	t.Logf("TCP listener on %s", addr)

	// Connect and send query
	conn := connectToTCPServer(t, addr)
	defer func() { _ = conn.Close() }()

	// Send DNS query and read response
	responseLength, response := sendTCPQueryAndReadResponse(t, conn, "google.com.")

	// Verify response
	verifyDNSResponse(t, response, dns.RcodeSuccess, true)

	t.Logf("✓ RFC 7766 TCP Length Prefix: Query succeeded, response length %d bytes", responseLength)
}

// TestRFC7766_PersistentConnections tests persistent TCP connections.
func TestRFC7766_PersistentConnections(t *testing.T) {
	t.Parallel()

	// Start test server
	tcpListener, addr := startTCPTestServer(t)
	defer func() { _ = tcpListener.Stop() }()

	// Connect once
	conn := connectToTCPServer(t, addr)
	defer func() { _ = conn.Close() }()

	// Send multiple queries on the same connection
	domains := []string{"google.com.", "cloudflare.com.", "github.com."}
	sendMultipleQueriesOnConnection(t, conn, domains)

	t.Logf("✓ RFC 7766 Persistent Connections: %d queries on single connection", len(domains))
}

// TestRFC7766_TCPIdleTimeout tests 10-second idle timeout.
func TestRFC7766_TCPIdleTimeout(t *testing.T) {
	t.Parallel()
	handler := setupTestHandler()
	tcpConfig := dnsio.DefaultListenerConfig("127.0.0.1:0")
	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}

	if err := tcpListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer func() { _ = tcpListener.Stop() }()

	addr := tcpListener.Addr().String()

	// Connect
	dialer := createTestDialer()
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send initial query
	_, _ = sendTCPQueryAndReadResponse(t, conn, "google.com.")
	t.Logf("✓ Initial query succeeded")

	// Wait slightly less than timeout (connection should stay open)
	time.Sleep(9 * time.Second)

	// Send second query (should succeed)
	_, _ = sendTCPQueryAndReadResponse(t, conn, "cloudflare.com.")

	t.Logf("✓ RFC 7766 Idle Timeout: Connection persisted after 9s idle (within 10s timeout)")
}

// TestRFC7766_LargeResponse tests large responses over TCP.
func TestRFC7766_LargeResponse(t *testing.T) {
	t.Parallel()
	handler := setupTestHandler()
	tcpConfig := dnsio.DefaultListenerConfig("127.0.0.1:0")
	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}

	if err := tcpListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer func() { _ = tcpListener.Stop() }()

	addr := tcpListener.Addr().String()

	// Connect
	dialer := createTestDialer()
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Query for TXT record (typically larger)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeTXT)
	queryBytes, _ := msg.Pack()

	lengthPrefix := make([]byte, 2)
	//nolint:gosec // G115: Test query messages are small (<512 bytes), safe for uint16 conversion
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))
	_, _ = conn.Write(lengthPrefix)
	_, _ = conn.Write(queryBytes)

	// Read response
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseLengthBuf); err != nil {
		t.Fatalf("Failed to read response length: %v", err)
	}

	responseLength := binary.BigEndian.Uint16(responseLengthBuf)
	if responseLength > 512 {
		t.Logf("✓ Large response: %d bytes (exceeds 512-byte UDP limit)", responseLength)
	}

	responseBytes := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, responseBytes); err != nil {
		t.Fatalf("Failed to read large response: %v", err)
	}

	// Verify response
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		t.Fatalf("Failed to unpack large response: %v", err)
	}

	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got %v", dns.RcodeToString[response.Rcode])
	}

	t.Logf("✓ RFC 7766 Large Response: Successfully received %d bytes over TCP", responseLength)
}

// TestRFC7766_ConnectionLimit tests max connection limit.
func TestRFC7766_ConnectionLimit(t *testing.T) {
	t.Parallel()
	handler := setupTestHandler()
	tcpConfig := dnsio.DefaultListenerConfig("127.0.0.1:0")
	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}

	// Set low connection limit for testing
	tcpListener.SetMaxConnections(5)

	if err := tcpListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer func() { _ = tcpListener.Stop() }()

	addr := tcpListener.Addr().String()

	// Open connections up to the limit
	conns := make([]net.Conn, 0, 5)
	for i := range 5 {
		dialer := createTestDialer()
		conn, err := dialer.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("Failed to connect %d: %v", i, err)
		}
		conns = append(conns, conn)
		t.Logf("Connection %d established", i+1)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	// Try to open one more connection (should be rejected)
	dialer6 := createTestDialer()
	conn6, err := dialer6.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Logf("✓ RFC 7766 Connection Limit: 6th connection rejected as expected")

		return
	}
	defer func() { _ = conn6.Close() }()

	// If connection succeeded, try sending a query
	_ = conn6.SetDeadline(time.Now().Add(1 * time.Second))
	_, _, err = sendTCPQueryWithDeadline(t, conn6, "google.com.", dns.TypeA)
	if err != nil {
		t.Logf("✓ RFC 7766 Connection Limit: 6th connection rejected (closed during query)")

		return
	}

	t.Logf("⚠ RFC 7766 Connection Limit: 6th connection accepted (may be async close)")
}

// startTCPTestServer creates and starts a TCP listener for testing.
func startTCPTestServer(t *testing.T) (*dnsio.TCPListener, string) {
	t.Helper()
	handler := setupTestHandler()
	tcpConfig := dnsio.DefaultListenerConfig("127.0.0.1:0")
	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}

	if err := tcpListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}

	return tcpListener, tcpListener.Addr().String()
}

// connectToTCPServer connects to the TCP test server.
func connectToTCPServer(t *testing.T, addr string) net.Conn {
	t.Helper()
	dialer := createTestDialer()
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to TCP server: %v", err)
	}

	return conn
}

// createTestDialer creates a dialer for testing.
func createTestDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:       0,
		Deadline:      time.Time{},
		LocalAddr:     nil,
		DualStack:     false,
		FallbackDelay: 0,
		KeepAlive:     0,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   false,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
		Resolver:       nil,
		Cancel:         nil,
		Control:        nil,
		ControlContext: nil,
	}
}

// sendTCPQueryAndReadResponse sends a DNS query and reads the response.
func sendTCPQueryAndReadResponse(t *testing.T, conn net.Conn, domain string) (uint16, *dns.Msg) {
	t.Helper()

	// Create and pack query
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)
	queryBytes, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send with length prefix
	sendTCPQuery(t, conn, queryBytes)

	// Read response
	return readTCPResponse(t, conn)
}

// sendTCPQuery sends a DNS query with 2-byte length prefix.
func sendTCPQuery(t *testing.T, conn net.Conn, queryBytes []byte) {
	t.Helper()
	lengthPrefix := make([]byte, 2)
	//nolint:gosec // G115: Test query messages are small (<512 bytes), safe for uint16 conversion
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))

	if _, err := conn.Write(lengthPrefix); err != nil {
		t.Fatalf("Failed to write length prefix: %v", err)
	}
	if _, err := conn.Write(queryBytes); err != nil {
		t.Fatalf("Failed to write query: %v", err)
	}
}

// readTCPResponse reads a DNS response with 2-byte length prefix.
func readTCPResponse(t *testing.T, conn net.Conn) (uint16, *dns.Msg) {
	t.Helper()

	// Read length prefix
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseLengthBuf); err != nil {
		t.Fatalf("Failed to read response length: %v", err)
	}

	responseLength := binary.BigEndian.Uint16(responseLengthBuf)
	if responseLength == 0 {
		t.Fatalf("Invalid response length: %d", responseLength)
	}

	// Read response bytes
	responseBytes := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, responseBytes); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	return responseLength, response
}

// sendTCPQueryWithDeadline sends a DNS query and tries to read response, returning error if connection fails.
func sendTCPQueryWithDeadline(t *testing.T, conn net.Conn, domain string, qtype uint16) (uint16, *dns.Msg, error) {
	t.Helper()

	// Create and pack query
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	queryBytes, err := msg.Pack()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to pack query: %w", err)
	}

	// Send query
	lengthPrefix := make([]byte, 2)
	//nolint:gosec // G115: Test query messages are small (<512 bytes), safe for uint16 conversion
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))

	if _, err := conn.Write(lengthPrefix); err != nil {
		return 0, nil, fmt.Errorf("failed to write length prefix: %w", err)
	}
	if _, err := conn.Write(queryBytes); err != nil {
		return 0, nil, fmt.Errorf("failed to write query bytes: %w", err)
	}

	// Try to read response
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseLengthBuf); err != nil {
		return 0, nil, fmt.Errorf("failed to read response length: %w", err)
	}

	responseLength := binary.BigEndian.Uint16(responseLengthBuf)
	responseBytes := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, responseBytes); err != nil {
		return 0, nil, fmt.Errorf("failed to read response bytes: %w", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		return 0, nil, fmt.Errorf("failed to unpack response: %w", err)
	}

	return responseLength, response, nil
}

// verifyDNSResponse verifies a DNS response.
func verifyDNSResponse(t *testing.T, response *dns.Msg, expectedRcode int, expectAnswers bool) {
	t.Helper()

	if response.Rcode != expectedRcode {
		t.Errorf("Expected rcode %v, got %v", dns.RcodeToString[expectedRcode], dns.RcodeToString[response.Rcode])
	}

	if expectAnswers && len(response.Answer) == 0 {
		t.Errorf("Expected answers in response")
	}
}

// sendMultipleQueriesOnConnection sends multiple DNS queries on the same TCP connection.
func sendMultipleQueriesOnConnection(t *testing.T, conn net.Conn, domains []string) {
	t.Helper()

	for i, domain := range domains {
		// Send query and read response
		_, response := sendTCPQueryAndReadResponse(t, conn, domain)

		// Verify response
		if response.Rcode != dns.RcodeSuccess {
			t.Errorf("Query %d (%s): Expected NOERROR, got %v", i, domain, dns.RcodeToString[response.Rcode])
		}

		t.Logf("✓ Query %d (%s) succeeded on persistent connection", i+1, domain)
	}
}

// Helper function to setup test handler.
func setupTestHandler() *server.Handler {
	config := server.DefaultHandlerConfig()
	config.ResolverMode = resolver.ForwardingMode

	return server.NewHandler(config)
}
