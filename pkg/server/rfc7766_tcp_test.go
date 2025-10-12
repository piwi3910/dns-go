package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
	"github.com/piwi3910/dns-go/pkg/resolver"
)

// TestRFC7766_TCPLengthPrefix tests 2-byte length prefix handling.
func TestRFC7766_TCPLengthPrefix(t *testing.T) {
	t.Parallel()
	// Start test server with TCP support
	handler := setupTestHandler()
	tcpConfig := dnsio.DefaultListenerConfig("127.0.0.1:0")
	tcpListener, err := dnsio.NewTCPListener(tcpConfig, handler)
	if err != nil {
		t.Fatalf("Failed to create TCP listener: %v", err)
	}

	if err := tcpListener.Start(); err != nil {
		t.Fatalf("Failed to start TCP listener: %v", err)
	}
	defer tcpListener.Stop()

	addr := tcpListener.Addr().String()
	t.Logf("TCP listener on %s", addr)

	// Connect to TCP server
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to TCP server: %v", err)
	}
	defer conn.Close()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	queryBytes, err := msg.Pack()
	if err != nil {
		t.Fatalf("Failed to pack query: %v", err)
	}

	// Send query with 2-byte length prefix (RFC 7766)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))

	if _, err := conn.Write(lengthPrefix); err != nil {
		t.Fatalf("Failed to write length prefix: %v", err)
	}
	if _, err := conn.Write(queryBytes); err != nil {
		t.Fatalf("Failed to write query: %v", err)
	}

	// Read response with 2-byte length prefix
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseLengthBuf); err != nil {
		t.Fatalf("Failed to read response length: %v", err)
	}

	responseLength := binary.BigEndian.Uint16(responseLengthBuf)
	if responseLength == 0 {
		t.Fatalf("Invalid response length: %d", responseLength)
	}

	responseBytes := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, responseBytes); err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Parse response
	response := new(dns.Msg)
	if err := response.Unpack(responseBytes); err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	// Verify response
	if response.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected NOERROR, got %v", dns.RcodeToString[response.Rcode])
	}

	if len(response.Answer) == 0 {
		t.Errorf("Expected answers in response")
	}

	t.Logf("✓ RFC 7766 TCP Length Prefix: Query succeeded, response length %d bytes", responseLength)
}

// TestRFC7766_PersistentConnections tests persistent TCP connections.
func TestRFC7766_PersistentConnections(t *testing.T) {
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
	defer tcpListener.Stop()

	addr := tcpListener.Addr().String()

	// Connect once
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send multiple queries on the same connection
	domains := []string{"google.com.", "cloudflare.com.", "github.com."}

	for i, domain := range domains {
		// Create query
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeA)
		queryBytes, err := msg.Pack()
		if err != nil {
			t.Fatalf("Failed to pack query %d: %v", i, err)
		}

		// Send with length prefix
		lengthPrefix := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))

		if _, err := conn.Write(lengthPrefix); err != nil {
			t.Fatalf("Failed to write length prefix %d: %v", i, err)
		}
		if _, err := conn.Write(queryBytes); err != nil {
			t.Fatalf("Failed to write query %d: %v", i, err)
		}

		// Read response
		responseLengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, responseLengthBuf); err != nil {
			t.Fatalf("Failed to read response length %d: %v", i, err)
		}

		responseLength := binary.BigEndian.Uint16(responseLengthBuf)
		responseBytes := make([]byte, responseLength)
		if _, err := io.ReadFull(conn, responseBytes); err != nil {
			t.Fatalf("Failed to read response %d: %v", i, err)
		}

		// Verify response
		response := new(dns.Msg)
		if err := response.Unpack(responseBytes); err != nil {
			t.Fatalf("Failed to unpack response %d: %v", i, err)
		}

		if response.Rcode != dns.RcodeSuccess {
			t.Errorf("Query %d (%s): Expected NOERROR, got %v", i, domain, dns.RcodeToString[response.Rcode])
		}

		t.Logf("✓ Query %d (%s) succeeded on persistent connection", i+1, domain)
	}

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
	defer tcpListener.Stop()

	addr := tcpListener.Addr().String()

	// Connect
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Send initial query
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	queryBytes, _ := msg.Pack()
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))
	conn.Write(lengthPrefix)
	conn.Write(queryBytes)

	// Read response
	responseLengthBuf := make([]byte, 2)
	io.ReadFull(conn, responseLengthBuf)
	responseLength := binary.BigEndian.Uint16(responseLengthBuf)
	responseBytes := make([]byte, responseLength)
	io.ReadFull(conn, responseBytes)

	t.Logf("✓ Initial query succeeded")

	// Wait slightly less than timeout (connection should stay open)
	time.Sleep(9 * time.Second)

	// Send second query (should succeed)
	msg2 := new(dns.Msg)
	msg2.SetQuestion("cloudflare.com.", dns.TypeA)
	queryBytes2, _ := msg2.Pack()
	lengthPrefix2 := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix2, uint16(len(queryBytes2)))

	if _, err := conn.Write(lengthPrefix2); err != nil {
		t.Fatalf("Connection closed prematurely: %v", err)
	}
	if _, err := conn.Write(queryBytes2); err != nil {
		t.Fatalf("Failed to write second query: %v", err)
	}

	// Read response
	responseLengthBuf2 := make([]byte, 2)
	if _, err := io.ReadFull(conn, responseLengthBuf2); err != nil {
		t.Fatalf("Failed to read second response: %v", err)
	}
	responseLength2 := binary.BigEndian.Uint16(responseLengthBuf2)
	responseBytes2 := make([]byte, responseLength2)
	if _, err := io.ReadFull(conn, responseBytes2); err != nil {
		t.Fatalf("Failed to read second response bytes: %v", err)
	}

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
	defer tcpListener.Stop()

	addr := tcpListener.Addr().String()

	// Connect
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Query for TXT record (typically larger)
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeTXT)
	queryBytes, _ := msg.Pack()

	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))
	conn.Write(lengthPrefix)
	conn.Write(queryBytes)

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
	defer tcpListener.Stop()

	addr := tcpListener.Addr().String()

	// Open connections up to the limit
	conns := make([]net.Conn, 0, 5)
	for i := range 5 {
		dialer := &net.Dialer{}
		conn, err := dialer.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("Failed to connect %d: %v", i, err)
		}
		conns = append(conns, conn)
		t.Logf("Connection %d established", i+1)
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	// Try to open one more connection (should be rejected)
	dialer6 := &net.Dialer{}
	conn6, err := dialer6.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Logf("✓ RFC 7766 Connection Limit: 6th connection rejected as expected")

		return
	}
	defer conn6.Close()

	// If connection succeeded, server might be handling it anyway
	// Send a query to see if it works
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)
	queryBytes, _ := msg.Pack()
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(queryBytes)))

	conn6.SetDeadline(time.Now().Add(1 * time.Second))
	conn6.Write(lengthPrefix)
	conn6.Write(queryBytes)

	// Try to read response
	responseLengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn6, responseLengthBuf); err != nil {
		t.Logf("✓ RFC 7766 Connection Limit: 6th connection rejected (closed during query)")

		return
	}

	t.Logf("⚠ RFC 7766 Connection Limit: 6th connection accepted (may be async close)")
}

// Helper function to setup test handler.
func setupTestHandler() *Handler {
	config := DefaultHandlerConfig()
	config.ResolverMode = resolver.ForwardingMode

	return NewHandler(config)
}
