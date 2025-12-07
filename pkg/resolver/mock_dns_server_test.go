package resolver_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/piwi3910/dns-go/pkg/resolver"
)

// MockDNSServer is a simple DNS server for testing
// Runs on a random available port and responds with pre-configured answers.
type MockDNSServer struct {
	addr      string
	port      int
	ip        string
	conn      *net.UDPConn
	responses map[string]*dns.Msg // Map of "name:type" -> response
	mu        sync.RWMutex
	running   bool
	wg        sync.WaitGroup
}

// NewMockDNSServer creates a new mock DNS server on 127.0.0.1 with a random port.
func NewMockDNSServer() (*MockDNSServer, error) {
	return NewMockDNSServerWithIP("127.0.0.1")
}

// NewMockDNSServerWithIP creates a new mock DNS server on a specific IP address with a random port.
// This allows creating multiple mock servers with different IPs for testing (e.g., 127.0.0.1, 127.0.0.2, etc.).
func NewMockDNSServerWithIP(ip string) (*MockDNSServer, error) {
	// Listen on random port
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", ip))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	server := &MockDNSServer{
		addr:      fmt.Sprintf("%s:%d", ip, localAddr.Port),
		port:      localAddr.Port,
		ip:        ip,
		conn:      conn,
		responses: make(map[string]*dns.Msg),
		running:   false,
	}

	return server, nil
}

// SetResponse configures a response for a specific query (name, type).
func (m *MockDNSServer) SetResponse(name string, qtype uint16, response *dns.Msg) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%d", name, qtype)
	m.responses[key] = response
}

// AddARecord adds a simple A record response.
func (m *MockDNSServer) AddARecord(name string, ip string, ttl uint32) error {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Response = true
	msg.Authoritative = true

	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", name, ttl, ip))
	if err != nil {
		return err
	}
	msg.Answer = append(msg.Answer, rr)

	m.SetResponse(name, dns.TypeA, msg)
	return nil
}

// AddAAAARecord adds a simple AAAA record response.
func (m *MockDNSServer) AddAAAARecord(name string, ipv6 string, ttl uint32) error {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	msg.Response = true
	msg.Authoritative = true

	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", name, ttl, ipv6))
	if err != nil {
		return err
	}
	msg.Answer = append(msg.Answer, rr)

	m.SetResponse(name, dns.TypeAAAA, msg)
	return nil
}

// AddNXDOMAIN configures an NXDOMAIN response.
func (m *MockDNSServer) AddNXDOMAIN(name string, qtype uint16) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.Response = true
	msg.Authoritative = true
	msg.Rcode = dns.RcodeNameError

	m.SetResponse(name, qtype, msg)
}

// AddDelegation adds a delegation response (NS records with optional glue).
// This is used to simulate referrals from root servers and TLD servers.
func (m *MockDNSServer) AddDelegation(zone string, nsRecords []string, glueRecords map[string]string, ttl uint32) error {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeA) // Delegation can be for any type
	msg.Response = true
	msg.Authoritative = false // Delegations are not authoritative
	msg.Rcode = dns.RcodeSuccess

	// Add NS records to Authority section
	for _, ns := range nsRecords {
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN NS %s", zone, ttl, ns))
		if err != nil {
			return fmt.Errorf("failed to create NS record: %w", err)
		}
		msg.Ns = append(msg.Ns, rr)
	}

	// Add glue records (A records for NS) to Additional section
	for ns, address := range glueRecords {
		// Extract IP from address (may have port for testing)
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			// No port, use address as-is
			host = address
			port = ""
		}

		// Create A record with just the IP
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", ns, ttl, host))
		if err != nil {
			return fmt.Errorf("failed to create glue record: %w", err)
		}
		msg.Extra = append(msg.Extra, rr)

		// If there was a port, add it as a TXT record for testing
		if port != "" {
			txt := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   ns,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Txt: []string{fmt.Sprintf("port=%s", port)},
			}
			msg.Extra = append(msg.Extra, txt)
		}
	}

	// Store for multiple query types
	m.SetResponse(zone, dns.TypeA, msg)
	m.SetResponse(zone, dns.TypeAAAA, msg)
	m.SetResponse(zone, dns.TypeNS, msg)

	return nil
}

// AddNSRecord adds an NS record response (used for NS queries).
func (m *MockDNSServer) AddNSRecord(zone string, nsName string, ttl uint32) error {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	msg.Response = true
	msg.Authoritative = true

	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN NS %s", zone, ttl, nsName))
	if err != nil {
		return fmt.Errorf("failed to create NS record: %w", err)
	}
	msg.Answer = append(msg.Answer, rr)

	m.SetResponse(zone, dns.TypeNS, msg)
	return nil
}

// AddCustomARecord adds a custom A record that can include port for testing.
// This bypasses dns.NewRR validation to allow addresses with ports.
func (m *MockDNSServer) AddCustomARecord(name string, address string, ttl uint32) error {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Response = true
	msg.Authoritative = true

	// Create A record manually to bypass validation
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: nil, // Will be set below
	}

	// Parse address (may include port)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port, use address as-is
		host = address
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}

	// For testing, store the full address in the message Extra field as metadata
	// The actual A record will have the IP, but we'll also store port info
	rr.A = ip.To4()
	if rr.A == nil {
		rr.A = ip
	}

	msg.Answer = append(msg.Answer, rr)

	// Store original address with port in Extra as TXT record (hack for testing)
	if strings.Contains(address, ":") {
		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   fmt.Sprintf("_port.%s", name),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{address},
		}
		msg.Extra = append(msg.Extra, txt)
	}

	m.SetResponse(name, dns.TypeA, msg)
	return nil
}

// Start starts the mock DNS server.
func (m *MockDNSServer) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	m.running = true
	m.mu.Unlock()

	m.wg.Add(1)
	go m.serve()

	// Wait a bit for server to be ready
	time.Sleep(50 * time.Millisecond)

	return nil
}

// serve handles incoming DNS queries.
func (m *MockDNSServer) serve() {
	defer m.wg.Done()

	buffer := make([]byte, 4096)

	for {
		m.mu.RLock()
		running := m.running
		m.mu.RUnlock()

		if !running {
			return
		}

		// Set read deadline to allow checking running flag periodically
		_ = m.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, addr, err := m.conn.ReadFromUDP(buffer)
		if err != nil {
			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Other error - might be closed connection
			return
		}

		// Parse query
		query := new(dns.Msg)
		if err := query.Unpack(buffer[:n]); err != nil {
			continue // Ignore malformed queries
		}

		// Build response
		response := m.buildResponse(query)

		// Send response
		responseBytes, err := response.Pack()
		if err != nil {
			continue
		}

		_, _ = m.conn.WriteToUDP(responseBytes, addr)
	}
}

// buildResponse creates a response for a query.
// Implements hierarchical matching: if no exact match, look for parent zone delegations.
func (m *MockDNSServer) buildResponse(query *dns.Msg) *dns.Msg {
	if len(query.Question) == 0 {
		// FORMERR
		response := new(dns.Msg)
		response.SetRcode(query, dns.RcodeFormatError)
		return response
	}

	q := query.Question[0]
	key := fmt.Sprintf("%s:%d", q.Name, q.Qtype)

	m.mu.RLock()
	response, exists := m.responses[key]

	// If no exact match, walk up the domain hierarchy to find a delegation
	// This simulates how real DNS servers return referrals for subdomains
	if !exists {
		labels := dns.SplitDomainName(q.Name)
		for i := 1; i < len(labels); i++ {
			parentZone := dns.Fqdn(strings.Join(labels[i:], "."))
			parentKey := fmt.Sprintf("%s:%d", parentZone, q.Qtype)
			if parentResp, found := m.responses[parentKey]; found {
				// Check if this is a delegation (has NS records, no answers)
				if len(parentResp.Ns) > 0 && len(parentResp.Answer) == 0 {
					response = parentResp
					exists = true
					break
				}
			}
		}
	}
	m.mu.RUnlock()

	if !exists {
		// NXDOMAIN by default
		response = new(dns.Msg)
		response.SetRcode(query, dns.RcodeNameError)
		response.Authoritative = true
		return response
	}

	// Clone response and set ID
	result := response.Copy()
	result.Id = query.Id
	result.RecursionDesired = query.RecursionDesired
	result.RecursionAvailable = true

	return result
}

// Stop stops the mock DNS server.
func (m *MockDNSServer) Stop() {
	m.mu.Lock()
	m.running = false
	m.mu.Unlock()

	if m.conn != nil {
		_ = m.conn.Close()
	}

	m.wg.Wait()
}

// Addr returns the address of the mock server (e.g., "127.0.0.1:12345").
func (m *MockDNSServer) Addr() string {
	return m.addr
}

// Port returns the port the mock server is listening on.
func (m *MockDNSServer) Port() int {
	return m.port
}

// QueryDirect sends a query directly to the mock server (for testing).
func (m *MockDNSServer) QueryDirect(query *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	response, _, err := client.ExchangeContext(ctx, query, m.addr)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// MockDNSInfrastructure represents a complete mock DNS hierarchy for iterative testing.
type MockDNSInfrastructure struct {
	RootServer    *MockDNSServer            // Single root server (simulates all 13 roots)
	TLDServers    map[string]*MockDNSServer // Map of TLD -> server
	AuthServers   map[string]*MockDNSServer // Map of domain -> server
	nsAddresses   map[string]string         // Map of NS name -> address (with port)
	serverToNS    map[*MockDNSServer]string // Map of server -> NS name (for port lookups)
	nextIPCounter int                       // Counter for unique IP generation
}

// NewMockDNSInfrastructure creates a complete mock DNS infrastructure.
// All servers run on 127.0.0.1 with different random ports.
// Port overrides are used to route to the correct server.
func NewMockDNSInfrastructure() (*MockDNSInfrastructure, error) {
	// Root server on 127.0.0.1
	rootServer, err := NewMockDNSServerWithIP("127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("failed to create root server: %w", err)
	}

	infra := &MockDNSInfrastructure{
		RootServer:    rootServer,
		TLDServers:    make(map[string]*MockDNSServer),
		AuthServers:   make(map[string]*MockDNSServer),
		nsAddresses:   make(map[string]string),
		serverToNS:    make(map[*MockDNSServer]string),
		nextIPCounter: 2, // Start from 127.0.0.2 (root conceptually at 127.0.0.1)
	}

	return infra, nil
}

// AddTLD adds a TLD server to the infrastructure.
// All servers run on 127.0.0.1 with different ports.
// The nsAddresses map stores the full address (IP:port) for NS name lookups.
func (m *MockDNSInfrastructure) AddTLD(tld string) (*MockDNSServer, error) {
	// Create server on 127.0.0.1 with random port
	server, err := NewMockDNSServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLD server for %s: %w", tld, err)
	}

	m.TLDServers[tld] = server
	m.nextIPCounter++ // Track count

	// Configure root server to delegate to this TLD server
	nsName := fmt.Sprintf("ns1.%s", tld)

	// Store NS name -> full address mapping (with port)
	m.serverToNS[server] = nsName
	m.nsAddresses[nsName] = server.Addr() // Full address with port

	// Configure root to answer A queries for the NS name
	// We store the full address in nsAddresses, but DNS A records only contain IP
	// The test uses nsAddressLookup to get the full address
	err = m.RootServer.AddARecord(nsName, server.ip, 86400)
	if err != nil {
		return nil, fmt.Errorf("failed to add A record for NS: %w", err)
	}

	// Add delegation WITH glue containing the IP
	// Note: In real DNS, glue only contains IP. We use nsAddresses for port lookup.
	err = m.RootServer.AddDelegation(
		tld,
		[]string{nsName},
		map[string]string{nsName: server.ip}, // Just IP in DNS glue
		86400,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add delegation for %s: %w", tld, err)
	}

	return server, nil
}

// AddAuthServer adds an authoritative server for a specific domain.
// All servers run on 127.0.0.1 with different ports.
// The nsAddresses map stores the full address (IP:port) for NS name lookups.
func (m *MockDNSInfrastructure) AddAuthServer(domain string, tld string) (*MockDNSServer, error) {
	// Create server on 127.0.0.1 with random port
	server, err := NewMockDNSServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create auth server for %s: %w", domain, err)
	}

	m.AuthServers[domain] = server
	m.nextIPCounter++ // Track count

	// Configure TLD server to delegate to this auth server
	tldServer, exists := m.TLDServers[tld]
	if !exists {
		return nil, fmt.Errorf("TLD server for %s not found", tld)
	}

	nsName := fmt.Sprintf("ns1.%s", domain)

	// Store NS name -> full address mapping (with port)
	m.serverToNS[server] = nsName
	m.nsAddresses[nsName] = server.Addr() // Full address with port

	// Add delegation WITH glue containing the IP
	// Note: In real DNS, glue only contains IP. We use nsAddresses for port lookup.
	err = tldServer.AddDelegation(
		domain,
		[]string{nsName},
		map[string]string{nsName: server.ip}, // Just IP in DNS glue
		86400,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to add delegation for %s: %w", domain, err)
	}

	return server, nil
}

// Start starts all servers in the infrastructure.
func (m *MockDNSInfrastructure) Start() error {
	if err := m.RootServer.Start(); err != nil {
		return fmt.Errorf("failed to start root server: %w", err)
	}

	for tld, server := range m.TLDServers {
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start TLD server for %s: %w", tld, err)
		}
	}

	for domain, server := range m.AuthServers {
		if err := server.Start(); err != nil {
			return fmt.Errorf("failed to start auth server for %s: %w", domain, err)
		}
	}

	return nil
}

// Stop stops all servers in the infrastructure.
func (m *MockDNSInfrastructure) Stop() {
	m.RootServer.Stop()

	for _, server := range m.TLDServers {
		server.Stop()
	}

	for _, server := range m.AuthServers {
		server.Stop()
	}
}

// GetRootHints returns root hints configuration for the mock root server.
func (m *MockDNSInfrastructure) GetRootHints() []string {
	return []string{m.RootServer.Addr()}
}

// CreateTestClient creates a DNS client that routes requests to the correct mock servers.
// This allows the iterative resolver to work with mock servers on non-standard ports.
func (m *MockDNSInfrastructure) CreateTestClient() *dns.Client {
	return &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
		Dialer: &net.Dialer{
			Timeout: 5 * time.Second,
		},
		// Override dialer to route to correct ports
	}
}

// GetNSAddressLookup returns a map of NS name -> full address for all mock servers in the infrastructure.
// This allows the iterative resolver to look up the correct address (with port) for each NS name.
func (m *MockDNSInfrastructure) GetNSAddressLookup() map[string]string {
	return m.nsAddresses
}

// CreateIterativeResolver creates an iterative resolver configured for this mock infrastructure.
func (m *MockDNSInfrastructure) CreateIterativeResolver() *resolver.IterativeResolver {
	rootPool := resolver.NewRootServerPoolWithAddresses(m.GetRootHints())
	nsLookup := m.GetNSAddressLookup()
	return resolver.NewIterativeResolverWithNSLookup(rootPool, nsLookup)
}
