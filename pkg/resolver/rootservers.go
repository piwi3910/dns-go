package resolver

import (
	"net"
	"sync"
	"time"
)

// Root server configuration constants.
const (
	rootServerPoolCapacity = 26 // 13 root servers * 2 (IPv4 + IPv6)
	rttEMADivisor          = 8  // Exponential moving average divisor for RTT calculation
)

// RootServer represents a DNS root server with its addresses.
type RootServer struct {
	Name string
	IPv4 []string
	IPv6 []string
}

// RootServerPool manages queries to root servers.
type RootServerPool struct {
	servers []string // Flattened list of all root server IPs
	current int      // Round-robin index
	mu      sync.RWMutex

	// Performance tracking
	rttMap map[string]time.Duration
	rttMu  sync.RWMutex
}

// NewRootServerPool creates a new root server pool.
func NewRootServerPool() *RootServerPool {
	// Root hints: the 13 DNS root servers (a-m.root-servers.net)
	// These are relatively static and maintained by IANA.
	rootHints := []RootServer{
		{Name: "a.root-servers.net", IPv4: []string{"198.41.0.4"}, IPv6: []string{"2001:503:ba3e::2:30"}},
		{Name: "b.root-servers.net", IPv4: []string{"199.9.14.201"}, IPv6: []string{"2001:500:200::b"}},
		{Name: "c.root-servers.net", IPv4: []string{"192.33.4.12"}, IPv6: []string{"2001:500:2::c"}},
		{Name: "d.root-servers.net", IPv4: []string{"199.7.91.13"}, IPv6: []string{"2001:500:2d::d"}},
		{Name: "e.root-servers.net", IPv4: []string{"192.203.230.10"}, IPv6: []string{"2001:500:a8::e"}},
		{Name: "f.root-servers.net", IPv4: []string{"192.5.5.241"}, IPv6: []string{"2001:500:2f::f"}},
		{Name: "g.root-servers.net", IPv4: []string{"192.112.36.4"}, IPv6: []string{"2001:500:12::d0d"}},
		{Name: "h.root-servers.net", IPv4: []string{"198.97.190.53"}, IPv6: []string{"2001:500:1::53"}},
		{Name: "i.root-servers.net", IPv4: []string{"192.36.148.17"}, IPv6: []string{"2001:7fe::53"}},
		{Name: "j.root-servers.net", IPv4: []string{"192.58.128.30"}, IPv6: []string{"2001:503:c27::2:30"}},
		{Name: "k.root-servers.net", IPv4: []string{"193.0.14.129"}, IPv6: []string{"2001:7fd::1"}},
		{Name: "l.root-servers.net", IPv4: []string{"199.7.83.42"}, IPv6: []string{"2001:500:9f::42"}},
		{Name: "m.root-servers.net", IPv4: []string{"202.12.27.33"}, IPv6: []string{"2001:dc3::35"}},
	}

	pool := &RootServerPool{
		servers: make([]string, 0, rootServerPoolCapacity), // 13 servers * 2 (IPv4 + IPv6)
		current: 0,
		mu:      sync.RWMutex{},
		rttMap:  make(map[string]time.Duration),
		rttMu:   sync.RWMutex{},
	}

	// Flatten root servers into address list
	// Prioritize IPv4 for now (IPv6 support can be added later)
	for _, root := range rootHints {
		for _, ipv4 := range root.IPv4 {
			pool.servers = append(pool.servers, net.JoinHostPort(ipv4, "53"))
		}
	}

	return pool
}

// GetNext returns the next root server to query (round-robin with RTT awareness).
func (p *RootServerPool) GetNext() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.servers) == 0 {
		return ""
	}

	// Simple round-robin for now
	// Note: RTT-based selection could be implemented. See issue #2
	server := p.servers[p.current]
	p.current = (p.current + 1) % len(p.servers)

	return server
}

// RecordRTT records the RTT for a root server.
func (p *RootServerPool) RecordRTT(server string, rtt time.Duration) {
	p.rttMu.Lock()
	defer p.rttMu.Unlock()

	// Simple exponential moving average (EMA): new = (old * (n-1) + new) / n
	if existing, exists := p.rttMap[server]; exists {
		p.rttMap[server] = (existing*(rttEMADivisor-1) + rtt) / rttEMADivisor
	} else {
		p.rttMap[server] = rtt
	}
}

// GetAllServers returns all root server addresses.
func (p *RootServerPool) GetAllServers() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]string, len(p.servers))
	copy(result, p.servers)

	return result
}
