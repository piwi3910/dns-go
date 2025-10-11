package io

import (
	"sync"

	"github.com/miekg/dns"
)

const (
	// DefaultBufferSize is the default size for DNS message buffers
	// 4096 bytes is sufficient for most DNS messages (max UDP is 512-4096 with EDNS0)
	DefaultBufferSize = 4096

	// MaxUDPSize is the maximum UDP message size with EDNS0
	MaxUDPSize = 4096
)

// BufferPool manages reusable byte buffers to eliminate allocations in hot path
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with the specified buffer size
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, size)
				return &buf
			},
		},
		size: size,
	}
}

// Get retrieves a buffer from the pool
// CRITICAL: Caller MUST call Put() to return buffer to pool
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get().(*[]byte)
	return (*bufPtr)[:bp.size]
}

// Put returns a buffer to the pool for reuse
func (bp *BufferPool) Put(buf []byte) {
	bp.pool.Put(&buf)
}

// MessagePool manages reusable DNS message objects
type MessagePool struct {
	pool sync.Pool
}

// NewMessagePool creates a new DNS message pool
func NewMessagePool() *MessagePool {
	return &MessagePool{
		pool: sync.Pool{
			New: func() interface{} {
				return new(dns.Msg)
			},
		},
	}
}

// Get retrieves a DNS message from the pool
// CRITICAL: Caller MUST call Put() to return message to pool
func (mp *MessagePool) Get() *dns.Msg {
	msg := mp.pool.Get().(*dns.Msg)
	// Reset message to clean state
	msg.Id = 0
	msg.Response = false
	msg.Opcode = 0
	msg.Authoritative = false
	msg.Truncated = false
	msg.RecursionDesired = false
	msg.RecursionAvailable = false
	msg.Zero = false
	msg.AuthenticatedData = false
	msg.CheckingDisabled = false
	msg.Rcode = 0
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	return msg
}

// Put returns a DNS message to the pool for reuse
func (mp *MessagePool) Put(msg *dns.Msg) {
	// Clear slices but keep capacity to avoid reallocation
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]
	mp.pool.Put(msg)
}

// Global pools for common use
var (
	// DefaultBufferPool is the default buffer pool for DNS messages
	DefaultBufferPool = NewBufferPool(DefaultBufferSize)

	// DefaultMessagePool is the default message pool
	DefaultMessagePool = NewMessagePool()
)
