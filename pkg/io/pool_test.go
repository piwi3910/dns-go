package io_test

import (
	"testing"

	"github.com/miekg/dns"
	dnsio "github.com/piwi3910/dns-go/pkg/io"
)

// BenchmarkBufferPool tests zero-allocation buffer pool operations.
func BenchmarkBufferPoolGet(b *testing.B) {
	pool := dnsio.NewBufferPool(dnsio.DefaultBufferSize)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		buf := pool.Get()
		pool.Put(buf)
	}
}

// BenchmarkBufferPoolGetPut tests complete get/put cycle.
func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := dnsio.NewBufferPool(dnsio.DefaultBufferSize)
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			// Simulate some work
			_ = buf[0]
			pool.Put(buf)
		}
	})
}

// BenchmarkMessagePool tests zero-allocation message pool operations.
func BenchmarkMessagePoolGet(b *testing.B) {
	pool := dnsio.NewMessagePool()
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		msg := pool.Get()
		pool.Put(msg)
	}
}

// BenchmarkMessagePoolGetPut tests complete get/put cycle.
func BenchmarkMessagePoolGetPut(b *testing.B) {
	pool := dnsio.NewMessagePool()
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			msg := pool.Get()
			// Simulate message usage
			msg.SetQuestion("example.com.", dns.TypeA)
			pool.Put(msg)
		}
	})
}

// TestBufferPoolReuse verifies buffers are actually reused.
func TestBufferPoolReuse(t *testing.T) {
	t.Parallel()
	pool := dnsio.NewBufferPool(dnsio.DefaultBufferSize)

	buf1 := pool.Get()
	ptr1 := &buf1[0]
	pool.Put(buf1)

	buf2 := pool.Get()
	ptr2 := &buf2[0]

	if ptr1 != ptr2 {
		t.Error("Buffer pool did not reuse buffer")
	}
}

// TestMessagePoolReuse verifies messages are actually reused.
func TestMessagePoolReuse(t *testing.T) {
	t.Parallel()
	pool := dnsio.NewMessagePool()

	msg1 := pool.Get()
	ptr1 := msg1
	pool.Put(msg1)

	msg2 := pool.Get()
	ptr2 := msg2

	if ptr1 != ptr2 {
		t.Error("Message pool did not reuse message")
	}
}

// TestMessagePoolReset verifies messages are properly reset.
func TestMessagePoolReset(t *testing.T) {
	t.Parallel()
	pool := dnsio.NewMessagePool()

	msg := pool.Get()
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.RecursionDesired = true
	pool.Put(msg)

	msg2 := pool.Get()
	if len(msg2.Question) != 0 {
		t.Error("Message pool did not clear Question slice")
	}
	if msg2.RecursionDesired {
		t.Error("Message pool did not reset RecursionDesired flag")
	}
}
