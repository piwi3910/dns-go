package bridge

import (
	"log"
	"sync"
)

// RestartCallback is a function that will be called when a restart is required.
// It should trigger a graceful restart of the DNS server.
type RestartCallback func(reason string)

// RestartManager manages restart requests from config changes.
type RestartManager struct {
	mu       sync.Mutex
	callback RestartCallback
	pending  bool
	reason   string
}

// NewRestartManager creates a new RestartManager.
func NewRestartManager() *RestartManager {
	return &RestartManager{}
}

// SetCallback sets the restart callback function.
func (rm *RestartManager) SetCallback(cb RestartCallback) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.callback = cb
}

// RequestRestart requests a server restart with the given reason.
// If a callback is set, it will be called immediately.
// If no callback is set, the request is queued for when a callback is registered.
func (rm *RestartManager) RequestRestart(reason string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	log.Printf("Restart requested: %s", reason)

	if rm.callback != nil {
		// Execute callback outside the lock to prevent deadlocks
		cb := rm.callback
		rm.mu.Unlock()
		cb(reason)
		rm.mu.Lock()
	} else {
		// Queue the restart request
		rm.pending = true
		rm.reason = reason
	}
}

// HasPendingRestart returns true if there's a pending restart request.
func (rm *RestartManager) HasPendingRestart() (bool, string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.pending, rm.reason
}

// ClearPendingRestart clears any pending restart request.
func (rm *RestartManager) ClearPendingRestart() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.pending = false
	rm.reason = ""
}

// DefaultRestartManager is a global restart manager instance.
var DefaultRestartManager = NewRestartManager()
