// Package ha provides high availability components for the DNS control plane.
package ha

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// LeaderRole represents the role of a control plane instance.
type LeaderRole string

const (
	// RoleLeader is the active leader.
	RoleLeader LeaderRole = "Leader"
	// RoleFollower is a standby follower.
	RoleFollower LeaderRole = "Follower"
	// RoleCandidate is attempting to become leader.
	RoleCandidate LeaderRole = "Candidate"
	// RoleUnknown is when role is not determined.
	RoleUnknown LeaderRole = "Unknown"
)

// LeaderElectionConfig configures leader election.
type LeaderElectionConfig struct {
	// InstanceID is the unique ID of this control plane instance.
	InstanceID string

	// ClusterID is the cluster where this instance runs.
	ClusterID string

	// LeaseDuration is how long a leader holds the lease.
	LeaseDuration time.Duration

	// RenewDeadline is the deadline for renewing the lease.
	RenewDeadline time.Duration

	// RetryPeriod is the time between retry attempts.
	RetryPeriod time.Duration

	// Priority determines failover order (lower = higher priority).
	Priority int

	// PreferredLeader marks this instance as preferred leader.
	PreferredLeader bool
}

// DefaultLeaderElectionConfig returns a default configuration.
func DefaultLeaderElectionConfig(instanceID, clusterID string) *LeaderElectionConfig {
	return &LeaderElectionConfig{
		InstanceID:      instanceID,
		ClusterID:       clusterID,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Priority:        100,
		PreferredLeader: false,
	}
}

// LeaderElector manages leader election for the control plane.
type LeaderElector struct {
	mu     sync.RWMutex
	config *LeaderElectionConfig

	// Current role.
	role LeaderRole

	// Current leader info.
	currentLeader     string
	currentLeaderCluster string
	leaderSince       *time.Time

	// Quorum manager for split-brain prevention.
	quorum *QuorumManager

	// Lease backend.
	backend LeaseBackend

	// Callbacks.
	onStartedLeading  func(context.Context)
	onStoppedLeading  func()
	onNewLeader       func(identity string)

	// Context for shutdown.
	ctx    context.Context
	cancel context.CancelFunc
}

// LeaseBackend is the interface for lease storage backends.
type LeaseBackend interface {
	// Acquire attempts to acquire the lease.
	// Returns true if acquired, false if someone else holds it.
	Acquire(ctx context.Context, identity string, duration time.Duration) (bool, error)

	// Renew renews the lease if we hold it.
	Renew(ctx context.Context, identity string, duration time.Duration) (bool, error)

	// Release releases the lease if we hold it.
	Release(ctx context.Context, identity string) error

	// GetCurrentHolder returns the current lease holder.
	GetCurrentHolder(ctx context.Context) (string, time.Time, error)
}

// NewLeaderElector creates a new leader elector.
func NewLeaderElector(config *LeaderElectionConfig, quorum *QuorumManager, backend LeaseBackend) *LeaderElector {
	if config == nil {
		config = DefaultLeaderElectionConfig("unknown", "unknown")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &LeaderElector{
		config:  config,
		role:    RoleUnknown,
		quorum:  quorum,
		backend: backend,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// OnStartedLeading sets the callback for when this instance becomes leader.
func (le *LeaderElector) OnStartedLeading(fn func(context.Context)) {
	le.mu.Lock()
	defer le.mu.Unlock()
	le.onStartedLeading = fn
}

// OnStoppedLeading sets the callback for when this instance stops being leader.
func (le *LeaderElector) OnStoppedLeading(fn func()) {
	le.mu.Lock()
	defer le.mu.Unlock()
	le.onStoppedLeading = fn
}

// OnNewLeader sets the callback for when a new leader is elected.
func (le *LeaderElector) OnNewLeader(fn func(identity string)) {
	le.mu.Lock()
	defer le.mu.Unlock()
	le.onNewLeader = fn
}

// Start begins the leader election process.
func (le *LeaderElector) Start() error {
	go le.electionLoop()
	return nil
}

// Stop stops the leader election process.
func (le *LeaderElector) Stop() {
	le.cancel()

	// Release lease if we're the leader.
	le.mu.Lock()
	wasLeader := le.role == RoleLeader
	le.role = RoleUnknown
	le.mu.Unlock()

	if wasLeader && le.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = le.backend.Release(ctx, le.config.InstanceID)
	}
}

// GetRole returns the current role.
func (le *LeaderElector) GetRole() LeaderRole {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.role
}

// IsLeader returns whether this instance is the leader.
func (le *LeaderElector) IsLeader() bool {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.role == RoleLeader
}

// GetCurrentLeader returns the current leader identity and cluster.
func (le *LeaderElector) GetCurrentLeader() (string, string) {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.currentLeader, le.currentLeaderCluster
}

// GetLeaderSince returns when the current leader became leader.
func (le *LeaderElector) GetLeaderSince() *time.Time {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.leaderSince
}

// electionLoop is the main election loop.
func (le *LeaderElector) electionLoop() {
	ticker := time.NewTicker(le.config.RetryPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-le.ctx.Done():
			return
		case <-ticker.C:
			le.runElectionRound()
		}
	}
}

// runElectionRound runs a single election round.
func (le *LeaderElector) runElectionRound() {
	le.mu.RLock()
	currentRole := le.role
	le.mu.RUnlock()

	// Check quorum first - can't lead without quorum.
	if le.quorum != nil && !le.quorum.HasQuorum() {
		if currentRole == RoleLeader {
			le.stepDown("lost quorum")
		}
		return
	}

	// Check fencing status.
	if le.quorum != nil && !le.quorum.ShouldAcceptWrites() {
		if currentRole == RoleLeader {
			le.stepDown("fenced due to quorum loss")
		}
		return
	}

	switch currentRole {
	case RoleLeader:
		le.renewLease()
	case RoleFollower, RoleCandidate, RoleUnknown:
		le.tryAcquireLease()
	}
}

// tryAcquireLease attempts to acquire the leader lease.
func (le *LeaderElector) tryAcquireLease() {
	if le.backend == nil {
		// No backend - assume single instance mode.
		le.becomeLeader()
		return
	}

	ctx, cancel := context.WithTimeout(le.ctx, le.config.RenewDeadline)
	defer cancel()

	// Check who currently holds the lease.
	currentHolder, _, err := le.backend.GetCurrentHolder(ctx)
	if err != nil {
		log.Printf("Failed to get current leader: %v", err)
		return
	}

	// Update our view of the current leader.
	le.mu.Lock()
	if currentHolder != "" && currentHolder != le.currentLeader {
		le.currentLeader = currentHolder
		if le.onNewLeader != nil {
			go le.onNewLeader(currentHolder)
		}
	}
	le.mu.Unlock()

	// Try to acquire.
	acquired, err := le.backend.Acquire(ctx, le.config.InstanceID, le.config.LeaseDuration)
	if err != nil {
		log.Printf("Failed to acquire lease: %v", err)
		le.setRole(RoleFollower)
		return
	}

	if acquired {
		le.becomeLeader()
	} else {
		le.setRole(RoleFollower)
	}
}

// renewLease renews the leader lease.
func (le *LeaderElector) renewLease() {
	if le.backend == nil {
		return
	}

	ctx, cancel := context.WithTimeout(le.ctx, le.config.RenewDeadline)
	defer cancel()

	renewed, err := le.backend.Renew(ctx, le.config.InstanceID, le.config.LeaseDuration)
	if err != nil {
		log.Printf("Failed to renew lease: %v", err)
		le.stepDown("failed to renew lease")
		return
	}

	if !renewed {
		le.stepDown("lease not renewed (someone else acquired it)")
	}
}

// becomeLeader transitions to the leader role.
func (le *LeaderElector) becomeLeader() {
	le.mu.Lock()
	wasLeader := le.role == RoleLeader
	le.role = RoleLeader
	le.currentLeader = le.config.InstanceID
	le.currentLeaderCluster = le.config.ClusterID
	now := time.Now()
	le.leaderSince = &now
	callback := le.onStartedLeading
	le.mu.Unlock()

	if !wasLeader {
		log.Printf("Became leader (instance: %s, cluster: %s)", le.config.InstanceID, le.config.ClusterID)
		if callback != nil {
			go callback(le.ctx)
		}
	}
}

// stepDown transitions from leader to follower.
func (le *LeaderElector) stepDown(reason string) {
	le.mu.Lock()
	wasLeader := le.role == RoleLeader
	le.role = RoleFollower
	le.leaderSince = nil
	callback := le.onStoppedLeading
	le.mu.Unlock()

	if wasLeader {
		log.Printf("Stepped down from leader: %s", reason)
		if callback != nil {
			go callback()
		}

		// Release the lease.
		if le.backend != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = le.backend.Release(ctx, le.config.InstanceID)
		}
	}
}

// setRole sets the role without triggering callbacks.
func (le *LeaderElector) setRole(role LeaderRole) {
	le.mu.Lock()
	defer le.mu.Unlock()
	le.role = role
}

// MemoryLeaseBackend is an in-memory lease backend for testing/single-node.
type MemoryLeaseBackend struct {
	mu           sync.Mutex
	holder       string
	expiry       time.Time
}

// NewMemoryLeaseBackend creates a new in-memory lease backend.
func NewMemoryLeaseBackend() *MemoryLeaseBackend {
	return &MemoryLeaseBackend{}
}

// Acquire attempts to acquire the lease.
func (m *MemoryLeaseBackend) Acquire(ctx context.Context, identity string, duration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Check if lease is held by someone else and not expired.
	if m.holder != "" && m.holder != identity && now.Before(m.expiry) {
		return false, nil
	}

	// Acquire or re-acquire.
	m.holder = identity
	m.expiry = now.Add(duration)
	return true, nil
}

// Renew renews the lease.
func (m *MemoryLeaseBackend) Renew(ctx context.Context, identity string, duration time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Can only renew if we hold the lease.
	if m.holder != identity {
		return false, nil
	}

	// Check if expired.
	if now.After(m.expiry) {
		return false, nil
	}

	m.expiry = now.Add(duration)
	return true, nil
}

// Release releases the lease.
func (m *MemoryLeaseBackend) Release(ctx context.Context, identity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.holder == identity {
		m.holder = ""
		m.expiry = time.Time{}
	}
	return nil
}

// GetCurrentHolder returns the current lease holder.
func (m *MemoryLeaseBackend) GetCurrentHolder(ctx context.Context) (string, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if m.holder != "" && now.After(m.expiry) {
		// Expired.
		return "", time.Time{}, nil
	}
	return m.holder, m.expiry, nil
}

// HAManager combines quorum and leader election for full HA support.
type HAManager struct {
	mu sync.RWMutex

	quorum *QuorumManager
	leader *LeaderElector
	config *HAConfig

	// State.
	enabled bool
	mode    HAMode

	// Context.
	ctx    context.Context
	cancel context.CancelFunc
}

// HAMode defines the HA operating mode.
type HAMode string

const (
	// HAModeActivePassive has one active leader.
	HAModeActivePassive HAMode = "ActivePassive"
	// HAModeActiveActive has multiple active instances (read operations).
	HAModeActiveActive HAMode = "ActiveActive"
)

// HAConfig configures the HA manager.
type HAConfig struct {
	Enabled         bool
	Mode            HAMode
	InstanceID      string
	ClusterID       string
	QuorumConfig    *QuorumConfig
	LeaderConfig    *LeaderElectionConfig
}

// NewHAManager creates a new HA manager.
func NewHAManager(config *HAConfig) *HAManager {
	ctx, cancel := context.WithCancel(context.Background())

	ham := &HAManager{
		config:  config,
		enabled: config.Enabled,
		mode:    config.Mode,
		ctx:     ctx,
		cancel:  cancel,
	}

	if !config.Enabled {
		return ham
	}

	// Create quorum manager.
	ham.quorum = NewQuorumManager(config.QuorumConfig)

	// Create leader elector.
	leaderConfig := config.LeaderConfig
	if leaderConfig == nil {
		leaderConfig = DefaultLeaderElectionConfig(config.InstanceID, config.ClusterID)
	}
	ham.leader = NewLeaderElector(leaderConfig, ham.quorum, NewMemoryLeaseBackend())

	return ham
}

// Start starts the HA manager.
func (ham *HAManager) Start() error {
	if !ham.enabled {
		return nil
	}

	ham.quorum.Start()
	return ham.leader.Start()
}

// Stop stops the HA manager.
func (ham *HAManager) Stop() {
	ham.cancel()
	if ham.leader != nil {
		ham.leader.Stop()
	}
	if ham.quorum != nil {
		ham.quorum.Stop()
	}
}

// IsEnabled returns whether HA is enabled.
func (ham *HAManager) IsEnabled() bool {
	return ham.enabled
}

// GetMode returns the HA mode.
func (ham *HAManager) GetMode() HAMode {
	return ham.mode
}

// IsLeader returns whether this instance is the leader.
func (ham *HAManager) IsLeader() bool {
	if !ham.enabled || ham.leader == nil {
		return true // Single instance is always leader.
	}
	return ham.leader.IsLeader()
}

// HasQuorum returns whether quorum is held.
func (ham *HAManager) HasQuorum() bool {
	if !ham.enabled || ham.quorum == nil {
		return true // Single instance always has quorum.
	}
	return ham.quorum.HasQuorum()
}

// ShouldAcceptWrites returns whether writes should be accepted.
func (ham *HAManager) ShouldAcceptWrites() bool {
	if !ham.enabled {
		return true
	}

	// In active-passive, only leader accepts writes.
	if ham.mode == HAModeActivePassive && !ham.IsLeader() {
		return false
	}

	// Check quorum/fencing.
	if ham.quorum != nil && !ham.quorum.ShouldAcceptWrites() {
		return false
	}

	return true
}

// ShouldAcceptReads returns whether reads should be accepted.
func (ham *HAManager) ShouldAcceptReads() bool {
	if !ham.enabled {
		return true
	}

	// In active-active, all instances accept reads.
	if ham.mode == HAModeActiveActive {
		return true
	}

	// In active-passive, only leader accepts reads.
	return ham.IsLeader()
}

// RecordWorkerHeartbeat records a worker heartbeat for quorum.
func (ham *HAManager) RecordWorkerHeartbeat(clusterID, workerID string) {
	if ham.quorum != nil {
		ham.quorum.RecordWorkerHeartbeat(clusterID, workerID)
	}
}

// GetQuorumStatus returns the current quorum status.
func (ham *HAManager) GetQuorumStatus() *QuorumStatus {
	if ham.quorum == nil {
		return nil
	}
	status := ham.quorum.GetStatus()
	return &status
}

// GetLeaderInfo returns leader information.
func (ham *HAManager) GetLeaderInfo() (identity string, cluster string, since *time.Time) {
	if ham.leader == nil {
		return "", "", nil
	}
	identity, cluster = ham.leader.GetCurrentLeader()
	since = ham.leader.GetLeaderSince()
	return
}

// GetRole returns the current role.
func (ham *HAManager) GetRole() LeaderRole {
	if ham.leader == nil {
		return RoleLeader // Single instance is always leader.
	}
	return ham.leader.GetRole()
}

// String returns a string representation of the HA state.
func (ham *HAManager) String() string {
	if !ham.enabled {
		return "HA: disabled"
	}

	role := ham.GetRole()
	hasQuorum := ham.HasQuorum()
	leader, cluster, _ := ham.GetLeaderInfo()

	return fmt.Sprintf("HA: enabled, mode=%s, role=%s, hasQuorum=%v, leader=%s@%s",
		ham.mode, role, hasQuorum, leader, cluster)
}
