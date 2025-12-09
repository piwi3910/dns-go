// Package ha provides high availability components for the DNS control plane.
package ha

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// QuorumType defines the type of quorum mechanism.
type QuorumType string

const (
	// QuorumTypeMajority requires >50% of voters.
	QuorumTypeMajority QuorumType = "Majority"
	// QuorumTypeWorkerWitness uses workers as witness nodes.
	QuorumTypeWorkerWitness QuorumType = "WorkerWitness"
	// QuorumTypeExternalWitness uses an external witness service.
	QuorumTypeExternalWitness QuorumType = "ExternalWitness"
)

// VoteWeight defines how worker votes are weighted.
type VoteWeight string

const (
	// VoteWeightEqual gives each cluster's workers one vote.
	VoteWeightEqual VoteWeight = "Equal"
	// VoteWeightProportional weights votes by worker count.
	VoteWeightProportional VoteWeight = "Proportional"
)

// QuorumConfig configures the quorum mechanism.
type QuorumConfig struct {
	Type              QuorumType
	MinimumQuorum     int
	FencingEnabled    bool
	GracePeriod       time.Duration
	WorkerWitness     *WorkerWitnessConfig
	ExternalWitness   *ExternalWitnessConfig
}

// WorkerWitnessConfig configures worker-based quorum.
type WorkerWitnessConfig struct {
	MinClustersRequired  int
	MinWorkersPerCluster int
	VoteWeight           VoteWeight
	HeartbeatInterval    time.Duration
	HeartbeatTimeout     time.Duration
}

// ExternalWitnessConfig configures external witness quorum.
type ExternalWitnessConfig struct {
	Endpoint string
	Type     string
}

// DefaultQuorumConfig returns a default quorum configuration.
func DefaultQuorumConfig() *QuorumConfig {
	return &QuorumConfig{
		Type:           QuorumTypeWorkerWitness,
		MinimumQuorum:  1,
		FencingEnabled: true,
		GracePeriod:    30 * time.Second,
		WorkerWitness: &WorkerWitnessConfig{
			MinClustersRequired:  1,
			MinWorkersPerCluster: 1,
			VoteWeight:           VoteWeightEqual,
			HeartbeatInterval:    5 * time.Second,
			HeartbeatTimeout:     15 * time.Second,
		},
	}
}

// ClusterVote represents a vote from a cluster's workers.
type ClusterVote struct {
	ClusterID     string
	WorkersTotal  int
	WorkersVoting int
	LastHeartbeat time.Time
	VoteValid     bool
}

// QuorumStatus represents the current quorum state.
type QuorumStatus struct {
	HasQuorum       bool
	QuorumType      QuorumType
	VotersTotal     int
	VotersReachable int
	ClusterVotes    []ClusterVote
	LastCheck       time.Time
	QuorumLostSince *time.Time
}

// QuorumManager manages quorum for the control plane.
type QuorumManager struct {
	mu     sync.RWMutex
	config *QuorumConfig

	// Worker heartbeat tracking per cluster.
	clusterHeartbeats map[string]*clusterHeartbeatState

	// Current quorum status.
	status QuorumStatus

	// Callbacks for quorum changes.
	onQuorumLost   func()
	onQuorumGained func()

	// Context for shutdown.
	ctx    context.Context
	cancel context.CancelFunc
}

// clusterHeartbeatState tracks worker heartbeats from a cluster.
type clusterHeartbeatState struct {
	clusterID        string
	workers          map[string]time.Time // workerID -> lastHeartbeat
	lastAnyHeartbeat time.Time
}

// NewQuorumManager creates a new quorum manager.
func NewQuorumManager(config *QuorumConfig) *QuorumManager {
	if config == nil {
		config = DefaultQuorumConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	qm := &QuorumManager{
		config:            config,
		clusterHeartbeats: make(map[string]*clusterHeartbeatState),
		status: QuorumStatus{
			HasQuorum:  false,
			QuorumType: config.Type,
		},
		ctx:    ctx,
		cancel: cancel,
	}

	return qm
}

// Start starts the quorum manager's background tasks.
func (qm *QuorumManager) Start() {
	go qm.monitorLoop()
}

// Stop stops the quorum manager.
func (qm *QuorumManager) Stop() {
	qm.cancel()
}

// OnQuorumLost sets the callback for when quorum is lost.
func (qm *QuorumManager) OnQuorumLost(fn func()) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	qm.onQuorumLost = fn
}

// OnQuorumGained sets the callback for when quorum is gained.
func (qm *QuorumManager) OnQuorumGained(fn func()) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	qm.onQuorumGained = fn
}

// RecordWorkerHeartbeat records a heartbeat from a worker.
func (qm *QuorumManager) RecordWorkerHeartbeat(clusterID, workerID string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	now := time.Now()

	state, exists := qm.clusterHeartbeats[clusterID]
	if !exists {
		state = &clusterHeartbeatState{
			clusterID: clusterID,
			workers:   make(map[string]time.Time),
		}
		qm.clusterHeartbeats[clusterID] = state
	}

	state.workers[workerID] = now
	state.lastAnyHeartbeat = now
}

// RemoveWorker removes a worker from tracking.
func (qm *QuorumManager) RemoveWorker(clusterID, workerID string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	if state, exists := qm.clusterHeartbeats[clusterID]; exists {
		delete(state.workers, workerID)
	}
}

// GetStatus returns the current quorum status.
func (qm *QuorumManager) GetStatus() QuorumStatus {
	qm.mu.RLock()
	defer qm.mu.RUnlock()
	return qm.status
}

// HasQuorum returns whether quorum is currently held.
func (qm *QuorumManager) HasQuorum() bool {
	qm.mu.RLock()
	defer qm.mu.RUnlock()
	return qm.status.HasQuorum
}

// checkQuorum evaluates the current quorum state.
func (qm *QuorumManager) checkQuorum() QuorumStatus {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	now := time.Now()
	status := QuorumStatus{
		QuorumType:  qm.config.Type,
		LastCheck:   now,
		HasQuorum:   false,
	}

	switch qm.config.Type {
	case QuorumTypeWorkerWitness:
		status = qm.checkWorkerWitnessQuorum(now)
	case QuorumTypeMajority:
		status = qm.checkMajorityQuorum(now)
	case QuorumTypeExternalWitness:
		status = qm.checkExternalWitnessQuorum(now)
	}

	// Track quorum changes.
	previousHadQuorum := qm.status.HasQuorum
	if status.HasQuorum && !previousHadQuorum {
		// Gained quorum.
		status.QuorumLostSince = nil
		if qm.onQuorumGained != nil {
			go qm.onQuorumGained()
		}
	} else if !status.HasQuorum && previousHadQuorum {
		// Lost quorum.
		lostTime := now
		status.QuorumLostSince = &lostTime
		if qm.onQuorumLost != nil {
			go qm.onQuorumLost()
		}
	} else if !status.HasQuorum && qm.status.QuorumLostSince != nil {
		// Still don't have quorum.
		status.QuorumLostSince = qm.status.QuorumLostSince
	}

	qm.status = status
	return status
}

// checkWorkerWitnessQuorum checks quorum using worker witnesses.
func (qm *QuorumManager) checkWorkerWitnessQuorum(now time.Time) QuorumStatus {
	cfg := qm.config.WorkerWitness
	if cfg == nil {
		cfg = &WorkerWitnessConfig{
			MinClustersRequired:  1,
			MinWorkersPerCluster: 1,
			HeartbeatTimeout:     15 * time.Second,
		}
	}

	status := QuorumStatus{
		QuorumType: QuorumTypeWorkerWitness,
		LastCheck:  now,
	}

	var validClusters int
	var totalWorkers int
	cutoff := now.Add(-cfg.HeartbeatTimeout)

	for clusterID, state := range qm.clusterHeartbeats {
		vote := ClusterVote{
			ClusterID:     clusterID,
			WorkersTotal:  len(state.workers),
			LastHeartbeat: state.lastAnyHeartbeat,
		}

		// Count workers with recent heartbeats.
		var reachableWorkers int
		for _, lastHB := range state.workers {
			if lastHB.After(cutoff) {
				reachableWorkers++
			}
		}
		vote.WorkersVoting = reachableWorkers

		// Check if this cluster's vote is valid.
		vote.VoteValid = reachableWorkers >= cfg.MinWorkersPerCluster
		if vote.VoteValid {
			validClusters++
			totalWorkers += reachableWorkers
		}

		status.ClusterVotes = append(status.ClusterVotes, vote)
		status.VotersTotal++
		if vote.VoteValid {
			status.VotersReachable++
		}
	}

	// Determine if we have quorum.
	status.HasQuorum = validClusters >= cfg.MinClustersRequired &&
		totalWorkers >= qm.config.MinimumQuorum

	return status
}

// checkMajorityQuorum checks traditional majority quorum.
func (qm *QuorumManager) checkMajorityQuorum(now time.Time) QuorumStatus {
	// For majority quorum, we need to track control plane instances.
	// This is a placeholder - actual implementation would track peer CPs.
	return QuorumStatus{
		QuorumType: QuorumTypeMajority,
		LastCheck:  now,
		HasQuorum:  true, // Placeholder: assume quorum in single-instance mode.
	}
}

// checkExternalWitnessQuorum checks quorum via external witness.
func (qm *QuorumManager) checkExternalWitnessQuorum(now time.Time) QuorumStatus {
	// This would connect to etcd/Consul to check for lease ownership.
	// Placeholder implementation.
	return QuorumStatus{
		QuorumType: QuorumTypeExternalWitness,
		LastCheck:  now,
		HasQuorum:  true, // Placeholder.
	}
}

// monitorLoop continuously monitors quorum status.
func (qm *QuorumManager) monitorLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-qm.ctx.Done():
			return
		case <-ticker.C:
			qm.checkQuorum()
		}
	}
}

// ShouldAcceptWrites returns whether this instance should accept writes.
// Returns false if fencing is enabled and quorum is lost beyond grace period.
func (qm *QuorumManager) ShouldAcceptWrites() bool {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	if !qm.config.FencingEnabled {
		return true
	}

	if qm.status.HasQuorum {
		return true
	}

	if qm.status.QuorumLostSince == nil {
		return true
	}

	// Check if we're within grace period.
	gracePeriodEnd := qm.status.QuorumLostSince.Add(qm.config.GracePeriod)
	return time.Now().Before(gracePeriodEnd)
}

// FencingStatus returns the current fencing state.
type FencingStatus struct {
	IsFenced       bool
	Reason         string
	QuorumLostAt   *time.Time
	GracePeriodEnd *time.Time
}

// GetFencingStatus returns the current fencing status.
func (qm *QuorumManager) GetFencingStatus() FencingStatus {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	status := FencingStatus{
		IsFenced: false,
	}

	if !qm.config.FencingEnabled {
		return status
	}

	if qm.status.HasQuorum {
		return status
	}

	if qm.status.QuorumLostSince == nil {
		return status
	}

	gracePeriodEnd := qm.status.QuorumLostSince.Add(qm.config.GracePeriod)
	status.QuorumLostAt = qm.status.QuorumLostSince
	status.GracePeriodEnd = &gracePeriodEnd

	if time.Now().After(gracePeriodEnd) {
		status.IsFenced = true
		status.Reason = fmt.Sprintf("quorum lost at %v, grace period expired", qm.status.QuorumLostSince)
	}

	return status
}
