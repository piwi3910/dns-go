// Package v1alpha1 contains API Schema definitions for the dns v1alpha1 API group
package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DNSClusterSpec defines the desired state of DNSCluster
type DNSClusterSpec struct {
	// ControlPlane defines the control plane configuration
	ControlPlane ControlPlaneSpec `json:"controlPlane,omitempty"`

	// Workers defines the worker configuration
	Workers WorkerSpec `json:"workers,omitempty"`

	// Image defines the container image to use
	Image ImageSpec `json:"image,omitempty"`

	// Zones defines the DNS zones to manage
	Zones []ZoneSpec `json:"zones,omitempty"`

	// Upstreams defines upstream DNS servers
	Upstreams []string `json:"upstreams,omitempty"`

	// MultiCluster defines multi-cluster deployment settings
	// +optional
	MultiCluster *MultiClusterSpec `json:"multiCluster,omitempty"`

	// HighAvailability defines HA settings for the control plane
	// +optional
	HighAvailability *HighAvailabilitySpec `json:"highAvailability,omitempty"`
}

// MultiClusterSpec defines multi-cluster deployment configuration
type MultiClusterSpec struct {
	// Enabled enables multi-cluster deployment mode
	// When enabled, workers can be distributed across registered clusters
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// ControlPlaneCluster specifies where to run the control plane
	// If empty, runs in the local (management) cluster
	// +optional
	ControlPlaneCluster string `json:"controlPlaneCluster,omitempty"`

	// WorkerPlacements defines where to place workers
	// If empty and multi-cluster is enabled, workers spread across all ready clusters
	// +optional
	WorkerPlacements []WorkerPlacement `json:"workerPlacements,omitempty"`

	// GlobalDistribution defines how to distribute workers globally
	// +optional
	GlobalDistribution *GlobalDistributionSpec `json:"globalDistribution,omitempty"`
}

// WorkerPlacement defines worker placement in a specific cluster
type WorkerPlacement struct {
	// ClusterRef references a ClusterRegistration by name
	ClusterRef string `json:"clusterRef"`

	// Replicas is the number of workers in this cluster
	// If omitted, calculated from weight or distributed evenly
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// Weight for proportional distribution (0-100)
	// Higher weight = more workers allocated to this cluster
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Weight *int32 `json:"weight,omitempty"`

	// MinReplicas is the minimum workers in this cluster
	// +optional
	MinReplicas *int32 `json:"minReplicas,omitempty"`

	// MaxReplicas is the maximum workers in this cluster
	// +optional
	MaxReplicas *int32 `json:"maxReplicas,omitempty"`

	// Tolerations for cluster taints
	// +optional
	Tolerations []ClusterToleration `json:"tolerations,omitempty"`
}

// ClusterToleration allows scheduling on clusters with matching taints
type ClusterToleration struct {
	// Key is the taint key
	Key string `json:"key"`

	// Operator is the toleration operator (Exists, Equal)
	// +kubebuilder:default=Equal
	Operator string `json:"operator,omitempty"`

	// Value is the taint value to match
	// +optional
	Value string `json:"value,omitempty"`

	// Effect is the taint effect to tolerate
	// +optional
	Effect string `json:"effect,omitempty"`
}

// GlobalDistributionSpec defines global worker distribution strategy
type GlobalDistributionSpec struct {
	// Strategy is the distribution strategy
	// - Balanced: Equal workers per cluster
	// - Weighted: Distribute by cluster weight
	// - Geographic: Optimize for geographic coverage
	// - FollowLoad: Distribute based on current load
	// +kubebuilder:validation:Enum=Balanced;Weighted;Geographic;FollowLoad
	// +kubebuilder:default=Balanced
	Strategy string `json:"strategy,omitempty"`

	// RegionAffinity prefers clusters in specific regions
	// +optional
	RegionAffinity []string `json:"regionAffinity,omitempty"`

	// AntiAffinity spreads workers across different regions/zones
	// +optional
	AntiAffinity *AntiAffinitySpec `json:"antiAffinity,omitempty"`

	// FailoverPolicy defines behavior when a cluster fails
	// +optional
	FailoverPolicy *FailoverPolicySpec `json:"failoverPolicy,omitempty"`
}

// AntiAffinitySpec defines anti-affinity rules for spreading
type AntiAffinitySpec struct {
	// TopologyKey is the key for spreading (region, zone)
	// +kubebuilder:validation:Enum=region;zone
	// +kubebuilder:default=zone
	TopologyKey string `json:"topologyKey,omitempty"`

	// MaxSkew is the maximum difference in worker count between topologies
	// +kubebuilder:default=1
	MaxSkew int32 `json:"maxSkew,omitempty"`
}

// FailoverPolicySpec defines cluster failover behavior
type FailoverPolicySpec struct {
	// Enabled enables automatic failover
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// FailoverThreshold is the time a cluster must be offline before failover (e.g., "5m")
	// +kubebuilder:default="5m"
	FailoverThreshold string `json:"failoverThreshold,omitempty"`

	// RebalanceOnRecovery redistributes workers when a cluster recovers
	// +kubebuilder:default=true
	RebalanceOnRecovery bool `json:"rebalanceOnRecovery,omitempty"`
}

// HighAvailabilitySpec defines HA configuration for the control plane
type HighAvailabilitySpec struct {
	// Enabled enables HA mode for the control plane
	// +kubebuilder:default=false
	Enabled bool `json:"enabled,omitempty"`

	// Mode defines the HA strategy
	// - ActivePassive: One active leader, others on standby
	// - ActiveActive: Multiple active instances with load balancing (read operations)
	// +kubebuilder:validation:Enum=ActivePassive;ActiveActive
	// +kubebuilder:default=ActivePassive
	Mode string `json:"mode,omitempty"`

	// LeaderElection configures leader election behavior
	// +optional
	LeaderElection *LeaderElectionSpec `json:"leaderElection,omitempty"`

	// Quorum defines quorum settings for split-brain prevention
	// +optional
	Quorum *QuorumSpec `json:"quorum,omitempty"`

	// ControlPlanePlacements defines where to place control plane instances
	// Required when HA is enabled with multi-cluster
	// +optional
	ControlPlanePlacements []ControlPlanePlacement `json:"controlPlanePlacements,omitempty"`

	// SyncReplication enables synchronous replication between control planes
	// +kubebuilder:default=true
	SyncReplication bool `json:"syncReplication,omitempty"`
}

// LeaderElectionSpec configures leader election
type LeaderElectionSpec struct {
	// LeaseDuration is the duration a leader holds the lease (e.g., "15s")
	// +kubebuilder:default="15s"
	LeaseDuration string `json:"leaseDuration,omitempty"`

	// RenewDeadline is the duration before lease renewal deadline (e.g., "10s")
	// +kubebuilder:default="10s"
	RenewDeadline string `json:"renewDeadline,omitempty"`

	// RetryPeriod is the duration between retry attempts (e.g., "2s")
	// +kubebuilder:default="2s"
	RetryPeriod string `json:"retryPeriod,omitempty"`

	// LeaderElectionNamespace is where to store the lease
	// +optional
	LeaderElectionNamespace string `json:"leaderElectionNamespace,omitempty"`
}

// QuorumSpec defines quorum configuration for split-brain prevention
type QuorumSpec struct {
	// Type defines how quorum is calculated
	// - Majority: Requires >50% of voters
	// - WorkerWitness: Uses workers as witness nodes for 2-site deployments
	// - ExternalWitness: Uses external witness service
	// +kubebuilder:validation:Enum=Majority;WorkerWitness;ExternalWitness
	// +kubebuilder:default=WorkerWitness
	Type string `json:"type,omitempty"`

	// MinimumQuorum is the minimum number of voters required for quorum
	// For WorkerWitness, this is the minimum workers needed to confirm leadership
	// +kubebuilder:default=1
	MinimumQuorum int32 `json:"minimumQuorum,omitempty"`

	// WorkerWitnessConfig configures worker-based quorum (for 2-site deployments)
	// +optional
	WorkerWitness *WorkerWitnessSpec `json:"workerWitness,omitempty"`

	// ExternalWitnessConfig configures external witness service
	// +optional
	ExternalWitness *ExternalWitnessSpec `json:"externalWitness,omitempty"`

	// FencingEnabled enables automatic fencing of split-brain nodes
	// When a control plane loses quorum, it stops serving writes
	// +kubebuilder:default=true
	FencingEnabled bool `json:"fencingEnabled,omitempty"`

	// GracePeriod is how long to wait before fencing after losing quorum
	// +kubebuilder:default="30s"
	GracePeriod string `json:"gracePeriod,omitempty"`
}

// WorkerWitnessSpec configures worker-based split-brain prevention
// Workers vote for the control plane they can reach, providing quorum in 2-site scenarios
type WorkerWitnessSpec struct {
	// MinClustersRequired is the minimum clusters with reachable workers for quorum
	// For 2-site: set to 2 to require workers from both sites
	// +kubebuilder:default=1
	MinClustersRequired int32 `json:"minClustersRequired,omitempty"`

	// MinWorkersPerCluster is the minimum workers per cluster for that cluster's vote to count
	// +kubebuilder:default=1
	MinWorkersPerCluster int32 `json:"minWorkersPerCluster,omitempty"`

	// VoteWeight defines how worker votes are weighted
	// - Equal: Each cluster's workers count as one vote
	// - Proportional: More workers = more weight (up to 3x)
	// +kubebuilder:validation:Enum=Equal;Proportional
	// +kubebuilder:default=Equal
	VoteWeight string `json:"voteWeight,omitempty"`

	// HeartbeatInterval is how often workers send heartbeats to control plane
	// +kubebuilder:default="5s"
	HeartbeatInterval string `json:"heartbeatInterval,omitempty"`

	// HeartbeatTimeout is how long before a worker is considered unreachable
	// +kubebuilder:default="15s"
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`
}

// ExternalWitnessSpec configures an external witness service for quorum
type ExternalWitnessSpec struct {
	// Endpoint is the URL of the external witness service
	Endpoint string `json:"endpoint"`

	// SecretRef references a secret containing auth credentials
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// Type is the type of external witness
	// - Etcd: Use external etcd cluster
	// - Consul: Use Consul for distributed locking
	// - Custom: Custom witness implementation
	// +kubebuilder:validation:Enum=Etcd;Consul;Custom
	// +kubebuilder:default=Etcd
	Type string `json:"type,omitempty"`
}

// ControlPlanePlacement defines where to place a control plane instance
type ControlPlanePlacement struct {
	// ClusterRef references a ClusterRegistration by name
	ClusterRef string `json:"clusterRef"`

	// Priority determines failover order (lower = higher priority)
	// +kubebuilder:default=100
	Priority int32 `json:"priority,omitempty"`

	// PreferredLeader marks this placement as the preferred leader location
	// +kubebuilder:default=false
	PreferredLeader bool `json:"preferredLeader,omitempty"`

	// NodeSelector for control plane pods in this cluster
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for control plane pods in this cluster
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// ControlPlaneSpec defines the control plane settings
type ControlPlaneSpec struct {
	// Replicas is the number of control plane replicas (default: 1)
	// +kubebuilder:default=1
	Replicas int32 `json:"replicas,omitempty"`

	// Resources defines resource requests/limits
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// GRPCPort is the port for gRPC communication (default: 9090)
	// +kubebuilder:default=9090
	GRPCPort int32 `json:"grpcPort,omitempty"`

	// HTTPPort is the port for HTTP API (default: 8080)
	// +kubebuilder:default=8080
	HTTPPort int32 `json:"httpPort,omitempty"`

	// NodeSelector for control plane pods
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for control plane pods
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// WorkerSpec defines the worker settings
type WorkerSpec struct {
	// Replicas is the number of worker replicas (default: 3)
	// +kubebuilder:default=3
	Replicas int32 `json:"replicas,omitempty"`

	// MinReplicas for HPA (default: 3)
	// +kubebuilder:default=3
	MinReplicas int32 `json:"minReplicas,omitempty"`

	// MaxReplicas for HPA (default: 20)
	// +kubebuilder:default=20
	MaxReplicas int32 `json:"maxReplicas,omitempty"`

	// Resources defines resource requests/limits
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// DNSPort is the port for DNS (default: 53)
	// +kubebuilder:default=53
	DNSPort int32 `json:"dnsPort,omitempty"`

	// ServiceType is the type of service (default: LoadBalancer)
	// +kubebuilder:default=LoadBalancer
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`

	// NodeSelector for worker pods
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for worker pods
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Autoscaling configuration
	Autoscaling AutoscalingSpec `json:"autoscaling,omitempty"`
}

// AutoscalingSpec defines autoscaling settings
type AutoscalingSpec struct {
	// Enabled enables HPA (default: true)
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// TargetCPUUtilization is the target CPU utilization (default: 70)
	// +kubebuilder:default=70
	TargetCPUUtilization int32 `json:"targetCPUUtilization,omitempty"`

	// TargetMemoryUtilization is the target memory utilization (default: 80)
	// +kubebuilder:default=80
	TargetMemoryUtilization int32 `json:"targetMemoryUtilization,omitempty"`
}

// ImageSpec defines the container image
type ImageSpec struct {
	// Repository is the image repository
	// +kubebuilder:default="ghcr.io/piwi3910/dns-go"
	Repository string `json:"repository,omitempty"`

	// Tag is the image tag
	// +kubebuilder:default="latest"
	Tag string `json:"tag,omitempty"`

	// PullPolicy is the image pull policy
	// +kubebuilder:default=IfNotPresent
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// PullSecrets are the image pull secrets
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`
}

// ZoneSpec defines a DNS zone
type ZoneSpec struct {
	// Name is the zone name (e.g., "example.com")
	Name string `json:"name"`

	// Type is the zone type (primary or secondary)
	// +kubebuilder:default=primary
	// +kubebuilder:validation:Enum=primary;secondary
	Type string `json:"type,omitempty"`

	// Records are the DNS records in the zone
	Records []RecordSpec `json:"records,omitempty"`

	// PrimaryNS is the primary nameserver for secondary zones
	PrimaryNS string `json:"primaryNS,omitempty"`
}

// RecordSpec defines a DNS record
type RecordSpec struct {
	// Name is the record name (relative to zone)
	Name string `json:"name"`

	// Type is the record type (A, AAAA, CNAME, MX, TXT, etc.)
	Type string `json:"type"`

	// TTL is the record TTL in seconds
	// +kubebuilder:default=300
	TTL uint32 `json:"ttl,omitempty"`

	// Value is the record value
	Value string `json:"value"`

	// Priority for MX/SRV records
	Priority *uint16 `json:"priority,omitempty"`
}

// DNSClusterStatus defines the observed state of DNSCluster
type DNSClusterStatus struct {
	// Phase is the current phase of the cluster
	// +kubebuilder:validation:Enum=Pending;Creating;Running;Updating;Failed
	Phase string `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ControlPlaneReady indicates if the control plane is ready
	ControlPlaneReady bool `json:"controlPlaneReady,omitempty"`

	// WorkersReady is the number of ready workers
	WorkersReady int32 `json:"workersReady,omitempty"`

	// WorkersDesired is the desired number of workers
	WorkersDesired int32 `json:"workersDesired,omitempty"`

	// ExternalDNS is the external DNS endpoint (LoadBalancer IP/hostname)
	ExternalDNS string `json:"externalDNS,omitempty"`

	// ZonesLoaded is the number of zones loaded
	ZonesLoaded int32 `json:"zonesLoaded,omitempty"`

	// LastUpdated is the last time the status was updated
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`

	// ClusterStatuses shows per-cluster worker status (multi-cluster mode)
	// +optional
	ClusterStatuses []ClusterWorkerStatus `json:"clusterStatuses,omitempty"`

	// TotalClusters is the total number of clusters with workers
	// +optional
	TotalClusters int32 `json:"totalClusters,omitempty"`

	// HealthyClusters is the number of healthy clusters
	// +optional
	HealthyClusters int32 `json:"healthyClusters,omitempty"`

	// HA status fields (only populated when HA is enabled)

	// HAStatus shows the current HA state
	// +optional
	HAStatus *HAStatus `json:"haStatus,omitempty"`
}

// HAStatus shows the current HA state of the control plane
type HAStatus struct {
	// Mode is the current HA mode
	Mode string `json:"mode,omitempty"`

	// CurrentLeader is the current leader control plane instance
	// +optional
	CurrentLeader string `json:"currentLeader,omitempty"`

	// LeaderCluster is the cluster where the leader is running
	// +optional
	LeaderCluster string `json:"leaderCluster,omitempty"`

	// LeaderSince is when the current leader became leader
	// +optional
	LeaderSince *metav1.Time `json:"leaderSince,omitempty"`

	// QuorumStatus shows the current quorum state
	// +optional
	QuorumStatus *QuorumStatus `json:"quorumStatus,omitempty"`

	// ControlPlaneInstances shows status of each control plane instance
	// +optional
	ControlPlaneInstances []ControlPlaneInstanceStatus `json:"controlPlaneInstances,omitempty"`

	// LastFailover is the timestamp of the last failover event
	// +optional
	LastFailover *metav1.Time `json:"lastFailover,omitempty"`

	// FailoverCount is the total number of failovers since creation
	FailoverCount int32 `json:"failoverCount,omitempty"`
}

// QuorumStatus shows the current quorum state
type QuorumStatus struct {
	// HasQuorum indicates whether quorum is currently met
	HasQuorum bool `json:"hasQuorum"`

	// QuorumType is the type of quorum being used
	QuorumType string `json:"quorumType,omitempty"`

	// VotersTotal is the total number of voters
	VotersTotal int32 `json:"votersTotal,omitempty"`

	// VotersReachable is the number of reachable voters
	VotersReachable int32 `json:"votersReachable,omitempty"`

	// WorkerWitnessStatus shows worker witness voting status (if using WorkerWitness quorum)
	// +optional
	WorkerWitnessStatus *WorkerWitnessStatus `json:"workerWitnessStatus,omitempty"`

	// LastQuorumCheck is the last time quorum was checked
	// +optional
	LastQuorumCheck *metav1.Time `json:"lastQuorumCheck,omitempty"`

	// QuorumLostSince is when quorum was lost (nil if quorum is held)
	// +optional
	QuorumLostSince *metav1.Time `json:"quorumLostSince,omitempty"`
}

// WorkerWitnessStatus shows worker-based quorum voting status
type WorkerWitnessStatus struct {
	// ClustersVoting is the number of clusters with workers voting for this control plane
	ClustersVoting int32 `json:"clustersVoting"`

	// ClustersRequired is the minimum clusters required for quorum
	ClustersRequired int32 `json:"clustersRequired"`

	// TotalWorkersVoting is the total workers voting for this control plane
	TotalWorkersVoting int32 `json:"totalWorkersVoting"`

	// ClusterVotes shows per-cluster voting status
	// +optional
	ClusterVotes []ClusterVoteStatus `json:"clusterVotes,omitempty"`
}

// ClusterVoteStatus shows voting status from a specific cluster
type ClusterVoteStatus struct {
	// ClusterRef is the ClusterRegistration name
	ClusterRef string `json:"clusterRef"`

	// WorkersVoting is the number of workers voting from this cluster
	WorkersVoting int32 `json:"workersVoting"`

	// WorkersTotal is the total workers in this cluster
	WorkersTotal int32 `json:"workersTotal"`

	// VoteValid indicates if this cluster's vote counts (meets minimum workers)
	VoteValid bool `json:"voteValid"`

	// LastHeartbeat is the last time we received heartbeats from this cluster's workers
	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`
}

// ControlPlaneInstanceStatus shows status of a control plane instance
type ControlPlaneInstanceStatus struct {
	// Name is the instance name/ID
	Name string `json:"name"`

	// ClusterRef is the cluster where this instance runs
	ClusterRef string `json:"clusterRef"`

	// Role is the current role (Leader, Follower, Candidate)
	// +kubebuilder:validation:Enum=Leader;Follower;Candidate;Unknown
	Role string `json:"role"`

	// Ready indicates if this instance is ready
	Ready bool `json:"ready"`

	// LastHeartbeat is the last time we heard from this instance
	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`

	// ReplicationLag is the replication lag behind the leader (if follower)
	// +optional
	ReplicationLag string `json:"replicationLag,omitempty"`

	// Endpoint is the gRPC endpoint for this instance
	// +optional
	Endpoint string `json:"endpoint,omitempty"`
}

// ClusterWorkerStatus shows worker status in a specific cluster
type ClusterWorkerStatus struct {
	// ClusterRef is the ClusterRegistration name
	ClusterRef string `json:"clusterRef"`

	// Region is the cluster region
	// +optional
	Region string `json:"region,omitempty"`

	// Zone is the cluster zone
	// +optional
	Zone string `json:"zone,omitempty"`

	// WorkersReady is the number of ready workers in this cluster
	WorkersReady int32 `json:"workersReady,omitempty"`

	// WorkersDesired is the desired number of workers in this cluster
	WorkersDesired int32 `json:"workersDesired,omitempty"`

	// Phase is the cluster's operational phase
	Phase string `json:"phase,omitempty"`

	// ExternalDNS is the DNS endpoint for this cluster
	// +optional
	ExternalDNS string `json:"externalDNS,omitempty"`

	// LastHeartbeat is the last time we got status from this cluster
	// +optional
	LastHeartbeat *metav1.Time `json:"lastHeartbeat,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Control",type="boolean",JSONPath=".status.controlPlaneReady"
// +kubebuilder:printcolumn:name="Workers",type="string",JSONPath=".status.workersReady"
// +kubebuilder:printcolumn:name="DNS",type="string",JSONPath=".status.externalDNS"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// DNSCluster is the Schema for the dnsclusters API
type DNSCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSClusterSpec   `json:"spec,omitempty"`
	Status DNSClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DNSClusterList contains a list of DNSCluster
type DNSClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DNSCluster{}, &DNSClusterList{})
}
