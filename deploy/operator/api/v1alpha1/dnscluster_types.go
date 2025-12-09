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
