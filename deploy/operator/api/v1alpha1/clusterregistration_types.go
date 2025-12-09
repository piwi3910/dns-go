/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterRegistrationSpec defines a remote Kubernetes cluster for DNS deployment
type ClusterRegistrationSpec struct {
	// DisplayName is a human-readable name for the cluster
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Region identifies the geographic region of the cluster
	// +optional
	Region string `json:"region,omitempty"`

	// Zone identifies the availability zone within a region
	// +optional
	Zone string `json:"zone,omitempty"`

	// KubeconfigSecret references a Secret containing the kubeconfig for this cluster
	// The secret must have a "kubeconfig" key with the kubeconfig YAML
	KubeconfigSecret SecretReference `json:"kubeconfigSecret"`

	// Labels are additional labels to apply to resources in this cluster
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Taints prevent DNS workloads from being scheduled unless tolerated
	// +optional
	Taints []ClusterTaint `json:"taints,omitempty"`

	// Capacity defines resource limits for this cluster
	// +optional
	Capacity ClusterCapacity `json:"capacity,omitempty"`
}

// SecretReference contains information to reference a Secret
type SecretReference struct {
	// Name is the name of the Secret
	Name string `json:"name"`

	// Namespace is the namespace of the Secret
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key is the key in the Secret data (default: "kubeconfig")
	// +optional
	Key string `json:"key,omitempty"`
}

// ClusterTaint prevents scheduling unless tolerated
type ClusterTaint struct {
	// Key is the taint key
	Key string `json:"key"`

	// Value is the taint value
	// +optional
	Value string `json:"value,omitempty"`

	// Effect is the taint effect (NoSchedule, PreferNoSchedule, NoExecute)
	Effect string `json:"effect"`
}

// ClusterCapacity defines resource capacity for a cluster
type ClusterCapacity struct {
	// MaxWorkers is the maximum number of DNS workers this cluster can run
	// +optional
	MaxWorkers *int32 `json:"maxWorkers,omitempty"`

	// MaxQPS is the maximum queries per second this cluster should handle
	// +optional
	MaxQPS *int64 `json:"maxQPS,omitempty"`
}

// ClusterRegistrationStatus defines the observed state of ClusterRegistration
type ClusterRegistrationStatus struct {
	// Phase represents the current phase of the cluster registration
	// +optional
	Phase ClusterPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastProbeTime is the last time the cluster was probed for connectivity
	// +optional
	LastProbeTime *metav1.Time `json:"lastProbeTime,omitempty"`

	// KubernetesVersion is the version of Kubernetes running in the cluster
	// +optional
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`

	// WorkerCount is the current number of DNS workers in this cluster
	// +optional
	WorkerCount int32 `json:"workerCount,omitempty"`

	// HealthyWorkers is the number of healthy DNS workers
	// +optional
	HealthyWorkers int32 `json:"healthyWorkers,omitempty"`

	// CurrentQPS is the current queries per second handled by this cluster
	// +optional
	CurrentQPS int64 `json:"currentQPS,omitempty"`

	// Message provides additional information about the current status
	// +optional
	Message string `json:"message,omitempty"`
}

// ClusterPhase represents the lifecycle phase of a cluster registration
// +kubebuilder:validation:Enum=Pending;Connecting;Ready;Degraded;Offline;Error
type ClusterPhase string

const (
	// ClusterPhasePending means the cluster registration is being processed
	ClusterPhasePending ClusterPhase = "Pending"

	// ClusterPhaseConnecting means we are attempting to connect to the cluster
	ClusterPhaseConnecting ClusterPhase = "Connecting"

	// ClusterPhaseReady means the cluster is connected and ready to receive workloads
	ClusterPhaseReady ClusterPhase = "Ready"

	// ClusterPhaseDegraded means the cluster is partially available
	ClusterPhaseDegraded ClusterPhase = "Degraded"

	// ClusterPhaseOffline means we cannot connect to the cluster
	ClusterPhaseOffline ClusterPhase = "Offline"

	// ClusterPhaseError means there was an error with the cluster registration
	ClusterPhaseError ClusterPhase = "Error"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster,shortName=cr
//+kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=`.spec.displayName`
//+kubebuilder:printcolumn:name="Region",type=string,JSONPath=`.spec.region`
//+kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
//+kubebuilder:printcolumn:name="Workers",type=integer,JSONPath=`.status.workerCount`
//+kubebuilder:printcolumn:name="Healthy",type=integer,JSONPath=`.status.healthyWorkers`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterRegistration represents a remote Kubernetes cluster where DNS workers can be deployed
type ClusterRegistration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterRegistrationSpec   `json:"spec,omitempty"`
	Status ClusterRegistrationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterRegistrationList contains a list of ClusterRegistration
type ClusterRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterRegistration `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterRegistration{}, &ClusterRegistrationList{})
}
