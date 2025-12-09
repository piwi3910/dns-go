// Package config provides configuration management for the DNS server.
package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DNSConfigSpec defines the desired state of DNSConfig CRD.
type DNSConfigSpec struct {
	// Server configuration
	Server ServerConfigSpec `json:"server,omitempty"`

	// Cache configuration
	Cache CacheConfigSpec `json:"cache,omitempty"`

	// Resolver configuration
	Resolver ResolverConfigSpec `json:"resolver,omitempty"`

	// Logging configuration
	Logging LoggingConfigSpec `json:"logging,omitempty"`

	// API configuration
	API APIConfigSpec `json:"api,omitempty"`
}

// ServerConfigSpec defines server configuration in CRD.
type ServerConfigSpec struct {
	ListenAddress           string `json:"listenAddress,omitempty"`
	NumWorkers              int    `json:"numWorkers,omitempty"`
	EnableTCP               bool   `json:"enableTcp,omitempty"`
	PprofAddress            string `json:"pprofAddress,omitempty"`
	GracefulShutdownTimeout int    `json:"gracefulShutdownTimeoutSeconds,omitempty"`
	StatsReportInterval     int    `json:"statsReportIntervalSeconds,omitempty"`
}

// CacheConfigSpec defines cache configuration in CRD.
type CacheConfigSpec struct {
	MessageCache MessageCacheSpec `json:"messageCache,omitempty"`
	RRsetCache   RRsetCacheSpec   `json:"rrsetCache,omitempty"`
	Prefetch     PrefetchSpec     `json:"prefetch,omitempty"`
	MinTTLSecs   int              `json:"minTtlSeconds,omitempty"`
	MaxTTLSecs   int              `json:"maxTtlSeconds,omitempty"`
	NegTTLSecs   int              `json:"negativeTtlSeconds,omitempty"`
}

// MessageCacheSpec defines message cache configuration.
type MessageCacheSpec struct {
	MaxSizeMB int `json:"maxSizeMb,omitempty"`
	NumShards int `json:"numShards,omitempty"`
}

// RRsetCacheSpec defines RRset cache configuration.
type RRsetCacheSpec struct {
	MaxSizeMB int `json:"maxSizeMb,omitempty"`
	NumShards int `json:"numShards,omitempty"`
}

// PrefetchSpec defines prefetch configuration.
type PrefetchSpec struct {
	Enabled             bool    `json:"enabled,omitempty"`
	ThresholdHits       int     `json:"thresholdHits,omitempty"`
	ThresholdTTLPercent float64 `json:"thresholdTtlPercent,omitempty"`
}

// ResolverConfigSpec defines resolver configuration in CRD.
type ResolverConfigSpec struct {
	Mode              string             `json:"mode,omitempty"`
	Upstreams         []string           `json:"upstreams,omitempty"`
	RootHintsFile     string             `json:"rootHintsFile,omitempty"`
	MaxRecursionDepth int                `json:"maxRecursionDepth,omitempty"`
	QueryTimeoutSecs  int                `json:"queryTimeoutSeconds,omitempty"`
	EnableCoalescing  bool               `json:"enableCoalescing,omitempty"`
	Parallel          ParallelConfigSpec `json:"parallel,omitempty"`
}

// ParallelConfigSpec defines parallel resolver configuration.
type ParallelConfigSpec struct {
	NumParallel         int   `json:"numParallel,omitempty"`
	FallbackToRecursive bool  `json:"fallbackToRecursive,omitempty"`
	SuccessRcodes       []int `json:"successRcodes,omitempty"`
}

// LoggingConfigSpec defines logging configuration in CRD.
type LoggingConfigSpec struct {
	Level          string `json:"level,omitempty"`
	Format         string `json:"format,omitempty"`
	EnableQueryLog bool   `json:"enableQueryLog,omitempty"`
}

// APIConfigSpec defines API configuration in CRD.
type APIConfigSpec struct {
	Enabled       bool     `json:"enabled,omitempty"`
	ListenAddress string   `json:"listenAddress,omitempty"`
	CORSOrigins   []string `json:"corsOrigins,omitempty"`
}

// DNSConfigStatus defines the observed state of DNSConfig.
type DNSConfigStatus struct {
	// LastApplied is the timestamp of when config was last applied
	LastApplied metav1.Time `json:"lastApplied,omitempty"`

	// Applied indicates if the config has been applied to all workers
	Applied bool `json:"applied,omitempty"`

	// Message contains status message
	Message string `json:"message,omitempty"`

	// WorkersReady is the number of workers that have applied the config
	WorkersReady int `json:"workersReady,omitempty"`

	// WorkersTotal is the total number of workers
	WorkersTotal int `json:"workersTotal,omitempty"`
}

// DNSConfig is the Schema for the dnsconfigs API.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dnscfg
type DNSConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSConfigSpec   `json:"spec,omitempty"`
	Status DNSConfigStatus `json:"status,omitempty"`
}

// DNSConfigList contains a list of DNSConfig.
// +kubebuilder:object:root=true
type DNSConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSConfig `json:"items"`
}

// DeepCopyObject implements runtime.Object interface.
func (in *DNSConfig) DeepCopyObject() interface{} {
	if in == nil {
		return nil
	}
	out := new(DNSConfig)
	*out = *in
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
	return out
}

// DeepCopyObject implements runtime.Object interface.
func (in *DNSConfigList) DeepCopyObject() interface{} {
	if in == nil {
		return nil
	}
	out := new(DNSConfigList)
	*out = *in
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]DNSConfig, len(in.Items))
		for i := range in.Items {
			out.Items[i] = in.Items[i]
		}
	}
	return out
}
