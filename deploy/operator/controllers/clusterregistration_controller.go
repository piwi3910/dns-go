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

package controllers

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/piwi3910/dns-go/deploy/operator/api/v1alpha1"
)

const (
	clusterFinalizerName = "dns.dns-go.io/cluster-finalizer"
	probeInterval        = 30 * time.Second
)

// ClusterRegistrationReconciler reconciles a ClusterRegistration object
type ClusterRegistrationReconciler struct {
	client.Client
	Scheme         *runtime.Scheme
	ClusterManager *ClusterClientManager
}

//+kubebuilder:rbac:groups=dns.dns-go.io,resources=clusterregistrations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dns.dns-go.io,resources=clusterregistrations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dns.dns-go.io,resources=clusterregistrations/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles ClusterRegistration reconciliation
func (r *ClusterRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the ClusterRegistration
	cluster := &dnsv1alpha1.ClusterRegistration{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		if errors.IsNotFound(err) {
			// Cluster was deleted, clean up the client
			r.ClusterManager.RemoveClient(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !cluster.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(cluster, clusterFinalizerName) {
			// Clean up the client
			r.ClusterManager.RemoveClient(cluster.Name)

			// Remove finalizer
			controllerutil.RemoveFinalizer(cluster, clusterFinalizerName)
			if err := r.Update(ctx, cluster); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(cluster, clusterFinalizerName) {
		controllerutil.AddFinalizer(cluster, clusterFinalizerName)
		if err := r.Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Get kubeconfig from secret
	kubeconfig, err := r.getKubeconfig(ctx, cluster)
	if err != nil {
		logger.Error(err, "Failed to get kubeconfig")
		return r.updateStatus(ctx, cluster, dnsv1alpha1.ClusterPhaseError, err.Error())
	}

	// Update status to connecting
	if cluster.Status.Phase != dnsv1alpha1.ClusterPhaseReady {
		cluster.Status.Phase = dnsv1alpha1.ClusterPhaseConnecting
		cluster.Status.Message = "Connecting to cluster..."
		if err := r.Status().Update(ctx, cluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Create or update the client
	remoteClient, err := r.ClusterManager.GetOrCreateClient(cluster.Name, kubeconfig)
	if err != nil {
		logger.Error(err, "Failed to create client for cluster")
		return r.updateStatus(ctx, cluster, dnsv1alpha1.ClusterPhaseError, err.Error())
	}

	// Probe the cluster
	version, err := r.probeCluster(ctx, remoteClient)
	if err != nil {
		logger.Error(err, "Failed to probe cluster")
		return r.updateStatus(ctx, cluster, dnsv1alpha1.ClusterPhaseOffline, err.Error())
	}

	// Update status to ready
	now := metav1.Now()
	cluster.Status.Phase = dnsv1alpha1.ClusterPhaseReady
	cluster.Status.KubernetesVersion = version
	cluster.Status.LastProbeTime = &now
	cluster.Status.Message = "Cluster is healthy and ready"

	// Update worker counts if we have any DNS workers
	workerCount, healthyWorkers, err := r.countWorkers(ctx, remoteClient, cluster.Name)
	if err != nil {
		logger.Error(err, "Failed to count workers")
	} else {
		cluster.Status.WorkerCount = workerCount
		cluster.Status.HealthyWorkers = healthyWorkers
	}

	// Set Ready condition
	setCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "ClusterReady",
		Message:            "Cluster is connected and healthy",
		LastTransitionTime: now,
	})

	if err := r.Status().Update(ctx, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue to periodically probe the cluster
	return ctrl.Result{RequeueAfter: probeInterval}, nil
}

// getKubeconfig retrieves the kubeconfig from the referenced secret
func (r *ClusterRegistrationReconciler) getKubeconfig(ctx context.Context, cluster *dnsv1alpha1.ClusterRegistration) ([]byte, error) {
	secretRef := cluster.Spec.KubeconfigSecret

	// Determine namespace
	namespace := secretRef.Namespace
	if namespace == "" {
		namespace = cluster.Namespace
		if namespace == "" {
			namespace = "default"
		}
	}

	// Determine key
	key := secretRef.Key
	if key == "" {
		key = "kubeconfig"
	}

	// Get the secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: namespace,
	}, secret); err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig secret: %w", err)
	}

	kubeconfig, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("kubeconfig key %q not found in secret", key)
	}

	return kubeconfig, nil
}

// probeCluster checks if the cluster is reachable and returns the Kubernetes version
func (r *ClusterRegistrationReconciler) probeCluster(ctx context.Context, remoteClient client.Client) (string, error) {
	// Try to list namespaces as a connectivity check
	namespaces := &corev1.NamespaceList{}
	if err := remoteClient.List(ctx, namespaces, client.Limit(1)); err != nil {
		return "", fmt.Errorf("failed to probe cluster: %w", err)
	}

	// Get server version (we'd need to use discovery client for this)
	// For now, return a placeholder
	return "connected", nil
}

// countWorkers counts DNS workers in the remote cluster
func (r *ClusterRegistrationReconciler) countWorkers(ctx context.Context, remoteClient client.Client, clusterName string) (int32, int32, error) {
	// Look for pods with our DNS worker labels
	pods := &corev1.PodList{}
	if err := remoteClient.List(ctx, pods, client.MatchingLabels{
		"app.kubernetes.io/name":      "dns-go",
		"app.kubernetes.io/component": "worker",
	}); err != nil {
		return 0, 0, err
	}

	var total, healthy int32
	for _, pod := range pods.Items {
		total++
		if pod.Status.Phase == corev1.PodRunning {
			ready := true
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status != corev1.ConditionTrue {
					ready = false
					break
				}
			}
			if ready {
				healthy++
			}
		}
	}

	return total, healthy, nil
}

// updateStatus updates the cluster status with the given phase and message
func (r *ClusterRegistrationReconciler) updateStatus(ctx context.Context, cluster *dnsv1alpha1.ClusterRegistration, phase dnsv1alpha1.ClusterPhase, message string) (ctrl.Result, error) {
	cluster.Status.Phase = phase
	cluster.Status.Message = message

	conditionStatus := metav1.ConditionFalse
	reason := "ClusterNotReady"
	if phase == dnsv1alpha1.ClusterPhaseReady {
		conditionStatus = metav1.ConditionTrue
		reason = "ClusterReady"
	}

	setCondition(&cluster.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, cluster); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue faster for error states
	requeueAfter := probeInterval
	if phase != dnsv1alpha1.ClusterPhaseReady {
		requeueAfter = 10 * time.Second
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// setCondition sets a condition in the conditions slice
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	for i, c := range *conditions {
		if c.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}

// SetupWithManager sets up the controller with the Manager
func (r *ClusterRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.ClusterRegistration{}).
		Complete(r)
}

// ClusterClientManager manages clients for remote clusters
type ClusterClientManager struct {
	clients map[string]client.Client
	scheme  *runtime.Scheme
}

// NewClusterClientManager creates a new cluster client manager
func NewClusterClientManager(scheme *runtime.Scheme) *ClusterClientManager {
	return &ClusterClientManager{
		clients: make(map[string]client.Client),
		scheme:  scheme,
	}
}

// GetOrCreateClient gets or creates a client for a cluster
func (m *ClusterClientManager) GetOrCreateClient(name string, kubeconfig []byte) (client.Client, error) {
	if c, ok := m.clients[name]; ok {
		return c, nil
	}

	// Parse kubeconfig
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	// Create client
	c, err := client.New(config, client.Options{Scheme: m.scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	m.clients[name] = c
	return c, nil
}

// GetClient gets a client for a cluster
func (m *ClusterClientManager) GetClient(name string) (client.Client, bool) {
	c, ok := m.clients[name]
	return c, ok
}

// RemoveClient removes a client for a cluster
func (m *ClusterClientManager) RemoveClient(name string) {
	delete(m.clients, name)
}

// ListClusters returns all registered cluster names
func (m *ClusterClientManager) ListClusters() []string {
	names := make([]string, 0, len(m.clients))
	for name := range m.clients {
		names = append(names, name)
	}
	return names
}
