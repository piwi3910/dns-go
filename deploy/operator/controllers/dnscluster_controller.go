// Package controllers contains the Kubernetes controller implementations
package controllers

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dnsv1alpha1 "github.com/piwi3910/dns-go/deploy/operator/api/v1alpha1"
)

const (
	// FinalizerName is the finalizer for DNSCluster resources
	FinalizerName = "dns.dns-go.io/finalizer"

	// Requeue intervals
	RequeueAfterSuccess = 30 * time.Second
	RequeueAfterError   = 10 * time.Second
)

// DNSClusterReconciler reconciles a DNSCluster object
type DNSClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=dns.dns-go.io,resources=dnsclusters,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=dns.dns-go.io,resources=dnsclusters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=dns.dns-go.io,resources=dnsclusters/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services;configmaps;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles DNSCluster reconciliation
func (r *DNSClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the DNSCluster instance
	dnsCluster := &dnsv1alpha1.DNSCluster{}
	if err := r.Get(ctx, req.NamespacedName, dnsCluster); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("DNSCluster resource not found, likely deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get DNSCluster")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !dnsCluster.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, dnsCluster)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(dnsCluster, FinalizerName) {
		controllerutil.AddFinalizer(dnsCluster, FinalizerName)
		if err := r.Update(ctx, dnsCluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update status to Creating if Pending
	if dnsCluster.Status.Phase == "" || dnsCluster.Status.Phase == "Pending" {
		dnsCluster.Status.Phase = "Creating"
		if err := r.Status().Update(ctx, dnsCluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Reconcile resources
	if err := r.reconcileControlPlane(ctx, dnsCluster); err != nil {
		logger.Error(err, "Failed to reconcile control plane")
		return r.setFailedStatus(ctx, dnsCluster, err)
	}

	if err := r.reconcileWorkers(ctx, dnsCluster); err != nil {
		logger.Error(err, "Failed to reconcile workers")
		return r.setFailedStatus(ctx, dnsCluster, err)
	}

	// Update status
	if err := r.updateStatus(ctx, dnsCluster); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{RequeueAfter: RequeueAfterError}, err
	}

	return ctrl.Result{RequeueAfter: RequeueAfterSuccess}, nil
}

// handleDeletion handles resource cleanup
func (r *DNSClusterReconciler) handleDeletion(ctx context.Context, dnsCluster *dnsv1alpha1.DNSCluster) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(dnsCluster, FinalizerName) {
		logger.Info("Performing cleanup for DNSCluster")

		// Cleanup logic here (if needed beyond owner references)

		// Remove finalizer
		controllerutil.RemoveFinalizer(dnsCluster, FinalizerName)
		if err := r.Update(ctx, dnsCluster); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// reconcileControlPlane ensures the control plane resources exist
func (r *DNSClusterReconciler) reconcileControlPlane(ctx context.Context, dnsCluster *dnsv1alpha1.DNSCluster) error {
	logger := log.FromContext(ctx)

	// Service Account
	sa := r.buildControlServiceAccount(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, sa); err != nil {
		return fmt.Errorf("failed to reconcile control service account: %w", err)
	}

	// ConfigMap
	cm := r.buildControlConfigMap(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, cm); err != nil {
		return fmt.Errorf("failed to reconcile control configmap: %w", err)
	}

	// Deployment
	deploy := r.buildControlDeployment(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, deploy); err != nil {
		return fmt.Errorf("failed to reconcile control deployment: %w", err)
	}

	// Service
	svc := r.buildControlService(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, svc); err != nil {
		return fmt.Errorf("failed to reconcile control service: %w", err)
	}

	logger.Info("Control plane reconciled successfully")
	return nil
}

// reconcileWorkers ensures the worker resources exist
func (r *DNSClusterReconciler) reconcileWorkers(ctx context.Context, dnsCluster *dnsv1alpha1.DNSCluster) error {
	logger := log.FromContext(ctx)

	// Service Account
	sa := r.buildWorkerServiceAccount(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, sa); err != nil {
		return fmt.Errorf("failed to reconcile worker service account: %w", err)
	}

	// Deployment
	deploy := r.buildWorkerDeployment(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, deploy); err != nil {
		return fmt.Errorf("failed to reconcile worker deployment: %w", err)
	}

	// Service
	svc := r.buildWorkerService(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, svc); err != nil {
		return fmt.Errorf("failed to reconcile worker service: %w", err)
	}

	// HPA (if autoscaling enabled)
	if dnsCluster.Spec.Workers.Autoscaling.Enabled {
		hpa := r.buildWorkerHPA(dnsCluster)
		if err := r.createOrUpdate(ctx, dnsCluster, hpa); err != nil {
			return fmt.Errorf("failed to reconcile worker HPA: %w", err)
		}
	}

	// PDB
	pdb := r.buildWorkerPDB(dnsCluster)
	if err := r.createOrUpdate(ctx, dnsCluster, pdb); err != nil {
		return fmt.Errorf("failed to reconcile worker PDB: %w", err)
	}

	logger.Info("Workers reconciled successfully")
	return nil
}

// createOrUpdate creates or updates a resource
func (r *DNSClusterReconciler) createOrUpdate(ctx context.Context, owner *dnsv1alpha1.DNSCluster, obj client.Object) error {
	// Set owner reference
	if err := controllerutil.SetControllerReference(owner, obj, r.Scheme); err != nil {
		return err
	}

	// Try to get existing resource
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}, existing)

	if errors.IsNotFound(err) {
		// Create new resource
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}

	// Update existing resource
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// updateStatus updates the DNSCluster status
func (r *DNSClusterReconciler) updateStatus(ctx context.Context, dnsCluster *dnsv1alpha1.DNSCluster) error {
	// Check control plane deployment
	controlDeploy := &appsv1.Deployment{}
	controlName := fmt.Sprintf("%s-control", dnsCluster.Name)
	err := r.Get(ctx, types.NamespacedName{Name: controlName, Namespace: dnsCluster.Namespace}, controlDeploy)
	if err == nil {
		dnsCluster.Status.ControlPlaneReady = controlDeploy.Status.ReadyReplicas > 0
	}

	// Check worker deployment
	workerDeploy := &appsv1.Deployment{}
	workerName := fmt.Sprintf("%s-worker", dnsCluster.Name)
	err = r.Get(ctx, types.NamespacedName{Name: workerName, Namespace: dnsCluster.Namespace}, workerDeploy)
	if err == nil {
		dnsCluster.Status.WorkersReady = workerDeploy.Status.ReadyReplicas
		dnsCluster.Status.WorkersDesired = *workerDeploy.Spec.Replicas
	}

	// Check worker service for external DNS
	workerSvc := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Name: workerName, Namespace: dnsCluster.Namespace}, workerSvc)
	if err == nil && workerSvc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if len(workerSvc.Status.LoadBalancer.Ingress) > 0 {
			ing := workerSvc.Status.LoadBalancer.Ingress[0]
			if ing.Hostname != "" {
				dnsCluster.Status.ExternalDNS = ing.Hostname
			} else if ing.IP != "" {
				dnsCluster.Status.ExternalDNS = ing.IP
			}
		}
	}

	// Update phase
	if dnsCluster.Status.ControlPlaneReady && dnsCluster.Status.WorkersReady > 0 {
		dnsCluster.Status.Phase = "Running"
		meta.SetStatusCondition(&dnsCluster.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "ClusterReady",
			Message:            "DNS cluster is ready",
			LastTransitionTime: metav1.Now(),
		})
	} else {
		dnsCluster.Status.Phase = "Creating"
		meta.SetStatusCondition(&dnsCluster.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ClusterNotReady",
			Message:            "DNS cluster is not yet ready",
			LastTransitionTime: metav1.Now(),
		})
	}

	dnsCluster.Status.ZonesLoaded = int32(len(dnsCluster.Spec.Zones))
	dnsCluster.Status.LastUpdated = metav1.Now()

	return r.Status().Update(ctx, dnsCluster)
}

// setFailedStatus sets the status to Failed
func (r *DNSClusterReconciler) setFailedStatus(ctx context.Context, dnsCluster *dnsv1alpha1.DNSCluster, err error) (ctrl.Result, error) {
	dnsCluster.Status.Phase = "Failed"
	meta.SetStatusCondition(&dnsCluster.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		Reason:             "ReconcileFailed",
		Message:            err.Error(),
		LastTransitionTime: metav1.Now(),
	})
	_ = r.Status().Update(ctx, dnsCluster)
	return ctrl.Result{RequeueAfter: RequeueAfterError}, err
}

// Helper functions to build resources

func (r *DNSClusterReconciler) buildControlServiceAccount(dc *dnsv1alpha1.DNSCluster) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-control", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "control"),
		},
	}
}

func (r *DNSClusterReconciler) buildWorkerServiceAccount(dc *dnsv1alpha1.DNSCluster) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "worker"),
		},
	}
}

func (r *DNSClusterReconciler) buildControlConfigMap(dc *dnsv1alpha1.DNSCluster) *corev1.ConfigMap {
	grpcPort := dc.Spec.ControlPlane.GRPCPort
	if grpcPort == 0 {
		grpcPort = 9090
	}
	httpPort := dc.Spec.ControlPlane.HTTPPort
	if httpPort == 0 {
		httpPort = 8080
	}

	configData := fmt.Sprintf(`mode: control
control_plane:
  grpc_address: ":%d"
  heartbeat_timeout: 30s
api:
  enabled: true
  listen_address: ":%d"
  cors_origins:
    - "*"
logging:
  level: info
  format: json
`, grpcPort, httpPort)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-control", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "control"),
		},
		Data: map[string]string{
			"config.yaml": configData,
		},
	}
}

func (r *DNSClusterReconciler) buildControlDeployment(dc *dnsv1alpha1.DNSCluster) *appsv1.Deployment {
	replicas := dc.Spec.ControlPlane.Replicas
	if replicas == 0 {
		replicas = 1
	}

	image := r.getImage(dc)
	grpcPort := dc.Spec.ControlPlane.GRPCPort
	if grpcPort == 0 {
		grpcPort = 9090
	}
	httpPort := dc.Spec.ControlPlane.HTTPPort
	if httpPort == 0 {
		httpPort = 8080
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-control", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "control"),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.selectorLabels(dc, "control"),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.labels(dc, "control"),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: fmt.Sprintf("%s-control", dc.Name),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(1000),
						RunAsGroup:   int64Ptr(1000),
						FSGroup:      int64Ptr(1000),
					},
					Containers: []corev1.Container{
						{
							Name:            "control",
							Image:           image,
							ImagePullPolicy: dc.Spec.Image.PullPolicy,
							Command:         []string{"/usr/local/bin/dns-control"},
							Args: []string{
								fmt.Sprintf("-grpc=:%d", grpcPort),
								fmt.Sprintf("-http=:%d", httpPort),
							},
							Ports: []corev1.ContainerPort{
								{Name: "grpc", ContainerPort: grpcPort, Protocol: corev1.ProtocolTCP},
								{Name: "http", ContainerPort: httpPort, Protocol: corev1.ProtocolTCP},
							},
							Resources: dc.Spec.ControlPlane.Resources,
							VolumeMounts: []corev1.VolumeMount{
								{Name: "config", MountPath: "/etc/dns-go", ReadOnly: true},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								ReadOnlyRootFilesystem:   boolPtr(true),
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: fmt.Sprintf("%s-control", dc.Name),
									},
								},
							},
						},
					},
					NodeSelector: dc.Spec.ControlPlane.NodeSelector,
					Tolerations:  dc.Spec.ControlPlane.Tolerations,
				},
			},
		},
	}
}

func (r *DNSClusterReconciler) buildControlService(dc *dnsv1alpha1.DNSCluster) *corev1.Service {
	grpcPort := dc.Spec.ControlPlane.GRPCPort
	if grpcPort == 0 {
		grpcPort = 9090
	}
	httpPort := dc.Spec.ControlPlane.HTTPPort
	if httpPort == 0 {
		httpPort = 8080
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-control", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "control"),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Name: "grpc", Port: grpcPort, TargetPort: intstr.FromString("grpc"), Protocol: corev1.ProtocolTCP},
				{Name: "http", Port: httpPort, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP},
			},
			Selector: r.selectorLabels(dc, "control"),
		},
	}
}

func (r *DNSClusterReconciler) buildWorkerDeployment(dc *dnsv1alpha1.DNSCluster) *appsv1.Deployment {
	replicas := dc.Spec.Workers.Replicas
	if replicas == 0 {
		replicas = 3
	}

	image := r.getImage(dc)
	dnsPort := dc.Spec.Workers.DNSPort
	if dnsPort == 0 {
		dnsPort = 53
	}
	grpcPort := dc.Spec.ControlPlane.GRPCPort
	if grpcPort == 0 {
		grpcPort = 9090
	}

	controlAddr := fmt.Sprintf("%s-control:%d", dc.Name, grpcPort)

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "worker"),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.selectorLabels(dc, "worker"),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.labels(dc, "worker"),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: fmt.Sprintf("%s-worker", dc.Name),
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: boolPtr(true),
						RunAsUser:    int64Ptr(1000),
						RunAsGroup:   int64Ptr(1000),
						FSGroup:      int64Ptr(1000),
					},
					Containers: []corev1.Container{
						{
							Name:            "worker",
							Image:           image,
							ImagePullPolicy: dc.Spec.Image.PullPolicy,
							Command:         []string{"/usr/local/bin/dns-worker"},
							Args: []string{
								fmt.Sprintf("-control=%s", controlAddr),
								fmt.Sprintf("-listen=0.0.0.0:%d", dnsPort),
								"-id=$(POD_NAME)",
							},
							Env: []corev1.EnvVar{
								{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
								{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
								{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
							},
							Ports: []corev1.ContainerPort{
								{Name: "dns-udp", ContainerPort: dnsPort, Protocol: corev1.ProtocolUDP},
								{Name: "dns-tcp", ContainerPort: dnsPort, Protocol: corev1.ProtocolTCP},
							},
							Resources: dc.Spec.Workers.Resources,
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								ReadOnlyRootFilesystem:   boolPtr(true),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
									Add:  []corev1.Capability{"NET_BIND_SERVICE"},
								},
							},
						},
					},
					NodeSelector: dc.Spec.Workers.NodeSelector,
					Tolerations:  dc.Spec.Workers.Tolerations,
				},
			},
		},
	}
}

func (r *DNSClusterReconciler) buildWorkerService(dc *dnsv1alpha1.DNSCluster) *corev1.Service {
	dnsPort := dc.Spec.Workers.DNSPort
	if dnsPort == 0 {
		dnsPort = 53
	}

	serviceType := dc.Spec.Workers.ServiceType
	if serviceType == "" {
		serviceType = corev1.ServiceTypeLoadBalancer
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "worker"),
		},
		Spec: corev1.ServiceSpec{
			Type:                  serviceType,
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
			Ports: []corev1.ServicePort{
				{Name: "dns-udp", Port: dnsPort, TargetPort: intstr.FromString("dns-udp"), Protocol: corev1.ProtocolUDP},
				{Name: "dns-tcp", Port: dnsPort, TargetPort: intstr.FromString("dns-tcp"), Protocol: corev1.ProtocolTCP},
			},
			Selector: r.selectorLabels(dc, "worker"),
		},
	}
}

func (r *DNSClusterReconciler) buildWorkerHPA(dc *dnsv1alpha1.DNSCluster) *autoscalingv2.HorizontalPodAutoscaler {
	minReplicas := dc.Spec.Workers.MinReplicas
	if minReplicas == 0 {
		minReplicas = 3
	}
	maxReplicas := dc.Spec.Workers.MaxReplicas
	if maxReplicas == 0 {
		maxReplicas = 20
	}
	cpuTarget := dc.Spec.Workers.Autoscaling.TargetCPUUtilization
	if cpuTarget == 0 {
		cpuTarget = 70
	}

	return &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "worker"),
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       fmt.Sprintf("%s-worker", dc.Name),
			},
			MinReplicas: &minReplicas,
			MaxReplicas: maxReplicas,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: corev1.ResourceCPU,
						Target: autoscalingv2.MetricTarget{
							Type:               autoscalingv2.UtilizationMetricType,
							AverageUtilization: &cpuTarget,
						},
					},
				},
			},
		},
	}
}

func (r *DNSClusterReconciler) buildWorkerPDB(dc *dnsv1alpha1.DNSCluster) *policyv1.PodDisruptionBudget {
	minAvailable := intstr.FromInt(2)

	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-worker", dc.Name),
			Namespace: dc.Namespace,
			Labels:    r.labels(dc, "worker"),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.selectorLabels(dc, "worker"),
			},
		},
	}
}

// Helper functions

func (r *DNSClusterReconciler) labels(dc *dnsv1alpha1.DNSCluster, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "dns-go",
		"app.kubernetes.io/instance":  dc.Name,
		"app.kubernetes.io/component": component,
		"app.kubernetes.io/part-of":   "dns-go",
	}
}

func (r *DNSClusterReconciler) selectorLabels(dc *dnsv1alpha1.DNSCluster, component string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "dns-go",
		"app.kubernetes.io/instance":  dc.Name,
		"app.kubernetes.io/component": component,
	}
}

func (r *DNSClusterReconciler) getImage(dc *dnsv1alpha1.DNSCluster) string {
	repo := dc.Spec.Image.Repository
	if repo == "" {
		repo = "ghcr.io/piwi3910/dns-go"
	}
	tag := dc.Spec.Image.Tag
	if tag == "" {
		tag = "latest"
	}
	return fmt.Sprintf("%s:%s", repo, tag)
}

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(i int64) *int64 {
	return &i
}

// SetupWithManager sets up the controller with the Manager.
func (r *DNSClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dnsv1alpha1.DNSCluster{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&autoscalingv2.HorizontalPodAutoscaler{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}
