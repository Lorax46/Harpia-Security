package kubernetes

import (
	"context"

	admissionregistrationv1typed "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	appsv1typed "k8s.io/client-go/kubernetes/typed/apps/v1"
	autoscalingv2typed "k8s.io/client-go/kubernetes/typed/autoscaling/v2"
	batchv1typed "k8s.io/client-go/kubernetes/typed/batch/v1"
	certificatesv1typed "k8s.io/client-go/kubernetes/typed/certificates/v1"
	coordinationv1typed "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1typed "k8s.io/client-go/kubernetes/typed/core/v1"
	flowcontrolv1typed "k8s.io/client-go/kubernetes/typed/flowcontrol/v1"
	networkingv1typed "k8s.io/client-go/kubernetes/typed/networking/v1"
	nodev1typed "k8s.io/client-go/kubernetes/typed/node/v1"
	policyv1typed "k8s.io/client-go/kubernetes/typed/policy/v1"
	policyv1beta1typed "k8s.io/client-go/kubernetes/typed/policy/v1beta1"
	rbacv1typed "k8s.io/client-go/kubernetes/typed/rbac/v1"
	schedulingv1typed "k8s.io/client-go/kubernetes/typed/scheduling/v1"
	storagev1typed "k8s.io/client-go/kubernetes/typed/storage/v1"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	flowcontrolv1 "k8s.io/api/flowcontrol/v1"
	networkingv1 "k8s.io/api/networking/v1"
	nodev1 "k8s.io/api/node/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool { return &b }

// unstructuredNestedBool safely retrieves a bool from an unstructured map.
func unstructuredNestedBool(obj map[string]interface{}, fields ...string) (bool, bool, error) {
	v, found, err := unstructured.NestedBool(obj, fields...)
	return v, found, err
}

// unstructuredNestedStringSlice safely retrieves a string slice from an unstructured map.
func unstructuredNestedStringSlice(obj map[string]interface{}, fields ...string) ([]string, bool, error) {
	v, found, err := unstructured.NestedStringSlice(obj, fields...)
	return v, found, err
}

// unstructuredNestedMap safely retrieves a map from an unstructured object.
func unstructuredNestedMap(obj map[string]interface{}, fields ...string) (map[string]interface{}, bool, error) {
	v, found, err := unstructured.NestedMap(obj, fields...)
	return v, found, err
}
// is not part of the typed API in modern Kubernetes.
type PSPInfo struct {
	Name                      string
	Privileged                bool
	AllowPrivilegeEscalation  *bool
	RequiredDropCapabilities  []string
	AllowedCapabilities       []string
	Volumes                   []string
	HostNetwork               bool
	HostPID                   bool
	HostIPC                   bool
	RunAsUser                 map[string]interface{}
	RunAsGroup                map[string]interface{}
	SELinux                   map[string]interface{}
}

// Provider implements the Kubernetes scanner provider backed by client-go.
type Provider struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	ctx       context.Context
}

// NewProvider builds a Kubernetes provider from a kubeconfig file path.
// If kubeconfigPath is empty, clientcmd falls back to the default loading
// rules (KUBECONFIG env var, ~/.kube/config, then in-cluster config).
func NewProvider(ctx context.Context, kubeconfigPath string) (*Provider, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Provider{clientset: clientset, config: config, ctx: ctx}, nil
}

// CoreV1 returns the full typed clientset.
func (p *Provider) CoreV1() kubernetes.Interface { return p.clientset }

// RbacV1 returns the rbac/v1 typed interface.
func (p *Provider) RbacV1() rbacv1typed.RbacV1Interface { return p.clientset.RbacV1() }

// AppsV1 returns the apps/v1 typed interface.
func (p *Provider) AppsV1() appsv1typed.AppsV1Interface { return p.clientset.AppsV1() }

// CoreV1Typed returns the core/v1 typed interface.
func (p *Provider) CoreV1Typed() corev1typed.CoreV1Interface { return p.clientset.CoreV1() }

// BatchV1 returns the batch/v1 typed interface.
func (p *Provider) BatchV1() batchv1typed.BatchV1Interface { return p.clientset.BatchV1() }

// NetworkingV1 returns the networking/v1 typed interface.
func (p *Provider) NetworkingV1() networkingv1typed.NetworkingV1Interface {
	return p.clientset.NetworkingV1()
}

// PolicyV1beta1 returns the policy/v1beta1 typed interface.
func (p *Provider) PolicyV1beta1() policyv1beta1typed.PolicyV1beta1Interface {
	return p.clientset.PolicyV1beta1()
}

// StorageV1 returns the storage/v1 typed interface.
func (p *Provider) StorageV1() storagev1typed.StorageV1Interface { return p.clientset.StorageV1() }

// AutoscalingV2 returns the autoscaling/v2 typed interface.
func (p *Provider) AutoscalingV2() autoscalingv2typed.AutoscalingV2Interface {
	return p.clientset.AutoscalingV2()
}

// Discovery returns the discovery client.
func (p *Provider) Discovery() discovery.DiscoveryInterface { return p.clientset.Discovery() }

// Dynamic returns a dynamic Kubernetes client.
func (p *Provider) Dynamic() (dynamic.Interface, error) {
	return dynamic.NewForConfig(p.config)
}

// ---------------------------------------------------------------------------
// List methods (used by checks via the KubernetesProviderClient interface)
// ---------------------------------------------------------------------------

func (p *Provider) ListNodes(ctx context.Context) (*corev1.NodeList, error) {
	return p.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListPods(ctx context.Context, namespace string) (*corev1.PodList, error) {
	return p.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	return p.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error) {
	return p.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error) {
	return p.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error) {
	return p.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error) {
	return p.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListServiceAccounts(ctx context.Context, namespace string) (*corev1.ServiceAccountList, error) {
	return p.clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListConfigMaps(ctx context.Context, namespace string) (*corev1.ConfigMapList, error) {
	return p.clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListSecrets(ctx context.Context, namespace string) (*corev1.SecretList, error) {
	return p.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListDaemonSets(ctx context.Context, namespace string) (*appsv1.DaemonSetList, error) {
	return p.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListDeployments(ctx context.Context, namespace string) (*appsv1.DeploymentList, error) {
	return p.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListStatefulSets(ctx context.Context, namespace string) (*appsv1.StatefulSetList, error) {
	return p.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListReplicaSets(ctx context.Context, namespace string) (*appsv1.ReplicaSetList, error) {
	return p.clientset.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListCronJobs(ctx context.Context, namespace string) (*batchv1.CronJobList, error) {
	return p.clientset.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListJobs(ctx context.Context, namespace string) (*batchv1.JobList, error) {
	return p.clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListNetworkPolicies(ctx context.Context, namespace string) (*networkingv1.NetworkPolicyList, error) {
	return p.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
}

// ListPodSecurityPolicies lists PSPs using the dynamic client since PSPs are
// removed from the typed clientset.
func (p *Provider) ListPodSecurityPolicies(ctx context.Context) ([]PSPInfo, error) {
	dyn, err := dynamic.NewForConfig(p.config)
	if err != nil {
		return nil, err
	}
	gvr := schema.GroupVersionResource{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies"}
	list, err := dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []PSPInfo
	for i := range list.Items {
		obj := list.Items[i].UnstructuredContent()
		psp := PSPInfo{Name: list.Items[i].GetName()}
		if spec, ok := obj["spec"].(map[string]interface{}); ok {
			if v, _, _ := unstructuredNestedBool(spec, "privileged"); v {
				psp.Privileged = true
			}
			if v, _, _ := unstructuredNestedBool(spec, "allowPrivilegeEscalation"); v {
				psp.AllowPrivilegeEscalation = boolPtr(true)
			}
			if v, ok, _ := unstructuredNestedStringSlice(spec, "requiredDropCapabilities"); ok {
				psp.RequiredDropCapabilities = v
			}
			if v, ok, _ := unstructuredNestedStringSlice(spec, "allowedCapabilities"); ok {
				psp.AllowedCapabilities = v
			}
			if v, ok, _ := unstructuredNestedStringSlice(spec, "volumes"); ok {
				psp.Volumes = v
			}
			if v, _, _ := unstructuredNestedBool(spec, "hostNetwork"); v {
				psp.HostNetwork = true
			}
			if v, _, _ := unstructuredNestedBool(spec, "hostPID"); v {
				psp.HostPID = true
			}
			if v, _, _ := unstructuredNestedBool(spec, "hostIPC"); v {
				psp.HostIPC = true
			}
			if v, ok, _ := unstructuredNestedMap(spec, "runAsUser"); ok {
				psp.RunAsUser = v
			}
			if v, ok, _ := unstructuredNestedMap(spec, "runAsGroup"); ok {
				psp.RunAsGroup = v
			}
			if v, ok, _ := unstructuredNestedMap(spec, "seLinux"); ok {
				psp.SELinux = v
			}
		}
		out = append(out, psp)
	}
	return out, nil
}

func (p *Provider) ListResourceQuotas(ctx context.Context, namespace string) (*corev1.ResourceQuotaList, error) {
	return p.clientset.CoreV1().ResourceQuotas(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListLimitRanges(ctx context.Context, namespace string) (*corev1.LimitRangeList, error) {
	return p.clientset.CoreV1().LimitRanges(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListHorizontalPodAutoscalers(ctx context.Context, namespace string) (*autoscalingv2.HorizontalPodAutoscalerList, error) {
	return p.clientset.AutoscalingV2().HorizontalPodAutoscalers(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListIngresses(ctx context.Context, namespace string) (*networkingv1.IngressList, error) {
	return p.clientset.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListStorageClasses(ctx context.Context) (*storagev1.StorageClassList, error) {
	return p.clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListPersistentVolumes(ctx context.Context) (*corev1.PersistentVolumeList, error) {
	return p.clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListPersistentVolumeClaims(ctx context.Context, namespace string) (*corev1.PersistentVolumeClaimList, error) {
	return p.clientset.CoreV1().PersistentVolumeClaims(namespace).List(ctx, metav1.ListOptions{})
}

// ListPodDisruptionBudgets lists policy/v1 PodDisruptionBudgets.
func (p *Provider) ListPodDisruptionBudgets(ctx context.Context, namespace string) (*policyv1.PodDisruptionBudgetList, error) {
	return p.clientset.PolicyV1().PodDisruptionBudgets(namespace).List(ctx, metav1.ListOptions{})
}

// ListPriorityClasses lists scheduling/v1 PriorityClasses.
func (p *Provider) ListPriorityClasses(ctx context.Context) (*schedulingv1.PriorityClassList, error) {
	return p.clientset.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListServices(ctx context.Context, namespace string) (*corev1.ServiceList, error) {
	return p.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListEndpoints(ctx context.Context, namespace string) (*corev1.EndpointsList, error) {
	return p.clientset.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListEvents(ctx context.Context, namespace string) (*corev1.EventList, error) {
	return p.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListIngressClasses(ctx context.Context) (*networkingv1.IngressClassList, error) {
	return p.clientset.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListRuntimeClasses(ctx context.Context) (*nodev1.RuntimeClassList, error) {
	return p.clientset.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListCSIDrivers(ctx context.Context) (*storagev1.CSIDriverList, error) {
	return p.clientset.StorageV1().CSIDrivers().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListCSINodes(ctx context.Context) (*storagev1.CSINodeList, error) {
	return p.clientset.StorageV1().CSINodes().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListCertificateSigningRequests(ctx context.Context) (*certificatesv1.CertificateSigningRequestList, error) {
	return p.clientset.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListLeases(ctx context.Context, namespace string) (*coordinationv1.LeaseList, error) {
	return p.clientset.CoordinationV1().Leases(namespace).List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListComponentStatuses(ctx context.Context) (*corev1.ComponentStatusList, error) {
	return p.clientset.CoreV1().ComponentStatuses().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListValidatingWebhookConfigurations(ctx context.Context) (*admissionregistrationv1.ValidatingWebhookConfigurationList, error) {
	return p.clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListMutatingWebhookConfigurations(ctx context.Context) (*admissionregistrationv1.MutatingWebhookConfigurationList, error) {
	return p.clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListFlowSchemas(ctx context.Context) (*flowcontrolv1.FlowSchemaList, error) {
	return p.clientset.FlowcontrolV1().FlowSchemas().List(ctx, metav1.ListOptions{})
}

func (p *Provider) ListPriorityLevelConfigurations(ctx context.Context) (*flowcontrolv1.PriorityLevelConfigurationList, error) {
	return p.clientset.FlowcontrolV1().PriorityLevelConfigurations().List(ctx, metav1.ListOptions{})
}

// ---------------------------------------------------------------------------
// Convenience accessors (all-namespaces listings using the stored context)
// ---------------------------------------------------------------------------

func (p *Provider) Nodes() (*corev1.NodeList, error) { return p.ListNodes(p.ctx) }

func (p *Provider) Pods() (*corev1.PodList, error) { return p.ListPods(p.ctx, "") }

func (p *Provider) Namespaces() (*corev1.NamespaceList, error) { return p.ListNamespaces(p.ctx) }

func (p *Provider) ClusterRoles() (*rbacv1.ClusterRoleList, error) {
	return p.ListClusterRoles(p.ctx)
}

func (p *Provider) ClusterRoleBindings() (*rbacv1.ClusterRoleBindingList, error) {
	return p.ListClusterRoleBindings(p.ctx)
}

func (p *Provider) Roles() (*rbacv1.RoleList, error) { return p.ListRoles(p.ctx, "") }

func (p *Provider) RoleBindings() (*rbacv1.RoleBindingList, error) {
	return p.ListRoleBindings(p.ctx, "")
}

func (p *Provider) ServiceAccounts() (*corev1.ServiceAccountList, error) {
	return p.ListServiceAccounts(p.ctx, "")
}

func (p *Provider) ConfigMaps() (*corev1.ConfigMapList, error) {
	return p.ListConfigMaps(p.ctx, "")
}

func (p *Provider) Secrets() (*corev1.SecretList, error) { return p.ListSecrets(p.ctx, "") }

func (p *Provider) DaemonSets() (*appsv1.DaemonSetList, error) {
	return p.ListDaemonSets(p.ctx, "")
}

func (p *Provider) Deployments() (*appsv1.DeploymentList, error) {
	return p.ListDeployments(p.ctx, "")
}

func (p *Provider) StatefulSets() (*appsv1.StatefulSetList, error) {
	return p.ListStatefulSets(p.ctx, "")
}

func (p *Provider) ReplicaSets() (*appsv1.ReplicaSetList, error) {
	return p.ListReplicaSets(p.ctx, "")
}

func (p *Provider) CronJobs() (*batchv1.CronJobList, error) { return p.ListCronJobs(p.ctx, "") }

func (p *Provider) Jobs() (*batchv1.JobList, error) { return p.ListJobs(p.ctx, "") }

func (p *Provider) NetworkPolicies() (*networkingv1.NetworkPolicyList, error) {
	return p.ListNetworkPolicies(p.ctx, "")
}

func (p *Provider) PodSecurityPolicies() ([]PSPInfo, error) {
	return p.ListPodSecurityPolicies(p.ctx)
}

func (p *Provider) ResourceQuotas() (*corev1.ResourceQuotaList, error) {
	return p.ListResourceQuotas(p.ctx, "")
}

func (p *Provider) LimitRanges() (*corev1.LimitRangeList, error) {
	return p.ListLimitRanges(p.ctx, "")
}

func (p *Provider) HorizontalPodAutoscalers() (*autoscalingv2.HorizontalPodAutoscalerList, error) {
	return p.ListHorizontalPodAutoscalers(p.ctx, "")
}

func (p *Provider) Ingresses() (*networkingv1.IngressList, error) {
	return p.ListIngresses(p.ctx, "")
}

func (p *Provider) StorageClasses() (*storagev1.StorageClassList, error) {
	return p.ListStorageClasses(p.ctx)
}

func (p *Provider) PersistentVolumes() (*corev1.PersistentVolumeList, error) {
	return p.ListPersistentVolumes(p.ctx)
}

func (p *Provider) PersistentVolumeClaims() (*corev1.PersistentVolumeClaimList, error) {
	return p.ListPersistentVolumeClaims(p.ctx, "")
}

func (p *Provider) Services() (*corev1.ServiceList, error)       { return p.ListServices(p.ctx, "") }
func (p *Provider) Endpoints() (*corev1.EndpointsList, error)     { return p.ListEndpoints(p.ctx, "") }
func (p *Provider) Events() (*corev1.EventList, error)             { return p.ListEvents(p.ctx, "") }
func (p *Provider) IngressClasses() (*networkingv1.IngressClassList, error) {
	return p.ListIngressClasses(p.ctx)
}
func (p *Provider) RuntimeClasses() (*nodev1.RuntimeClassList, error) {
	return p.ListRuntimeClasses(p.ctx)
}
func (p *Provider) CSIDrivers() (*storagev1.CSIDriverList, error) { return p.ListCSIDrivers(p.ctx) }
func (p *Provider) CSINodes() (*storagev1.CSINodeList, error)     { return p.ListCSINodes(p.ctx) }
func (p *Provider) CertificateSigningRequests() (*certificatesv1.CertificateSigningRequestList, error) {
	return p.ListCertificateSigningRequests(p.ctx)
}
func (p *Provider) Leases() (*coordinationv1.LeaseList, error)   { return p.ListLeases(p.ctx, "") }
func (p *Provider) ComponentStatuses() (*corev1.ComponentStatusList, error) {
	return p.ListComponentStatuses(p.ctx)
}
func (p *Provider) ValidatingWebhookConfigurations() (*admissionregistrationv1.ValidatingWebhookConfigurationList, error) {
	return p.ListValidatingWebhookConfigurations(p.ctx)
}
func (p *Provider) MutatingWebhookConfigurations() (*admissionregistrationv1.MutatingWebhookConfigurationList, error) {
	return p.ListMutatingWebhookConfigurations(p.ctx)
}
func (p *Provider) FlowSchemas() (*flowcontrolv1.FlowSchemaList, error) {
	return p.ListFlowSchemas(p.ctx)
}
func (p *Provider) PriorityLevelConfigurations() (*flowcontrolv1.PriorityLevelConfigurationList, error) {
	return p.ListPriorityLevelConfigurations(p.ctx)
}

// AdmissionregistrationV1 returns the admissionregistration/v1 typed interface.
func (p *Provider) AdmissionregistrationV1() admissionregistrationv1typed.AdmissionregistrationV1Interface {
	return p.clientset.AdmissionregistrationV1()
}

// CertificatesV1 returns the certificates/v1 typed interface.
func (p *Provider) CertificatesV1() certificatesv1typed.CertificatesV1Interface {
	return p.clientset.CertificatesV1()
}

// CoordinationV1 returns the coordination/v1 typed interface.
func (p *Provider) CoordinationV1() coordinationv1typed.CoordinationV1Interface {
	return p.clientset.CoordinationV1()
}

// FlowControlV1 returns the flowcontrol/v1 typed interface.
func (p *Provider) FlowControlV1() flowcontrolv1typed.FlowcontrolV1Interface {
	return p.clientset.FlowcontrolV1()
}

// NodeV1 returns the node/v1 typed interface.
func (p *Provider) NodeV1() nodev1typed.NodeV1Interface {
	return p.clientset.NodeV1()
}

// PolicyV1 returns the policy/v1 typed interface.
func (p *Provider) PolicyV1() policyv1typed.PolicyV1Interface {
	return p.clientset.PolicyV1()
}

// SchedulingV1 returns the scheduling/v1 typed interface.
func (p *Provider) SchedulingV1() schedulingv1typed.SchedulingV1Interface {
	return p.clientset.SchedulingV1()
}
