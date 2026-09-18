package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
)

// KubernetesCollector implements the Collector interface for Kubernetes.
// It discovers Kubernetes cluster resources using the client-go typed clients.
type KubernetesCollector struct {
	provider *kubernetes.Provider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewKubernetesCollector creates a new Kubernetes inventory collector.
func NewKubernetesCollector(provider *kubernetes.Provider) *KubernetesCollector {
	return &KubernetesCollector{
		provider: provider,
		cache:    make(map[string]*InventoryResult),
	}
}

// Collect discovers Kubernetes resources of the specified type.
func (c *KubernetesCollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "kubernetes",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	case "kubernetes_pod":
		result.Resources, err = c.collectPods(ctx)
	case "kubernetes_deployment":
		result.Resources, err = c.collectDeployments(ctx)
	case "kubernetes_stateful_set":
		result.Resources, err = c.collectStatefulSets(ctx)
	case "kubernetes_daemon_set":
		result.Resources, err = c.collectDaemonSets(ctx)
	case "kubernetes_replica_set":
		result.Resources, err = c.collectReplicaSets(ctx)
	case "kubernetes_job":
		result.Resources, err = c.collectJobs(ctx)
	case "kubernetes_cron_job":
		result.Resources, err = c.collectCronJobs(ctx)
	case "kubernetes_service":
		result.Resources, err = c.collectServices(ctx)
	case "kubernetes_ingress":
		result.Resources, err = c.collectIngresses(ctx)
	case "kubernetes_config_map":
		result.Resources, err = c.collectConfigMaps(ctx)
	case "kubernetes_secret":
		result.Resources, err = c.collectSecrets(ctx)
	case "kubernetes_persistent_volume":
		result.Resources, err = c.collectPersistentVolumes(ctx)
	case "kubernetes_persistent_volume_claim":
		result.Resources, err = c.collectPersistentVolumeClaims(ctx)
	case "kubernetes_storage_class":
		result.Resources, err = c.collectStorageClasses(ctx)
	case "kubernetes_namespace":
		result.Resources, err = c.collectNamespaces(ctx)
	case "kubernetes_node":
		result.Resources, err = c.collectNodes(ctx)
	case "kubernetes_service_account":
		result.Resources, err = c.collectServiceAccounts(ctx)
	case "kubernetes_role":
		result.Resources, err = c.collectRoles(ctx)
	case "kubernetes_cluster_role":
		result.Resources, err = c.collectClusterRoles(ctx)
	case "kubernetes_role_binding":
		result.Resources, err = c.collectRoleBindings(ctx)
	case "kubernetes_cluster_role_binding":
		result.Resources, err = c.collectClusterRoleBindings(ctx)
	case "kubernetes_network_policy":
		result.Resources, err = c.collectNetworkPolicies(ctx)
	case "kubernetes_resource_quota":
		result.Resources, err = c.collectResourceQuotas(ctx)
	case "kubernetes_limit_range":
		result.Resources, err = c.collectLimitRanges(ctx)
	case "kubernetes_horizontal_pod_autoscaler":
		result.Resources, err = c.collectHorizontalPodAutoscalers(ctx)
	
	case "kubernetes_default_service_account":
		result.Resources, err = c.collectDefaultServiceAccounts(ctx)
	case "kubernetes_endpoint":
		result.Resources, err = c.collectEndpoints(ctx)
	case "kubernetes_event":
		result.Resources, err = c.collectEvents(ctx)
	case "kubernetes_pod_security_policy":
		result.Resources, err = c.collectPodSecurityPolicies(ctx)
	case "kubernetes_ingress_class":
		result.Resources, err = c.collectIngressClasses(ctx)
	case "kubernetes_runtime_class":
		result.Resources, err = c.collectRuntimeClasses(ctx)
	case "kubernetes_csi_driver":
		result.Resources, err = c.collectCSIDrivers(ctx)
	case "kubernetes_csi_node":
		result.Resources, err = c.collectCSINodes(ctx)
	case "kubernetes_class":
		result.Resources, err = c.collectIngressClasses(ctx)
	case "kubernetes_resource":
		result.Resources, err = c.collectAllResources(ctx)
	case "kubernetes_api_service":
		result.Resources, err = c.collectAPIServices(ctx)
	case "kubernetes_validating_webhook_configuration":
		result.Resources, err = c.collectValidatingWebhookConfigurations(ctx)
	case "kubernetes_mutating_webhook_configuration":
		result.Resources, err = c.collectMutatingWebhookConfigurations(ctx)
	case "kubernetes_certificate_signing_request":
		result.Resources, err = c.collectCertificateSigningRequests(ctx)
	case "kubernetes_lease":
		result.Resources, err = c.collectLeases(ctx)
	case "kubernetes_component_status":
		result.Resources, err = c.collectComponentStatuses(ctx)
	case "kubernetes_flow_schema":
		result.Resources, err = c.collectFlowSchemas(ctx)
	case "kubernetes_priority_level_configuration":
		result.Resources, err = c.collectPriorityLevelConfigurations(ctx)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	if err != nil {
		return nil, err
	}

	result.Total = len(result.Resources)
	c.mu.Lock()
	c.cache[resourceType] = result
	c.mu.Unlock()
	return result, nil
}

// ListResourceTypes returns all Kubernetes resource types.
func (c *KubernetesCollector) ListResourceTypes() []ResourceType {
	var resourceTypes []ResourceType
	for _, rt := range steampipeResourceTypes {
		if rt.Provider == "kubernetes" {
			resourceTypes = append(resourceTypes, rt)
		}
	}
	return resourceTypes
}

func (c *KubernetesCollector) collectPods(ctx context.Context) ([]Resource, error) {
	pods, err := c.provider.Pods()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, pod := range pods.Items {
		resources = append(resources, Resource{
			ID:         string(pod.UID),
			Name:       pod.Name,
			Type:       "kubernetes_pod",
			Provider:   "kubernetes",
			Namespace:  pod.Namespace,
			Discovered: time.Now(),
			Tags:       pod.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectDeployments(ctx context.Context) ([]Resource, error) {
	deployments, err := c.provider.Deployments()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, deployment := range deployments.Items {
		resources = append(resources, Resource{
			ID:         string(deployment.UID),
			Name:       deployment.Name,
			Type:       "kubernetes_deployment",
			Provider:   "kubernetes",
			Namespace:  deployment.Namespace,
			Discovered: time.Now(),
			Tags:       deployment.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectStatefulSets(ctx context.Context) ([]Resource, error) {
	statefulSets, err := c.provider.StatefulSets()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ss := range statefulSets.Items {
		resources = append(resources, Resource{
			ID:         string(ss.UID),
			Name:       ss.Name,
			Type:       "kubernetes_stateful_set",
			Provider:   "kubernetes",
			Namespace:  ss.Namespace,
			Discovered: time.Now(),
			Tags:       ss.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectDaemonSets(ctx context.Context) ([]Resource, error) {
	daemonSets, err := c.provider.DaemonSets()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ds := range daemonSets.Items {
		resources = append(resources, Resource{
			ID:         string(ds.UID),
			Name:       ds.Name,
			Type:       "kubernetes_daemon_set",
			Provider:   "kubernetes",
			Namespace:  ds.Namespace,
			Discovered: time.Now(),
			Tags:       ds.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectReplicaSets(ctx context.Context) ([]Resource, error) {
	replicaSets, err := c.provider.ReplicaSets()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, rs := range replicaSets.Items {
		resources = append(resources, Resource{
			ID:         string(rs.UID),
			Name:       rs.Name,
			Type:       "kubernetes_replica_set",
			Provider:   "kubernetes",
			Namespace:  rs.Namespace,
			Discovered: time.Now(),
			Tags:       rs.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectJobs(ctx context.Context) ([]Resource, error) {
	jobs, err := c.provider.Jobs()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, job := range jobs.Items {
		resources = append(resources, Resource{
			ID:         string(job.UID),
			Name:       job.Name,
			Type:       "kubernetes_job",
			Provider:   "kubernetes",
			Namespace:  job.Namespace,
			Discovered: time.Now(),
			Tags:       job.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectCronJobs(ctx context.Context) ([]Resource, error) {
	cronJobs, err := c.provider.CronJobs()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cronJob := range cronJobs.Items {
		resources = append(resources, Resource{
			ID:         string(cronJob.UID),
			Name:       cronJob.Name,
			Type:       "kubernetes_cron_job",
			Provider:   "kubernetes",
			Namespace:  cronJob.Namespace,
			Discovered: time.Now(),
			Tags:       cronJob.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectServices(ctx context.Context) ([]Resource, error) {
	services, err := c.provider.Services()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, svc := range services.Items {
		resources = append(resources, Resource{
			ID:         string(svc.UID),
			Name:       svc.Name,
			Type:       "kubernetes_service",
			Provider:   "kubernetes",
			Namespace:  svc.Namespace,
			Discovered: time.Now(),
			Tags:       svc.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectIngresses(ctx context.Context) ([]Resource, error) {
	ingresses, err := c.provider.Ingresses()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ingress := range ingresses.Items {
		resources = append(resources, Resource{
			ID:         string(ingress.UID),
			Name:       ingress.Name,
			Type:       "kubernetes_ingress",
			Provider:   "kubernetes",
			Namespace:  ingress.Namespace,
			Discovered: time.Now(),
			Tags:       ingress.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectConfigMaps(ctx context.Context) ([]Resource, error) {
	configMaps, err := c.provider.ConfigMaps()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cm := range configMaps.Items {
		resources = append(resources, Resource{
			ID:         string(cm.UID),
			Name:       cm.Name,
			Type:       "kubernetes_config_map",
			Provider:   "kubernetes",
			Namespace:  cm.Namespace,
			Discovered: time.Now(),
			Tags:       cm.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectSecrets(ctx context.Context) ([]Resource, error) {
	secrets, err := c.provider.Secrets()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, secret := range secrets.Items {
		resources = append(resources, Resource{
			ID:         string(secret.UID),
			Name:       secret.Name,
			Type:       "kubernetes_secret",
			Provider:   "kubernetes",
			Namespace:  secret.Namespace,
			Discovered: time.Now(),
			Tags:       secret.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPersistentVolumes(ctx context.Context) ([]Resource, error) {
	pvs, err := c.provider.PersistentVolumes()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, pv := range pvs.Items {
		resources = append(resources, Resource{
			ID:         string(pv.UID),
			Name:       pv.Name,
			Type:       "kubernetes_persistent_volume",
			Provider:   "kubernetes",
			Namespace:  pv.Namespace,
			Discovered: time.Now(),
			Tags:       pv.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPersistentVolumeClaims(ctx context.Context) ([]Resource, error) {
	pvcs, err := c.provider.PersistentVolumeClaims()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, pvc := range pvcs.Items {
		resources = append(resources, Resource{
			ID:         string(pvc.UID),
			Name:       pvc.Name,
			Type:       "kubernetes_persistent_volume_claim",
			Provider:   "kubernetes",
			Namespace:  pvc.Namespace,
			Discovered: time.Now(),
			Tags:       pvc.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectStorageClasses(ctx context.Context) ([]Resource, error) {
	scs, err := c.provider.StorageClasses()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, sc := range scs.Items {
		resources = append(resources, Resource{
			ID:         string(sc.UID),
			Name:       sc.Name,
			Type:       "kubernetes_storage_class",
			Provider:   "kubernetes",
			Namespace:  sc.Namespace,
			Discovered: time.Now(),
			Tags:       sc.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectNamespaces(ctx context.Context) ([]Resource, error) {
	namespaces, err := c.provider.Namespaces()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ns := range namespaces.Items {
		resources = append(resources, Resource{
			ID:         string(ns.UID),
			Name:       ns.Name,
			Type:       "kubernetes_namespace",
			Provider:   "kubernetes",
			Namespace:  ns.Namespace,
			Discovered: time.Now(),
			Tags:       ns.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectNodes(ctx context.Context) ([]Resource, error) {
	nodes, err := c.provider.Nodes()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, node := range nodes.Items {
		resources = append(resources, Resource{
			ID:         string(node.UID),
			Name:       node.Name,
			Type:       "kubernetes_node",
			Provider:   "kubernetes",
			Namespace:  node.Namespace,
			Discovered: time.Now(),
			Tags:       node.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectServiceAccounts(ctx context.Context) ([]Resource, error) {
	sas, err := c.provider.ServiceAccounts()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, sa := range sas.Items {
		resources = append(resources, Resource{
			ID:         string(sa.UID),
			Name:       sa.Name,
			Type:       "kubernetes_service_account",
			Provider:   "kubernetes",
			Namespace:  sa.Namespace,
			Discovered: time.Now(),
			Tags:       sa.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectRoles(ctx context.Context) ([]Resource, error) {
	roles, err := c.provider.Roles()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, role := range roles.Items {
		resources = append(resources, Resource{
			ID:         string(role.UID),
			Name:       role.Name,
			Type:       "kubernetes_role",
			Provider:   "kubernetes",
			Namespace:  role.Namespace,
			Discovered: time.Now(),
			Tags:       role.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectClusterRoles(ctx context.Context) ([]Resource, error) {
	clusterRoles, err := c.provider.ClusterRoles()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cr := range clusterRoles.Items {
		resources = append(resources, Resource{
			ID:         string(cr.UID),
			Name:       cr.Name,
			Type:       "kubernetes_cluster_role",
			Provider:   "kubernetes",
			Namespace:  cr.Namespace,
			Discovered: time.Now(),
			Tags:       cr.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectRoleBindings(ctx context.Context) ([]Resource, error) {
	rbs, err := c.provider.RoleBindings()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, rb := range rbs.Items {
		resources = append(resources, Resource{
			ID:         string(rb.UID),
			Name:       rb.Name,
			Type:       "kubernetes_role_binding",
			Provider:   "kubernetes",
			Namespace:  rb.Namespace,
			Discovered: time.Now(),
			Tags:       rb.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectClusterRoleBindings(ctx context.Context) ([]Resource, error) {
	crbs, err := c.provider.ClusterRoleBindings()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, crb := range crbs.Items {
		resources = append(resources, Resource{
			ID:         string(crb.UID),
			Name:       crb.Name,
			Type:       "kubernetes_cluster_role_binding",
			Provider:   "kubernetes",
			Namespace:  crb.Namespace,
			Discovered: time.Now(),
			Tags:       crb.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectNetworkPolicies(ctx context.Context) ([]Resource, error) {
	nps, err := c.provider.NetworkPolicies()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, np := range nps.Items {
		resources = append(resources, Resource{
			ID:         string(np.UID),
			Name:       np.Name,
			Type:       "kubernetes_network_policy",
			Provider:   "kubernetes",
			Namespace:  np.Namespace,
			Discovered: time.Now(),
			Tags:       np.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectResourceQuotas(ctx context.Context) ([]Resource, error) {
	rqs, err := c.provider.ResourceQuotas()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, rq := range rqs.Items {
		resources = append(resources, Resource{
			ID:         string(rq.UID),
			Name:       rq.Name,
			Type:       "kubernetes_resource_quota",
			Provider:   "kubernetes",
			Namespace:  rq.Namespace,
			Discovered: time.Now(),
			Tags:       rq.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectLimitRanges(ctx context.Context) ([]Resource, error) {
	lrs, err := c.provider.LimitRanges()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, lr := range lrs.Items {
		resources = append(resources, Resource{
			ID:         string(lr.UID),
			Name:       lr.Name,
			Type:       "kubernetes_limit_range",
			Provider:   "kubernetes",
			Namespace:  lr.Namespace,
			Discovered: time.Now(),
			Tags:       lr.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectHorizontalPodAutoscalers(ctx context.Context) ([]Resource, error) {
	hpas, err := c.provider.HorizontalPodAutoscalers()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, hpa := range hpas.Items {
		resources = append(resources, Resource{
			ID:         string(hpa.UID),
			Name:       hpa.Name,
			Type:       "kubernetes_horizontal_pod_autoscaler",
			Provider:   "kubernetes",
			Namespace:  hpa.Namespace,
			Discovered: time.Now(),
			Tags:       hpa.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPodDisruptionBudgets(ctx context.Context) ([]Resource, error) {
	pdbs, err := c.provider.ListPodDisruptionBudgets(ctx, "")
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, pdb := range pdbs.Items {
		resources = append(resources, Resource{
			ID:         string(pdb.UID),
			Name:       pdb.Name,
			Type:       "kubernetes_pod_disruption_budget",
			Provider:   "kubernetes",
			Namespace:  pdb.Namespace,
			Discovered: time.Now(),
			Tags:       pdb.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPriorityClasses(ctx context.Context) ([]Resource, error) {
	pcs, err := c.provider.ListPriorityClasses(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, pc := range pcs.Items {
		resources = append(resources, Resource{
			ID:         string(pc.UID),
			Name:       pc.Name,
			Type:       "kubernetes_priority_class",
			Provider:   "kubernetes",
			Namespace:  pc.Namespace,
			Discovered: time.Now(),
			Tags:       pc.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectDefaultServiceAccounts(ctx context.Context) ([]Resource, error) {
	sas, err := c.provider.ServiceAccounts()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, sa := range sas.Items {
		if sa.Name == "default" || strings.Contains(sa.Name, "default") {
			resources = append(resources, Resource{
				ID:         string(sa.UID),
				Name:       sa.Name,
				Type:       "kubernetes_default_service_account",
				Provider:   "kubernetes",
				Namespace:  sa.Namespace,
				Discovered: time.Now(),
				Tags:       sa.Labels,
			})
		}
	}
	return resources, nil
}

func (c *KubernetesCollector) collectEndpoints(ctx context.Context) ([]Resource, error) {
	endpoints, err := c.provider.Endpoints()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ep := range endpoints.Items {
		resources = append(resources, Resource{
			ID:         string(ep.UID),
			Name:       ep.Name,
			Type:       "kubernetes_endpoint",
			Provider:   "kubernetes",
			Namespace:  ep.Namespace,
			Discovered: time.Now(),
			Tags:       ep.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectEvents(ctx context.Context) ([]Resource, error) {
	events, err := c.provider.Events()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, event := range events.Items {
		resources = append(resources, Resource{
			ID:         string(event.UID),
			Name:       event.Name,
			Type:       "kubernetes_event",
			Provider:   "kubernetes",
			Namespace:  event.Namespace,
			Discovered: time.Now(),
			Tags:       map[string]string{
				"reason":         event.Reason,
				"type":           event.Type,
				"involvedObject": event.InvolvedObject.Name,
			},
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPodSecurityPolicies(ctx context.Context) ([]Resource, error) {
	psps, err := c.provider.PodSecurityPolicies()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, psp := range psps {
		resources = append(resources, Resource{
			ID:         psp.Name,
			Name:       psp.Name,
			Type:       "kubernetes_pod_security_policy",
			Provider:   "kubernetes",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectIngressClasses(ctx context.Context) ([]Resource, error) {
	ics, err := c.provider.IngressClasses()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, ic := range ics.Items {
		resources = append(resources, Resource{
			ID:         string(ic.UID),
			Name:       ic.Name,
			Type:       "kubernetes_ingress_class",
			Provider:   "kubernetes",
			Namespace:  ic.Namespace,
			Discovered: time.Now(),
			Tags:       ic.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectRuntimeClasses(ctx context.Context) ([]Resource, error) {
	rcs, err := c.provider.RuntimeClasses()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, rc := range rcs.Items {
		resources = append(resources, Resource{
			ID:         string(rc.UID),
			Name:       rc.Name,
			Type:       "kubernetes_runtime_class",
			Provider:   "kubernetes",
			Namespace:  rc.Namespace,
			Discovered: time.Now(),
			Tags:       rc.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectCSIDrivers(ctx context.Context) ([]Resource, error) {
	drivers, err := c.provider.CSIDrivers()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, driver := range drivers.Items {
		resources = append(resources, Resource{
			ID:         string(driver.UID),
			Name:       driver.Name,
			Type:       "kubernetes_csi_driver",
			Provider:   "kubernetes",
			Namespace:  driver.Namespace,
			Discovered: time.Now(),
			Tags:       driver.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectCSINodes(ctx context.Context) ([]Resource, error) {
	nodes, err := c.provider.CSINodes()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, node := range nodes.Items {
		resources = append(resources, Resource{
			ID:         string(node.UID),
			Name:       node.Name,
			Type:       "kubernetes_csi_node",
			Provider:   "kubernetes",
			Namespace:  node.Namespace,
			Discovered: time.Now(),
			Tags:       node.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectAllResources(ctx context.Context) ([]Resource, error) {
	// kubernetes_resource is a virtual type that collects all unique resource kinds.
	// This aggregates one representative resource per known resource type.
	return c.collectKinds(ctx)
}

func (c *KubernetesCollector) collectAPIServices(ctx context.Context) ([]Resource, error) {
	// APIServices are cluster-scoped and tracked through the discovery API.
	// We aggregate a representative "apiservices" resource to expose them.
	return []Resource{
		{
			ID:         "apiservices",
			Name:       "APIServices",
			Type:       "kubernetes_api_service",
			Provider:   "kubernetes",
			Discovered: time.Now(),
		},
	}, nil
}

func (c *KubernetesCollector) collectValidatingWebhookConfigurations(ctx context.Context) ([]Resource, error) {
	configs, err := c.provider.ValidatingWebhookConfigurations()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cfg := range configs.Items {
		resources = append(resources, Resource{
			ID:         string(cfg.UID),
			Name:       cfg.Name,
			Type:       "kubernetes_validating_webhook_configuration",
			Provider:   "kubernetes",
			Namespace:  cfg.Namespace,
			Discovered: time.Now(),
			Tags:       cfg.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectMutatingWebhookConfigurations(ctx context.Context) ([]Resource, error) {
	configs, err := c.provider.MutatingWebhookConfigurations()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cfg := range configs.Items {
		resources = append(resources, Resource{
			ID:         string(cfg.UID),
			Name:       cfg.Name,
			Type:       "kubernetes_mutating_webhook_configuration",
			Provider:   "kubernetes",
			Namespace:  cfg.Namespace,
			Discovered: time.Now(),
			Tags:       cfg.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectCertificateSigningRequests(ctx context.Context) ([]Resource, error) {
	csrs, err := c.provider.CertificateSigningRequests()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, csr := range csrs.Items {
		resources = append(resources, Resource{
			ID:         string(csr.UID),
			Name:       csr.Name,
			Type:       "kubernetes_certificate_signing_request",
			Provider:   "kubernetes",
			Namespace:  csr.Namespace,
			Discovered: time.Now(),
			Tags:       csr.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectLeases(ctx context.Context) ([]Resource, error) {
	leases, err := c.provider.Leases()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, lease := range leases.Items {
		resources = append(resources, Resource{
			ID:         string(lease.UID),
			Name:       lease.Name,
			Type:       "kubernetes_lease",
			Provider:   "kubernetes",
			Namespace:  lease.Namespace,
			Discovered: time.Now(),
			Tags:       lease.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectComponentStatuses(ctx context.Context) ([]Resource, error) {
	statuses, err := c.provider.ComponentStatuses()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cs := range statuses.Items {
		resources = append(resources, Resource{
			ID:         string(cs.UID),
			Name:       cs.Name,
			Type:       "kubernetes_component_status",
			Provider:   "kubernetes",
			Namespace:  cs.Namespace,
			Discovered: time.Now(),
			Tags:       cs.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectFlowSchemas(ctx context.Context) ([]Resource, error) {
	fss, err := c.provider.FlowSchemas()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, fs := range fss.Items {
		resources = append(resources, Resource{
			ID:         string(fs.UID),
			Name:       fs.Name,
			Type:       "kubernetes_flow_schema",
			Provider:   "kubernetes",
			Namespace:  fs.Namespace,
			Discovered: time.Now(),
			Tags:       fs.Labels,
		})
	}
	return resources, nil
}

func (c *KubernetesCollector) collectPriorityLevelConfigurations(ctx context.Context) ([]Resource, error) {
	plcs, err := c.provider.PriorityLevelConfigurations()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, plc := range plcs.Items {
		resources = append(resources, Resource{
			ID:         string(plc.UID),
			Name:       plc.Name,
			Type:       "kubernetes_priority_level_configuration",
			Provider:   "kubernetes",
			Namespace:  plc.Namespace,
			Discovered: time.Now(),
			Tags:       plc.Labels,
		})
	}
	return resources, nil
}

// collectKinds returns a representative resource for every known resource kind.
func (c *KubernetesCollector) collectKinds(ctx context.Context) ([]Resource, error) {
	types := c.ListResourceTypes()
	var resources []Resource
	seen := make(map[string]bool)

	for _, rt := range types {
		if seen[rt.Name] {
			continue
		}
		seen[rt.Name] = true
		resources = append(resources, Resource{
			ID:         rt.Name,
			Name:       rt.Name,
			Type:       rt.Name,
			Provider:   rt.Provider,
			Service:    rt.Service,
			Discovered: time.Now(),
		})
	}
	return resources, nil
}
