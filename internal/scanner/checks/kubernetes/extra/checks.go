package extra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ---- NetworkPolicyDefaultDCheck ----

type NetworkPolicyDefaultDCheck struct {
	metadata models.CheckMetadata
}

func NewNetworkPolicyDefaultDCheck() *NetworkPolicyDefaultDCheck {
	return &NetworkPolicyDefaultDCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "network_policy_default_deny",
			CheckTitle:     "Default deny network policy should exist",
			Description:    "Namespaces should have a default deny network policy",
			Severity:       "high",
			ServiceName:    "extra",
			ResourceType:   "NetworkPolicy",
			RemediationText: "Create a default deny NetworkPolicy in each namespace",
			Categories:     []string{"network", "security"},
		},
	}
}

func (c *NetworkPolicyDefaultDCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkPolicyDefaultDCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	namespaces, err := kube.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if ns.Name == "kube-system" || ns.Name == "kube-public" {
			continue
		}

		nps, err := kube.ListNetworkPolicies(ctx, ns.Name)
		if err != nil {
			continue
		}

		hasDefaultDeny := false
		for _, np := range nps.Items {
			for _, policyType := range np.Spec.PolicyTypes {
				if policyType == "Ingress" || policyType == "Egress" {
					if len(np.Spec.PodSelector.MatchLabels) == 0 && len(np.Spec.PodSelector.MatchExpressions) == 0 {
						hasDefaultDeny = true
						break
					}
				}
			}
			if hasDefaultDeny {
				break
			}
		}

		if !hasDefaultDeny {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Namespace %s does not have a default deny network policy", ns.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     ns.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All namespaces have default deny network policies",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- PodSecurityPolicyRestrictedCheck ----

type PodSecurityPolicyRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewPodSecurityPolicyRestrictedCheck() *PodSecurityPolicyRestrictedCheck {
	return &PodSecurityPolicyRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "pod_security_policy_restricted",
			CheckTitle:     "PodSecurityPolicy should be restricted",
			Description:    "PodSecurityPolicy should use restricted profile",
			Severity:       "high",
			ServiceName:    "extra",
			ResourceType:   "PodSecurityPolicy",
			RemediationText: "Use restricted PodSecurityPolicy",
			Categories:     []string{"pod-security", "security"},
		},
	}
}

func (c *PodSecurityPolicyRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PodSecurityPolicyRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	findings := []models.Finding{}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         models.StatusInfo,
		StatusExtended: "PodSecurityPolicy is deprecated; use Pod Security Standards instead",
		Provider:       "kubernetes",
		Service:        "extra",
		ResourceID:     "",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
		FoundAt:        time.Now(),
	})

	return findings, nil
}

// ---- ResourceQuotaSetCheck ----

type ResourceQuotaSetCheck struct {
	metadata models.CheckMetadata
}

func NewResourceQuotaSetCheck() *ResourceQuotaSetCheck {
	return &ResourceQuotaSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "resource_quota_set",
			CheckTitle:     "Resource quotas should be set",
			Description:    "Namespaces should have resource quotas configured",
			Severity:       "medium",
			ServiceName:    "extra",
			ResourceType:   "ResourceQuota",
			RemediationText: "Set resource quotas for namespaces",
			Categories:     []string{"resource-management", "security"},
		},
	}
}

func (c *ResourceQuotaSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ResourceQuotaSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	namespaces, err := kube.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if ns.Name == "kube-system" || ns.Name == "kube-public" {
			continue
		}

		quotas, err := kube.ListResourceQuotas(ctx, ns.Name)
		if err != nil {
			continue
		}

		if len(quotas.Items) == 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Namespace %s does not have resource quotas", ns.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     ns.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All namespaces have resource quotas",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- LimitRangeSetCheck ----

type LimitRangeSetCheck struct {
	metadata models.CheckMetadata
}

func NewLimitRangeSetCheck() *LimitRangeSetCheck {
	return &LimitRangeSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "limit_range_set",
			CheckTitle:     "Limit ranges should be set",
			Description:    "Namespaces should have limit ranges configured",
			Severity:       "medium",
			ServiceName:    "extra",
			ResourceType:   "LimitRange",
			RemediationText: "Set limit ranges for namespaces",
			Categories:     []string{"resource-management", "security"},
		},
	}
}

func (c *LimitRangeSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LimitRangeSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	namespaces, err := kube.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if ns.Name == "kube-system" || ns.Name == "kube-public" {
			continue
		}

		ranges, err := kube.ListLimitRanges(ctx, ns.Name)
		if err != nil {
			continue
		}

		if len(ranges.Items) == 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Namespace %s does not have limit ranges", ns.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     ns.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All namespaces have limit ranges",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- HorizontalPodAutoscalerSetCheck ----

type HorizontalPodAutoscalerSetCheck struct {
	metadata models.CheckMetadata
}

func NewHorizontalPodAutoscalerSetCheck() *HorizontalPodAutoscalerSetCheck {
	return &HorizontalPodAutoscalerSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "horizontal_pod_autoscaler_set",
			CheckTitle:     "Horizontal Pod Autoscaler should be configured",
			Description:    "Deployments should have HPA configured",
			Severity:       "low",
			ServiceName:    "extra",
			ResourceType:   "HorizontalPodAutoscaler",
			RemediationText: "Configure HPA for deployments",
			Categories:     []string{"scalability", "performance"},
		},
	}
}

func (c *HorizontalPodAutoscalerSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HorizontalPodAutoscalerSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	namespaces, err := kube.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		if ns.Name == "kube-system" || ns.Name == "kube-public" {
			continue
		}

		hpas, err := kube.ListHorizontalPodAutoscalers(ctx, ns.Name)
		if err != nil {
			continue
		}

		if len(hpas.Items) == 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Namespace %s does not have HPA configured", ns.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     ns.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All namespaces have HPA configured",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- IngressTlsCheck ----

type IngressTlsCheck struct {
	metadata models.CheckMetadata
}

func NewIngressTlsCheck() *IngressTlsCheck {
	return &IngressTlsCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "ingress_tls",
			CheckTitle:     "Ingress should have TLS enabled",
			Description:    "Ingress resources should have TLS configured",
			Severity:       "high",
			ServiceName:    "extra",
			ResourceType:   "Ingress",
			RemediationText: "Enable TLS for Ingress resources",
			Categories:     []string{"network", "tls"},
		},
	}
}

func (c *IngressTlsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IngressTlsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	namespaces, err := kube.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	for _, ns := range namespaces.Items {
		ingresses, err := kube.ListIngresses(ctx, ns.Name)
		if err != nil {
			continue
		}

		for _, ingress := range ingresses.Items {
			if len(ingress.Spec.TLS) == 0 {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Ingress %s/%s does not have TLS configured", ns.Name, ingress.Name),
					Provider:       "kubernetes",
					Service:        "extra",
					ResourceID:     fmt.Sprintf("%s/%s", ns.Name, ingress.Name),
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All Ingress resources have TLS enabled",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- StorageClassEncryptionCheck ----

type StorageClassEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewStorageClassEncryptionCheck() *StorageClassEncryptionCheck {
	return &StorageClassEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "storage_class_encryption",
			CheckTitle:     "Storage classes should have encryption enabled",
			Description:    "Storage classes should use encryption",
			Severity:       "high",
			ServiceName:    "extra",
			ResourceType:   "StorageClass",
			RemediationText: "Enable encryption for storage classes",
			Categories:     []string{"storage", "encryption"},
		},
	}
}

func (c *StorageClassEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *StorageClassEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	storageClasses, err := kube.ListStorageClasses(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage classes: %w", err)
	}

	for _, sc := range storageClasses.Items {
		hasEncryption := false
		if sc.Parameters != nil {
			for _, v := range sc.Parameters {
				if strings.Contains(strings.ToLower(v), "encrypt") {
					hasEncryption = true
					break
				}
			}
		}

		if !hasEncryption {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("StorageClass %s does not have encryption enabled", sc.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     sc.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All StorageClasses have encryption enabled",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- PersistentVolumeEncryptionCheck ----

type PersistentVolumeEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewPersistentVolumeEncryptionCheck() *PersistentVolumeEncryptionCheck {
	return &PersistentVolumeEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "persistent_volume_encryption",
			CheckTitle:     "Persistent volumes should have encryption enabled",
			Description:    "Persistent volumes should use encryption",
			Severity:       "high",
			ServiceName:    "extra",
			ResourceType:   "PersistentVolume",
			RemediationText: "Enable encryption for persistent volumes",
			Categories:     []string{"storage", "encryption"},
		},
	}
}

func (c *PersistentVolumeEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PersistentVolumeEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pvs, err := kube.ListPersistentVolumes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list persistent volumes: %w", err)
	}

	for _, pv := range pvs.Items {
		hasEncryption := false
		if pv.Spec.CSI != nil && pv.Spec.CSI.VolumeAttributes != nil {
			for _, v := range pv.Spec.CSI.VolumeAttributes {
				if strings.Contains(strings.ToLower(v), "encrypt") {
					hasEncryption = true
					break
				}
			}
		}

		if !hasEncryption {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("PersistentVolume %s does not have encryption enabled", pv.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     pv.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All PersistentVolumes have encryption enabled",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- ServiceAccountTokenAutoMountCheck ----

type ServiceAccountTokenAutoMountCheck struct {
	metadata models.CheckMetadata
}

func NewServiceAccountTokenAutoMountCheck() *ServiceAccountTokenAutoMountCheck {
	return &ServiceAccountTokenAutoMountCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "service_account_token_auto_mount",
			CheckTitle:     "ServiceAccount token auto-mount should be disabled",
			Description:    "automountServiceAccountToken should be false",
			Severity:       "medium",
			ServiceName:    "extra",
			ResourceType:   "ServiceAccount",
			RemediationText: "Set automountServiceAccountToken to false",
			Categories:     []string{"authentication", "security"},
		},
	}
}

func (c *ServiceAccountTokenAutoMountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServiceAccountTokenAutoMountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	pods, err := kube.ListPods(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		if pod.Spec.AutomountServiceAccountToken != nil && !*pod.Spec.AutomountServiceAccountToken {
			continue
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: fmt.Sprintf("Pod %s/%s has automountServiceAccountToken enabled", pod.Namespace, pod.Name),
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All pods have automountServiceAccountToken disabled",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- NodeTaintSetCheck ----

type NodeTaintSetCheck struct {
	metadata models.CheckMetadata
}

func NewNodeTaintSetCheck() *NodeTaintSetCheck {
	return &NodeTaintSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "node_taint_set",
			CheckTitle:     "Nodes should have taints set",
			Description:    "Nodes should have taints to control pod scheduling",
			Severity:       "low",
			ServiceName:    "extra",
			ResourceType:   "Node",
			RemediationText: "Set taints on nodes for better pod placement control",
			Categories:     []string{"scheduling", "security"},
		},
	}
}

func (c *NodeTaintSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NodeTaintSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	nodes, err := kube.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	for _, node := range nodes.Items {
		if len(node.Spec.Taints) == 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("Node %s does not have taints set", node.Name),
				Provider:       "kubernetes",
				Service:        "extra",
				ResourceID:     node.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All nodes have taints set",
			Provider:       "kubernetes",
			Service:        "extra",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- PodDisruptionBudgetSetCheck ----

type PodDisruptionBudgetSetCheck struct {
	metadata models.CheckMetadata
}

func NewPodDisruptionBudgetSetCheck() *PodDisruptionBudgetSetCheck {
	return &PodDisruptionBudgetSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "pod_disruption_budget_set",
			CheckTitle:     "Pod Disruption Budget should be configured",
			Description:    "Deployments should have PDB configured",
			Severity:       "medium",
			ServiceName:    "extra",
			ResourceType:   "PodDisruptionBudget",
			RemediationText: "Configure PDB for deployments",
			Categories:     []string{"availability", "security"},
		},
	}
}

func (c *PodDisruptionBudgetSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PodDisruptionBudgetSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	findings := []models.Finding{}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         models.StatusInfo,
		StatusExtended: "PodDisruptionBudget check requires access to policy/v1 API",
		Provider:       "kubernetes",
		Service:        "extra",
		ResourceID:     "",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
		FoundAt:        time.Now(),
	})

	return findings, nil
}

// ---- PriorityClassSetCheck ----

type PriorityClassSetCheck struct {
	metadata models.CheckMetadata
}

func NewPriorityClassSetCheck() *PriorityClassSetCheck {
	return &PriorityClassSetCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "priority_class_set",
			CheckTitle:     "Priority classes should be configured",
			Description:    "Cluster should have custom priority classes",
			Severity:       "low",
			ServiceName:    "extra",
			ResourceType:   "PriorityClass",
			RemediationText: "Configure priority classes for workloads",
			Categories:     []string{"scheduling", "performance"},
		},
	}
}

func (c *PriorityClassSetCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PriorityClassSetCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	findings := []models.Finding{}

	findings = append(findings, models.Finding{
		ID:             c.metadata.CheckID,
		Title:          c.metadata.CheckTitle,
		Description:    c.metadata.Description,
		Severity:       c.metadata.Severity,
		Status:         models.StatusInfo,
		StatusExtended: "PriorityClass check requires access to scheduling/v1 API",
		Provider:       "kubernetes",
		Service:        "extra",
		ResourceID:     "",
		Remediation:    c.metadata.RemediationText,
		Categories:     c.metadata.Categories,
		FoundAt:        time.Now(),
	})

	return findings, nil
}
