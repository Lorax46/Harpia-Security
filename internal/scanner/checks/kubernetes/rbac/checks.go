package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/kubernetes"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ---- RbacClusterAdminUsageCheck ----

type RbacClusterAdminUsageCheck struct {
	metadata models.CheckMetadata
}

func NewRbacClusterAdminUsageCheck() *RbacClusterAdminUsageCheck {
	return &RbacClusterAdminUsageCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_cluster_admin_usage",
			CheckTitle:     "Minimize ClusterAdmin usage",
			Description:    "Minimize the use of ClusterAdmin role",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Use more granular roles instead of ClusterAdmin",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacClusterAdminUsageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacClusterAdminUsageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	bindings, err := kube.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, binding := range bindings.Items {
		if binding.RoleRef.Name == "cluster-admin" {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRoleBinding %s uses cluster-admin role", binding.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     binding.Name,
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
			StatusExtended: "No ClusterRoleBindings use cluster-admin role",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeCsrApprovalCheck ----

type RbacMinimizeCsrApprovalCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeCsrApprovalCheck() *RbacMinimizeCsrApprovalCheck {
	return &RbacMinimizeCsrApprovalCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_csr_approval",
			CheckTitle:     "Minimize CSR approval access",
			Description:    "Minimize access to CSR approval",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict CSR approval access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeCsrApprovalCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeCsrApprovalCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "certificatesigningrequests/approve" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "update" || verb == "create" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has CSR approval access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have CSR approval access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeNodeProxyCheck ----

type RbacMinimizeNodeProxyCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeNodeProxyCheck() *RbacMinimizeNodeProxyCheck {
	return &RbacMinimizeNodeProxyCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_node_proxy",
			CheckTitle:     "Minimize node/proxy access",
			Description:    "Minimize access to node/proxy subresource",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict node/proxy access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeNodeProxyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeNodeProxyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if strings.HasPrefix(resource, "nodes/") || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "create" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has node/proxy access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have node/proxy access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizePodCreationCheck ----

type RbacMinimizePodCreationCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizePodCreationCheck() *RbacMinimizePodCreationCheck {
	return &RbacMinimizePodCreationCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_pod_creation",
			CheckTitle:     "Minimize pod creation access",
			Description:    "Minimize access to pod creation",
			Severity:       "medium",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict pod creation access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizePodCreationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizePodCreationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "pods" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "create" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has pod creation access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have pod creation access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizePvCreationCheck ----

type RbacMinimizePvCreationCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizePvCreationCheck() *RbacMinimizePvCreationCheck {
	return &RbacMinimizePvCreationCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_pv_creation",
			CheckTitle:     "Minimize PV creation access",
			Description:    "Minimize access to persistent volume creation",
			Severity:       "medium",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict PV creation access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizePvCreationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizePvCreationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "persistentvolumes" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "create" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has PV creation access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have PV creation access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeSecretAccessCheck ----

type RbacMinimizeSecretAccessCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeSecretAccessCheck() *RbacMinimizeSecretAccessCheck {
	return &RbacMinimizeSecretAccessCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_secret_access",
			CheckTitle:     "Minimize secret access",
			Description:    "Minimize access to secrets",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict secret access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeSecretAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeSecretAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "secrets" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has secret access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have secret access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeTokenCreationCheck ----

type RbacMinimizeTokenCreationCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeTokenCreationCheck() *RbacMinimizeTokenCreationCheck {
	return &RbacMinimizeTokenCreationCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_token_creation",
			CheckTitle:     "Minimize token creation access",
			Description:    "Minimize access to serviceaccounts/token creation",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict token creation access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeTokenCreationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeTokenCreationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if resource == "serviceaccounts/token" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "create" || verb == "*" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has token creation access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have token creation access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeWebhookConfigCheck ----

type RbacMinimizeWebhookConfigCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeWebhookConfigCheck() *RbacMinimizeWebhookConfigCheck {
	return &RbacMinimizeWebhookConfigCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_webhook_config",
			CheckTitle:     "Minimize webhook config access",
			Description:    "Minimize access to webhook configurations",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Restrict webhook config access",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeWebhookConfigCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeWebhookConfigCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	sensitive := map[string]bool{
		"mutatingwebhookconfigurations":   true,
		"validatingwebhookconfigurations": true,
	}

	for _, role := range clusterRoles.Items {
		hasAccess := false
		for _, rule := range role.Rules {
			for _, resource := range rule.Resources {
				if sensitive[resource] || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "*" || verb == "update" || verb == "create" {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
			if hasAccess {
				break
			}
		}

		if hasAccess {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s has webhook config access", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles have webhook config access",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacMinimizeWildcardCheck ----

type RbacMinimizeWildcardCheck struct {
	metadata models.CheckMetadata
}

func NewRbacMinimizeWildcardCheck() *RbacMinimizeWildcardCheck {
	return &RbacMinimizeWildcardCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_minimize_wildcard",
			CheckTitle:     "No wildcard in roles",
			Description:    "Roles and ClusterRoles should not use wildcard verbs or resources",
			Severity:       "high",
			ServiceName:    "rbac",
			ResourceType:   "Role",
			RemediationText: "Avoid wildcard verbs and resources in roles",
			Categories:     []string{"rbac", "authorization"},
		},
	}
}

func (c *RbacMinimizeWildcardCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacMinimizeWildcardCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	kube, ok := provider.(*kubernetes.Provider)
	if !ok {
		return nil, fmt.Errorf("provider is not kubernetes.KubernetesProviderClient")
	}

	findings := []models.Finding{}

	clusterRoles, err := kube.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	for _, role := range clusterRoles.Items {
		hasWildcard := false
		for _, rule := range role.Rules {
			for _, verb := range rule.Verbs {
				if verb == "*" {
					hasWildcard = true
					break
				}
			}
			for _, resource := range rule.Resources {
				if resource == "*" {
					hasWildcard = true
					break
				}
			}
			if hasWildcard {
				break
			}
		}

		if hasWildcard {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("ClusterRole %s uses wildcard verbs or resources", role.Name),
				Provider:       "kubernetes",
				Service:        "rbac",
				ResourceID:     role.Name,
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
			StatusExtended: "No ClusterRoles use wildcard verbs or resources",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// ---- RbacServiceAccountTokenMountCheck ----

type RbacServiceAccountTokenMountCheck struct {
	metadata models.CheckMetadata
}

func NewRbacServiceAccountTokenMountCheck() *RbacServiceAccountTokenMountCheck {
	return &RbacServiceAccountTokenMountCheck{
		metadata: models.CheckMetadata{
			Provider:       "kubernetes",
			CheckID:        "rbac_service_account_token_mount",
			CheckTitle:     "ServiceAccount token should not be auto-mounted",
			Description:    "automountServiceAccountToken should be false",
			Severity:       "medium",
			ServiceName:    "rbac",
			ResourceType:   "ServiceAccount",
			RemediationText: "Set automountServiceAccountToken to false",
			Categories:     []string{"rbac", "authentication"},
		},
	}
}

func (c *RbacServiceAccountTokenMountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RbacServiceAccountTokenMountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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

		sas, err := kube.ListServiceAccounts(ctx, ns.Name)
		if err != nil {
			continue
		}

		for _, sa := range sas.Items {
			if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("ServiceAccount %s/%s has automountServiceAccountToken enabled", ns.Name, sa.Name),
					Provider:       "kubernetes",
					Service:        "rbac",
					ResourceID:     fmt.Sprintf("%s/%s", ns.Name, sa.Name),
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
			StatusExtended: "All ServiceAccounts have automountServiceAccountToken disabled",
			Provider:       "kubernetes",
			Service:        "rbac",
			ResourceID:     "",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
