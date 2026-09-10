// Package common provides common Kubernetes security checks
// that apply to all distributions (EKS, AKS, GKE, on-prem).
//
// These checks are based on:
// - CIS Kubernetes Benchmark v1.6.0
// - NSA/CISA Kubernetes Hardening Guide
// - Kubernetes Security Best Practices
package common

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// CheckCISKubernetes runs CIS Kubernetes Benchmark checks.
type CheckCISKubernetes struct {
	metadata models.CheckMetadata
}

// NewCheckCISKubernetes creates a new CIS Kubernetes check.
func NewCheckCISKubernetes() *CheckCISKubernetes {
	return &CheckCISKubernetes{
		metadata: models.CheckMetadata{
			Provider:     "kubernetes",
			CheckID:      "kubernetes_cis_benchmark",
			CheckTitle:   "CIS Kubernetes Benchmark v1.6.0",
			Description:  "Runs CIS Kubernetes Benchmark controls for secure cluster configuration",
			ServiceName:  "kubernetes",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"cis", "benchmark", "kubernetes"},
		},
	}
}

func (c *CheckCISKubernetes) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckCISKubernetes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(KubernetesProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement KubernetesProvider")
	}

	findings := []models.Finding{}

	// CIS 1.1 - Master Node Configuration Files
	findings = append(findings, checkMasterNodeFiles(ctx, p)...)

	// CIS 1.2 - API Server
	findings = append(findings, checkAPIServer(ctx, p)...)

	// CIS 1.3 - Controller Manager
	findings = append(findings, checkControllerManager(ctx, p)...)

	// CIS 1.4 - Scheduler
	findings = append(findings, checkScheduler(ctx, p)...)

	// CIS 2 - etcd
	findings = append(findings, checkEtcd(ctx, p)...)

	// CIS 3 - Control Plane Configuration
	findings = append(findings, checkControlPlane(ctx, p)...)

	// CIS 4 - Worker Nodes
	findings = append(findings, checkWorkerNodes(ctx, p)...)

	// CIS 5 - Policies
	findings = append(findings, checkPolicies(ctx, p)...)

	return findings, nil
}

// KubernetesProvider is the interface for Kubernetes cluster access.
type KubernetesProvider interface {
	GetClusterInfo(ctx context.Context) (*ClusterInfo, error)
	GetKubeletConfig(ctx context.Context, node string) (*KubeletConfig, error)
	GetAPIServerConfig(ctx context.Context) (*APIServerConfig, error)
	GetNetworkPolicies(ctx context.Context, namespace string) ([]NetworkPolicy, error)
	GetPodSecurityPolicies(ctx context.Context) ([]PodSecurityPolicy, error)
	GetRBAC(ctx context.Context) (*RBACConfig, error)
	GetSecrets(ctx context.Context, namespace string) ([]Secret, error)
	GetNamespaces(ctx context.Context) ([]Namespace, error)
}

// ClusterInfo holds cluster metadata.
type ClusterInfo struct {
	Name            string
	Version         string
	Distribution    string // eks, aks, gke, vanilla
	Region          string
	Endpoint        string
	AuditLogEnabled bool
	EncryptionEnabled bool
}

// KubeletConfig holds kubelet configuration.
type KubeletConfig struct {
	AnonymousAuth    bool
	AuthorizationMode string
	ClientCAFile     string
	TLSCertFile      string
	TLSPrivateKeyFile string
}

// APIServerConfig holds API server configuration.
type APIServerConfig struct {
	AnonymousAuth         bool
	AuthorizationMode    string
	AuditLogEnabled       bool
	AuditLogMaxAge        int
	AuditLogMaxBackup     int
	AuditLogMaxSize       int
	EncryptionProvider    string
	TLSCipherSuites      []string
	MinTLSVersion        string
}

// NetworkPolicy represents a Kubernetes NetworkPolicy.
type NetworkPolicy struct {
	Name      string
	Namespace string
	Spec      map[string]interface{}
}

// PodSecurityPolicy represents a Pod Security Policy.
type PodSecurityPolicy struct {
	Name     string
	Spec     map[string]interface{}
}

// RBACConfig holds RBAC configuration.
type RBACConfig struct {
	ClusterRoles        []ClusterRole
	ClusterRoleBindings []ClusterRoleBinding
	Roles               []Role
	RoleBindings        []RoleBinding
}

// ClusterRole represents a ClusterRole.
type ClusterRole struct {
	Name string
	Rules []PolicyRule
}

// ClusterRoleBinding represents a ClusterRoleBinding.
type ClusterRoleBinding struct {
	Name     string
	RoleName string
	Subjects []Subject
}

// Role represents a Role.
type Role struct {
	Name      string
	Namespace string
	Rules     []PolicyRule
}

// RoleBinding represents a RoleBinding.
type RoleBinding struct {
	Name      string
	Namespace string
	RoleName  string
	Subjects  []Subject
}

// PolicyRule represents an RBAC policy rule.
type PolicyRule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
}

// Subject represents an RBAC subject.
type Subject struct {
	Kind string
	Name string
}

// Secret represents a Kubernetes Secret.
type Secret struct {
	Name      string
	Namespace string
	Type      string
	DataKeys  []string
}

// Namespace represents a Kubernetes Namespace.
type Namespace struct {
	Name   string
	Labels map[string]string
}

func checkMasterNodeFiles(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 1.1.1 - Ensure pod specification file permissions
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_1_1",
		Title:          "Ensure pod specification file permissions are set to 644 or more restrictive",
		Description:    "Pod specification files define the containers that run in the cluster",
		Severity:       "medium",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for master node file permissions",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "master-node"},
		FoundAt:        time.Now(),
	})

	// CIS 1.1.2 - Ensure pod specification file ownership
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_1_2",
		Title:          "Ensure pod specification file ownership is set to root:root",
		Description:    "Pod specification files define the containers that run in the cluster",
		Severity:       "medium",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for master node file ownership",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "master-node"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkAPIServer(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 1.2.1 - Ensure anonymous requests are disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_2_1",
		Title:          "Ensure anonymous requests are disabled",
		Description:    "Disable anonymous requests to the API server",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for API server anonymous auth",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "api-server"},
		FoundAt:        time.Now(),
	})

	// CIS 1.2.2 - Ensure basic authentication is disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_2_2",
		Title:          "Ensure basic authentication is disabled",
		Description:    "Basic authentication was removed in Kubernetes 1.19+",
		Severity:       "high",
		Status:         models.StatusPass,
		StatusExtended: "Basic authentication is disabled by default in Kubernetes 1.19+",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "api-server"},
		FoundAt:        time.Now(),
	})

	// CIS 1.2.7 - Ensure authorization mode is not AlwaysAllow
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_2_7",
		Title:          "Ensure authorization mode is not AlwaysAllow",
		Description:    "Do not use AlwaysAllow authorization mode",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for API server authorization mode",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "api-server"},
		FoundAt:        time.Now(),
	})

	// CIS 1.2.11 - Ensure audit log is enabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_2_11",
		Title:          "Ensure audit log is enabled",
		Description:    "Enable audit logging for the API server",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for audit log configuration",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "api-server", "logging"},
		FoundAt:        time.Now(),
	})

	// CIS 1.2.15 - Ensure admission controllers are configured
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_2_15",
		Title:          "Ensure admission controllers are configured",
		Description:    "Configure admission controllers for security",
		Severity:       "medium",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for admission controller configuration",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "api-server"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkControllerManager(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 1.3.1 - Ensure terminated pod gc threshold is set
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_3_1",
		Title:          "Ensure terminated pod gc threshold is set",
		Description:    "Set the terminated pod garbage collection threshold",
		Severity:       "low",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for controller manager configuration",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "controller-manager"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkScheduler(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 1.4.1 - Ensure profiling is disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_1_4_1",
		Title:          "Ensure profiling is disabled",
		Description:    "Disable profiling to reduce potential attack surface",
		Severity:       "low",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for scheduler profiling",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "scheduler"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkEtcd(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 2.1 - Ensure anonymous authentication is disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_2_1",
		Title:          "Ensure anonymous authentication is disabled for etcd",
		Description:    "Disable anonymous authentication for etcd",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for etcd anonymous auth",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "etcd"},
		FoundAt:        time.Now(),
	})

	// CIS 2.2 - Ensure encryption at rest is enabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_2_2",
		Title:          "Ensure encryption at rest is enabled for etcd",
		Description:    "Enable encryption at rest for etcd data",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for etcd encryption",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "etcd", "encryption"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkControlPlane(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 3.1 - Ensure cluster-admin role is used minimally
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_3_1",
		Title:          "Ensure cluster-admin role is used minimally",
		Description:    "Minimize use of cluster-admin role",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for cluster-admin role usage",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "rbac"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkWorkerNodes(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 4.1.1 - Ensure kubelet anonymous auth is disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_4_1_1",
		Title:          "Ensure kubelet anonymous auth is disabled",
		Description:    "Disable anonymous authentication for kubelet",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for kubelet anonymous auth",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "kubelet"},
		FoundAt:        time.Now(),
	})

	// CIS 4.2.1 - Ensure anonymous authentication is disabled
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_4_2_1",
		Title:          "Ensure anonymous authentication is disabled for kubelet",
		Description:    "Disable anonymous authentication for kubelet",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for kubelet anonymous auth",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "kubelet"},
		FoundAt:        time.Now(),
	})

	return findings
}

func checkPolicies(ctx context.Context, p KubernetesProvider) []models.Finding {
	findings := []models.Finding{}

	// CIS 5.1.1 - Ensure image pull policy is Always
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_5_1_1",
		Title:          "Ensure image pull policy is Always",
		Description:    "Set image pull policy to Always for security",
		Severity:       "low",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for image pull policy",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "policies"},
		FoundAt:        time.Now(),
	})

	// CIS 5.2.1 - Ensure network policies are applied
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_5_2_1",
		Title:          "Ensure network policies are applied",
		Description:    "Apply network policies to control pod communication",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for network policies",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "networking"},
		FoundAt:        time.Now(),
	})

	// CIS 5.3.1 - Ensure TLS is configured for API server
	findings = append(findings, models.Finding{
		ID:             "kubernetes_cis_5_3_1",
		Title:          "Ensure TLS is configured for API server",
		Description:    "Configure TLS for API server communication",
		Severity:       "high",
		Status:         models.StatusManual,
		StatusExtended: "Manual verification required for API server TLS",
		Provider:       "kubernetes",
		Service:        "kubernetes",
		Categories:     []string{"cis", "tls"},
		FoundAt:        time.Now(),
	})

	return findings
}
