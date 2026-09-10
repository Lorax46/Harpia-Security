package container

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/container/v1"
)

type containerProvider interface {
	Container(ctx context.Context) (*container.Service, error)
	ProjectID() string
}

// --- GKEClusterPrivateNodesCheck ---

type GKEClusterPrivateNodesCheck struct {
	metadata models.CheckMetadata
}

func NewGKEClusterPrivateNodesCheck() *GKEClusterPrivateNodesCheck {
	return &GKEClusterPrivateNodesCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gke_cluster_private_nodes",
			CheckTitle:      "GKE cluster should have private nodes",
			ServiceName:     "container",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "GKE clusters should have private nodes",
			Risk:            "Public nodes are exposed to the internet",
			RemediationText: "Enable private nodes in GKE cluster",
			RemediationURL:  "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
			Categories:      []string{"gke", "networking"},
		},
	}
}

func (c *GKEClusterPrivateNodesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GKEClusterPrivateNodesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(containerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa containerProvider")
	}
	containerService, err := p.Container(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	parent := "projects/" + p.ProjectID() + "/locations/-"
	resp, err := containerService.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		isPrivate := cluster.PrivateClusterConfig != nil && cluster.PrivateClusterConfig.EnablePrivateNodes
		status := models.StatusPass
		ext := "Cluster has private nodes"
		if !isPrivate {
			status = models.StatusFail
			ext = "Cluster does not have private nodes"
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: ext,
			Provider:       "gcp",
			Service:        "container",
			ResourceID:     cluster.Name,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// --- GKEClusterNetworkPolicyCheck ---

type GKEClusterNetworkPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewGKEClusterNetworkPolicyCheck() *GKEClusterNetworkPolicyCheck {
	return &GKEClusterNetworkPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gke_cluster_network_policy",
			CheckTitle:      "GKE cluster should have network policy enabled",
			ServiceName:     "container",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "GKE clusters should have network policy enabled",
			Risk:            "Without network policy, pods can communicate freely, increasing attack surface",
			RemediationText: "Enable network policy in GKE cluster",
			RemediationURL:  "https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy",
			Categories:      []string{"gke", "networking"},
		},
	}
}

func (c *GKEClusterNetworkPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GKEClusterNetworkPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(containerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa containerProvider")
	}
	containerService, err := p.Container(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	parent := "projects/" + p.ProjectID() + "/locations/-"
	resp, err := containerService.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		isNetworkPolicyEnabled := cluster.NetworkPolicy != nil && cluster.NetworkPolicy.Enabled
		status := models.StatusPass
		ext := "Network policy is enabled"
		if !isNetworkPolicyEnabled {
			status = models.StatusFail
			ext = "Network policy is not enabled"
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: ext,
			Provider:       "gcp",
			Service:        "container",
			ResourceID:     cluster.Name,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// --- GKEClusterPodSecurityPolicyCheck ---

type GKEClusterPodSecurityPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewGKEClusterPodSecurityPolicyCheck() *GKEClusterPodSecurityPolicyCheck {
	return &GKEClusterPodSecurityPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gke_cluster_pod_security_policy",
			CheckTitle:      "GKE cluster should have binary authorization enabled",
			ServiceName:     "container",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "GKE clusters should have binary authorization enabled for pod security",
			Risk:            "Without binary authorization, untrusted container images may be deployed",
			RemediationText: "Enable binary authorization in GKE cluster",
			RemediationURL:  "https://cloud.google.com/kubernetes-engine/docs/how-to/binary-authorization",
			Categories:      []string{"gke", "security"},
		},
	}
}

func (c *GKEClusterPodSecurityPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GKEClusterPodSecurityPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(containerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa containerProvider")
	}
	containerService, err := p.Container(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	parent := "projects/" + p.ProjectID() + "/locations/-"
	resp, err := containerService.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		isBinAuthEnabled := cluster.BinaryAuthorization != nil &&
			cluster.BinaryAuthorization.EvaluationMode != "" &&
			cluster.BinaryAuthorization.EvaluationMode != "DISABLED"
		status := models.StatusPass
		ext := "Binary authorization is enabled"
		if !isBinAuthEnabled {
			status = models.StatusFail
			ext = "Binary authorization is not enabled"
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: ext,
			Provider:       "gcp",
			Service:        "container",
			ResourceID:     cluster.Name,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// --- GKEClusterMasterAuthCheck ---

type GKEClusterMasterAuthCheck struct {
	metadata models.CheckMetadata
}

func NewGKEClusterMasterAuthCheck() *GKEClusterMasterAuthCheck {
	return &GKEClusterMasterAuthCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gke_cluster_master_auth",
			CheckTitle:      "GKE cluster should have master authentication configured",
			ServiceName:     "container",
			Severity:        "high",
			ResourceType:    "Cluster",
			Description:     "GKE clusters should have master authentication configured with client certificate",
			Risk:            "Without proper master auth, unauthorized access to the Kubernetes API is possible",
			RemediationText: "Enable client certificate authentication for GKE master",
			RemediationURL:  "https://cloud.google.com/kubernetes-engine/docs/how-to/creating-an-authorization-policy",
			Categories:      []string{"gke", "security"},
		},
	}
}

func (c *GKEClusterMasterAuthCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GKEClusterMasterAuthCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(containerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa containerProvider")
	}
	containerService, err := p.Container(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	parent := "projects/" + p.ProjectID() + "/locations/-"
	resp, err := containerService.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		isMasterAuthConfigured := cluster.MasterAuth != nil &&
			cluster.MasterAuth.ClientCertificateConfig != nil &&
			cluster.MasterAuth.ClientCertificateConfig.IssueClientCertificate
		status := models.StatusPass
		ext := "Master authentication is properly configured"
		if !isMasterAuthConfigured {
			status = models.StatusFail
			ext = "Master authentication client certificate is not configured"
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: ext,
			Provider:       "gcp",
			Service:        "container",
			ResourceID:     cluster.Name,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}

// --- GKEClusterLoggingCheck ---

type GKEClusterLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewGKEClusterLoggingCheck() *GKEClusterLoggingCheck {
	return &GKEClusterLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "gke_cluster_logging",
			CheckTitle:      "GKE cluster should have logging enabled",
			ServiceName:     "container",
			Severity:        "medium",
			ResourceType:    "Cluster",
			Description:     "GKE clusters should have logging enabled via Cloud Logging",
			Risk:            "Without logging, cluster activities are not monitored or auditable",
			RemediationText: "Enable Cloud Logging for GKE cluster",
			RemediationURL:  "https://cloud.google.com/kubernetes-engine/docs/how-to/logging",
			Categories:      []string{"gke", "logging"},
		},
	}
}

func (c *GKEClusterLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GKEClusterLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(containerProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa containerProvider")
	}
	containerService, err := p.Container(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	parent := "projects/" + p.ProjectID() + "/locations/-"
	resp, err := containerService.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		isLoggingEnabled := cluster.LoggingService != "" && cluster.LoggingService != "none"
		status := models.StatusPass
		ext := "Logging is enabled"
		if !isLoggingEnabled {
			status = models.StatusFail
			ext = "Logging is not enabled"
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: ext,
			Provider:       "gcp",
			Service:        "container",
			ResourceID:     cluster.Name,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}
	return findings, nil
}