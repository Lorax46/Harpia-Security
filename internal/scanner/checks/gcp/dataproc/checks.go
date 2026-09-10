package dataproc

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"google.golang.org/api/dataproc/v1"
)

type dataprocProvider interface {
	Dataproc(ctx context.Context) (*dataproc.Service, error)
	ProjectID() string
	Region() string
}

// =============================================================================
// 1. DataprocClusterEncryptionCheck - Verifica se o cluster usa CMEK encryption
// =============================================================================

type DataprocClusterEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewDataprocClusterEncryptionCheck() *DataprocClusterEncryptionCheck {
	return &DataprocClusterEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "dataproc_cluster_encryption",
			CheckTitle:     "Dataproc cluster should use CMEK encryption",
			ServiceName:    "dataproc",
			Severity:       "high",
			ResourceType:   "Cluster",
			Description:    "Dataproc clusters should use CMEK encryption",
			RemediationText: "Enable CMEK encryption for Dataproc clusters",
			Categories:     []string{"dataproc", "encryption"},
		},
	}
}

func (c *DataprocClusterEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataprocClusterEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dataprocProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dataprocProvider")
	}
	dataprocService, err := p.Dataproc(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dataprocService.Projects.Regions.Clusters.List(p.ProjectID(), p.Region())
	err = req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
		for _, cluster := range page.Clusters {
			hasEncryption := cluster.Config.EncryptionConfig.GcePdKmsKeyName != ""
			status := models.StatusPass
			ext := "Cluster uses CMEK encryption"
			if !hasEncryption {
				status = models.StatusFail
				ext = "Cluster does not use CMEK encryption"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dataproc",
				ResourceID:     cluster.ClusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// =============================================================================
// 2. DataprocClusterPublicAccessCheck - Verifica se o cluster tem IP público
// =============================================================================

type DataprocClusterPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewDataprocClusterPublicAccessCheck() *DataprocClusterPublicAccessCheck {
	return &DataprocClusterPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "dataproc_cluster_public_access",
			CheckTitle:     "Dataproc cluster should not have public IP addresses",
			ServiceName:    "dataproc",
			Severity:       "critical",
			ResourceType:   "Cluster",
			Description:    "Dataproc clusters should not have public IP addresses",
			RemediationText: "Disable public IP addresses on Dataproc clusters by enabling InternalIpOnly",
			Categories:     []string{"dataproc", "network", "public_access"},
		},
	}
}

func (c *DataprocClusterPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataprocClusterPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dataprocProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dataprocProvider")
	}
	dataprocService, err := p.Dataproc(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dataprocService.Projects.Regions.Clusters.List(p.ProjectID(), p.Region())
	err = req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
		for _, cluster := range page.Clusters {
			isInternalOnly := cluster.Config.GceClusterConfig.InternalIpOnly
			status := models.StatusPass
			ext := "Cluster does not have public IP addresses (InternalIpOnly enabled)"
			if !isInternalOnly {
				status = models.StatusFail
				ext = "Cluster has public IP addresses (InternalIpOnly not enabled)"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dataproc",
				ResourceID:     cluster.ClusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// =============================================================================
// 3. DataprocClusterLoggingCheck - Verifica se o cluster tem logging habilitado
// =============================================================================

type DataprocClusterLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewDataprocClusterLoggingCheck() *DataprocClusterLoggingCheck {
	return &DataprocClusterLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "dataproc_cluster_logging",
			CheckTitle:     "Dataproc cluster should have Cloud Logging enabled",
			ServiceName:    "dataproc",
			Severity:       "medium",
			ResourceType:   "Cluster",
			Description:    "Dataproc clusters should have Cloud Logging enabled",
			RemediationText: "Enable Cloud Logging for Dataproc clusters",
			Categories:     []string{"dataproc", "logging", "monitoring"},
		},
	}
}

func (c *DataprocClusterLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataprocClusterLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dataprocProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dataprocProvider")
	}
	dataprocService, err := p.Dataproc(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dataprocService.Projects.Regions.Clusters.List(p.ProjectID(), p.Region())
	err = req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
		for _, cluster := range page.Clusters {
			hasLogging := false
			if cluster.Config.SoftwareConfig != nil && cluster.Config.SoftwareConfig.Properties != nil {
				loggingProp, exists := cluster.Config.SoftwareConfig.Properties["dataproc:dataproc.logging.stackdriver.enable"]
				hasLogging = exists && loggingProp == "true"
			}
			status := models.StatusPass
			ext := "Cluster has Cloud Logging enabled"
			if !hasLogging {
				status = models.StatusFail
				ext = "Cluster does not have Cloud Logging enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dataproc",
				ResourceID:     cluster.ClusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// =============================================================================
// 4. DataprocClusterNetworkCheck - Verifica se o cluster usa rede dedicada
// =============================================================================

type DataprocClusterNetworkCheck struct {
	metadata models.CheckMetadata
}

func NewDataprocClusterNetworkCheck() *DataprocClusterNetworkCheck {
	return &DataprocClusterNetworkCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "dataproc_cluster_network",
			CheckTitle:     "Dataproc cluster should use a dedicated VPC network",
			ServiceName:    "dataproc",
			Severity:       "high",
			ResourceType:   "Cluster",
			Description:    "Dataproc clusters should use a dedicated VPC network",
			RemediationText: "Configure Dataproc clusters to use a dedicated VPC network",
			Categories:     []string{"dataproc", "network", "vpc"},
		},
	}
}

func (c *DataprocClusterNetworkCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataprocClusterNetworkCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dataprocProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dataprocProvider")
	}
	dataprocService, err := p.Dataproc(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dataprocService.Projects.Regions.Clusters.List(p.ProjectID(), p.Region())
	err = req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
		for _, cluster := range page.Clusters {
			hasDedicatedNetwork := cluster.Config.GceClusterConfig.NetworkUri != "" && cluster.Config.GceClusterConfig.NetworkUri != "default"
			status := models.StatusPass
			ext := "Cluster uses a dedicated VPC network"
			if !hasDedicatedNetwork {
				status = models.StatusFail
				ext = "Cluster does not use a dedicated VPC network"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dataproc",
				ResourceID:     cluster.ClusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// =============================================================================
// 5. DataprocClusterAutoscalingCheck - Verifica se o cluster tem autoscaling habilitado
// =============================================================================

type DataprocClusterAutoscalingCheck struct {
	metadata models.CheckMetadata
}

func NewDataprocClusterAutoscalingCheck() *DataprocClusterAutoscalingCheck {
	return &DataprocClusterAutoscalingCheck{
		metadata: models.CheckMetadata{
			Provider:       "gcp",
			CheckID:        "dataproc_cluster_autoscaling",
			CheckTitle:     "Dataproc cluster should have autoscaling enabled",
			ServiceName:    "dataproc",
			Severity:       "medium",
			ResourceType:   "Cluster",
			Description:    "Dataproc clusters should have autoscaling enabled",
			RemediationText: "Enable autoscaling for Dataproc clusters",
			Categories:     []string{"dataproc", "autoscaling", "performance"},
		},
	}
}

func (c *DataprocClusterAutoscalingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataprocClusterAutoscalingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dataprocProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa dataprocProvider")
	}
	dataprocService, err := p.Dataproc(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := dataprocService.Projects.Regions.Clusters.List(p.ProjectID(), p.Region())
	err = req.Pages(ctx, func(page *dataproc.ListClustersResponse) error {
		for _, cluster := range page.Clusters {
			hasAutoscaling := cluster.Config.AutoscalingConfig != nil && cluster.Config.AutoscalingConfig.PolicyUri != ""
			status := models.StatusPass
			ext := "Cluster has autoscaling enabled"
			if !hasAutoscaling {
				status = models.StatusFail
				ext = "Cluster does not have autoscaling enabled"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "dataproc",
				ResourceID:     cluster.ClusterName,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}