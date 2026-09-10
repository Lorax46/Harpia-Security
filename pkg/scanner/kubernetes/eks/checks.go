// Package eks provides EKS-specific security checks.
package eks

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// CheckEKSControlPlaneLogging checks EKS control plane logging.
type CheckEKSControlPlaneLogging struct {
	metadata models.CheckMetadata
}

// NewCheckEKSControlPlaneLogging creates a new EKS control plane logging check.
func NewCheckEKSControlPlaneLogging() *CheckEKSControlPlaneLogging {
	return &CheckEKSControlPlaneLogging{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "eks_control_plane_logging_enabled",
			CheckTitle:   "Ensure EKS control plane logging is enabled",
			Description:  "EKS control plane logging should be enabled for audit and API server logs",
			ServiceName:  "eks",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"logging", "eks", "cis"},
		},
	}
}

func (c *CheckEKSControlPlaneLogging) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckEKSControlPlaneLogging) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(EKSProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EKSProvider")
	}

	findings := []models.Finding{}
	clusters, err := p.ListClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if !cluster.LoggingEnabled {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("EKS cluster %s does not have control plane logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("EKS cluster %s has control plane logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckEKSPrivateEndpoint checks EKS private endpoint configuration.
type CheckEKSPrivateEndpoint struct {
	metadata models.CheckMetadata
}

// NewCheckEKSPrivateEndpoint creates a new EKS private endpoint check.
func NewCheckEKSPrivateEndpoint() *CheckEKSPrivateEndpoint {
	return &CheckEKSPrivateEndpoint{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "eks_private_endpoint_enabled",
			CheckTitle:   "Ensure EKS private endpoint is enabled",
			Description:  "EKS cluster endpoint should be private for security",
			ServiceName:  "eks",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"networking", "eks", "cis"},
		},
	}
}

func (c *CheckEKSPrivateEndpoint) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckEKSPrivateEndpoint) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(EKSProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EKSProvider")
	}

	findings := []models.Finding{}
	clusters, err := p.ListClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if !cluster.PrivateEndpoint {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("EKS cluster %s does not have private endpoint enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("EKS cluster %s has private endpoint enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckEKSEncryption checks EKS encryption configuration.
type CheckEKSEncryption struct {
	metadata models.CheckMetadata
}

// NewCheckEKSEncryption creates a new EKS encryption check.
func NewCheckEKSEncryption() *CheckEKSEncryption {
	return &CheckEKSEncryption{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "eks_encryption_enabled",
			CheckTitle:   "Ensure EKS encryption is enabled",
			Description:  "EKS cluster should have encryption enabled for secrets",
			ServiceName:  "eks",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"encryption", "eks", "cis"},
		},
	}
}

func (c *CheckEKSEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckEKSEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(EKSProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EKSProvider")
	}

	findings := []models.Finding{}
	clusters, err := p.ListClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if !cluster.EncryptionEnabled {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("EKS cluster %s does not have encryption enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("EKS cluster %s has encryption enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "aws",
				Service:        "eks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// EKSProvider is the interface for EKS cluster access.
type EKSProvider interface {
	ListClusters(ctx context.Context) ([]EKSCluster, error)
	GetCluster(ctx context.Context, name string) (*EKSCluster, error)
}

// EKSCluster represents an EKS cluster.
type EKSCluster struct {
	Name             string
	Region           string
	Version          string
	Status           string
	LoggingEnabled   bool
	PrivateEndpoint  bool
	EncryptionEnabled bool
	Tags             map[string]string
}
