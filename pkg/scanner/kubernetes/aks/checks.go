// Package aks provides AKS-specific security checks.
package aks

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CheckAKSLogging checks AKS logging configuration.
type CheckAKSLogging struct {
	metadata models.CheckMetadata
}

// NewCheckAKSLogging creates a new AKS logging check.
func NewCheckAKSLogging() *CheckAKSLogging {
	return &CheckAKSLogging{
		metadata: models.CheckMetadata{
			Provider:     "azure",
			CheckID:      "aks_logging_enabled",
			CheckTitle:   "Ensure AKS logging is enabled",
			Description:  "AKS cluster should have monitoring and logging enabled",
			ServiceName:  "aks",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"logging", "aks", "cis"},
		},
	}
}

func (c *CheckAKSLogging) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckAKSLogging) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(AKSProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement AKSProvider")
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
				StatusExtended: fmt.Sprintf("AKS cluster %s does not have logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "azure",
				Service:        "aks",
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
				StatusExtended: fmt.Sprintf("AKS cluster %s has logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "azure",
				Service:        "aks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckAKSPrivateEndpoint checks AKS private cluster configuration.
type CheckAKSPrivateEndpoint struct {
	metadata models.CheckMetadata
}

// NewCheckAKSPrivateEndpoint creates a new AKS private endpoint check.
func NewCheckAKSPrivateEndpoint() *CheckAKSPrivateEndpoint {
	return &CheckAKSPrivateEndpoint{
		metadata: models.CheckMetadata{
			Provider:     "azure",
			CheckID:      "aks_private_cluster_enabled",
			CheckTitle:   "Ensure AKS private cluster is enabled",
			Description:  "AKS cluster should use private cluster for security",
			ServiceName:  "aks",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"networking", "aks", "cis"},
		},
	}
}

func (c *CheckAKSPrivateEndpoint) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckAKSPrivateEndpoint) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(AKSProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement AKSProvider")
	}

	findings := []models.Finding{}
	clusters, err := p.ListClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if !cluster.PrivateCluster {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("AKS cluster %s is not a private cluster", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "azure",
				Service:        "aks",
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
				StatusExtended: fmt.Sprintf("AKS cluster %s is a private cluster", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "azure",
				Service:        "aks",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// AKSProvider is the interface for AKS cluster access.
type AKSProvider interface {
	ListClusters(ctx context.Context) ([]AKSCluster, error)
	GetCluster(ctx context.Context, rg, name string) (*AKSCluster, error)
}

// AKSCluster represents an AKS cluster.
type AKSCluster struct {
	Name           string
	ResourceGroup  string
	Location       string
	KubernetesVersion string
	LoggingEnabled bool
	PrivateCluster bool
	Tags           map[string]string
}
