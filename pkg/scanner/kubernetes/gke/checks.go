// Package gke provides GKE-specific security checks.
package gke

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CheckGKELogging checks GKE logging configuration.
type CheckGKELogging struct {
	metadata models.CheckMetadata
}

// NewCheckGKELogging creates a new GKE logging check.
func NewCheckGKELogging() *CheckGKELogging {
	return &CheckGKELogging{
		metadata: models.CheckMetadata{
			Provider:     "gcp",
			CheckID:      "gke_logging_enabled",
			CheckTitle:   "Ensure GKE logging is enabled",
			Description:  "GKE cluster should have logging enabled",
			ServiceName:  "gke",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"logging", "gke", "cis"},
		},
	}
}

func (c *CheckGKELogging) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckGKELogging) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GKEProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GKEProvider")
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
				StatusExtended: fmt.Sprintf("GKE cluster %s does not have logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
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
				StatusExtended: fmt.Sprintf("GKE cluster %s has logging enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckGKEPrivateCluster checks GKE private cluster configuration.
type CheckGKEPrivateCluster struct {
	metadata models.CheckMetadata
}

// NewCheckGKEPrivateCluster creates a new GKE private cluster check.
func NewCheckGKEPrivateCluster() *CheckGKEPrivateCluster {
	return &CheckGKEPrivateCluster{
		metadata: models.CheckMetadata{
			Provider:     "gcp",
			CheckID:      "gke_private_cluster_enabled",
			CheckTitle:   "Ensure GKE private cluster is enabled",
			Description:  "GKE cluster should use private nodes for security",
			ServiceName:  "gke",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"networking", "gke", "cis"},
		},
	}
}

func (c *CheckGKEPrivateCluster) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckGKEPrivateCluster) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GKEProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GKEProvider")
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
				StatusExtended: fmt.Sprintf("GKE cluster %s is not a private cluster", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
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
				StatusExtended: fmt.Sprintf("GKE cluster %s is a private cluster", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckGKEShieldedNodes checks GKE shielded nodes configuration.
type CheckGKEShieldedNodes struct {
	metadata models.CheckMetadata
}

// NewCheckGKEShieldedNodes creates a new GKE shielded nodes check.
func NewCheckGKEShieldedNodes() *CheckGKEShieldedNodes {
	return &CheckGKEShieldedNodes{
		metadata: models.CheckMetadata{
			Provider:     "gcp",
			CheckID:      "gke_shielded_nodes_enabled",
			CheckTitle:   "Ensure GKE shielded nodes are enabled",
			Description:  "GKE cluster should have shielded nodes enabled for security",
			ServiceName:  "gke",
			Severity:     "high",
			ResourceType: "Cluster",
			Categories:   []string{"security", "gke", "cis"},
		},
	}
}

func (c *CheckGKEShieldedNodes) Metadata() models.CheckMetadata { return c.metadata }

func (c *CheckGKEShieldedNodes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(GKEProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GKEProvider")
	}

	findings := []models.Finding{}
	clusters, err := p.ListClusters(ctx)
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if !cluster.ShieldedNodes {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("GKE cluster %s does not have shielded nodes enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
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
				StatusExtended: fmt.Sprintf("GKE cluster %s has shielded nodes enabled", cluster.Name),
				ResourceID:     cluster.Name,
				Provider:       "gcp",
				Service:        "gke",
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
	}

	return findings, nil
}

// GKEProvider is the interface for GKE cluster access.
type GKEProvider interface {
	ListClusters(ctx context.Context) ([]GKECluster, error)
	GetCluster(ctx context.Context, zone, name string) (*GKECluster, error)
}

// GKECluster represents a GKE cluster.
type GKECluster struct {
	Name            string
	ProjectID       string
	Zone            string
	Region          string
	KubernetesVersion string
	LoggingEnabled  bool
	PrivateCluster  bool
	ShieldedNodes   bool
	BinaryAuthEnabled bool
	Tags            map[string]string
}
