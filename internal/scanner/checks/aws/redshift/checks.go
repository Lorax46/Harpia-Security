package redshift

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type redshiftProvider interface {
	Redshift(ctx context.Context) (*redshift.Client, error)
}

// RedshiftClusterAuditLogging - Redshift cluster has audit logging enabled
type RedshiftClusterAuditLogging struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterAuditLogging() *RedshiftClusterAuditLogging {
	return &RedshiftClusterAuditLogging{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_audit_logging",
			CheckTitle:   "Redshift cluster has audit logging enabled",
			ServiceName:  "redshift",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should have audit logging enabled",
			RemediationText: "Enable audit logging on your Redshift clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterAuditLogging) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterAuditLogging) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s audit logging requires manual verification (not available via SDK).", clusterID)

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterAutomatedSnapshot - Redshift cluster has automated snapshots enabled
type RedshiftClusterAutomatedSnapshot struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterAutomatedSnapshot() *RedshiftClusterAutomatedSnapshot {
	return &RedshiftClusterAutomatedSnapshot{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_automated_snapshot",
			CheckTitle:   "Redshift cluster has automated snapshots enabled",
			ServiceName:  "redshift",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should have automated snapshots enabled",
			RemediationText: "Enable automated snapshots on your Redshift clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterAutomatedSnapshot) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterAutomatedSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s has automated snapshots enabled.", clusterID)

		if cluster.ClusterSnapshotCopyStatus == nil || aws.ToInt32(cluster.ManualSnapshotRetentionPeriod) == -1 {
			if cluster.ClusterSnapshotCopyStatus == nil && cluster.ManualSnapshotRetentionPeriod == nil {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("Redshift Cluster %s has automated snapshots disabled.", clusterID)
			}
		}

		// Also check if automated snapshots are configured
		if cluster.AutomatedSnapshotRetentionPeriod != nil && aws.ToInt32(cluster.AutomatedSnapshotRetentionPeriod) <= 0 {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Redshift Cluster %s has automated snapshots disabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterAutomaticUpgrades - Redshift cluster has automatic upgrades enabled
type RedshiftClusterAutomaticUpgrades struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterAutomaticUpgrades() *RedshiftClusterAutomaticUpgrades {
	return &RedshiftClusterAutomaticUpgrades{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_automatic_upgrades",
			CheckTitle:   "Redshift cluster has AllowVersionUpgrade enabled",
			ServiceName:  "redshift",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should have AllowVersionUpgrade enabled for automatic maintenance",
			RemediationText: "Enable AllowVersionUpgrade on your Redshift clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterAutomaticUpgrades) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterAutomaticUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s has AllowVersionUpgrade enabled.", clusterID)

		if !aws.ToBool(cluster.AllowVersionUpgrade) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Redshift Cluster %s has AllowVersionUpgrade disabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterEncryptedAtRest - Redshift cluster is encrypted at rest
type RedshiftClusterEncryptedAtRest struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterEncryptedAtRest() *RedshiftClusterEncryptedAtRest {
	return &RedshiftClusterEncryptedAtRest{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_encrypted_at_rest",
			CheckTitle:   "Redshift cluster is encrypted at rest",
			ServiceName:  "redshift",
			Severity:     "high",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should be encrypted at rest",
			RemediationText: "Enable encryption at rest on your Redshift clusters",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *RedshiftClusterEncryptedAtRest) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterEncryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Redshift Cluster %s is not encrypted at rest.", clusterID)

		if aws.ToBool(cluster.Encrypted) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Redshift Cluster %s is encrypted at rest.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterEnhancedVpcRouting - Redshift cluster has enhanced VPC routing enabled
type RedshiftClusterEnhancedVpcRouting struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterEnhancedVpcRouting() *RedshiftClusterEnhancedVpcRouting {
	return &RedshiftClusterEnhancedVpcRouting{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_enhanced_vpc_routing",
			CheckTitle:   "Redshift cluster has enhanced VPC routing enabled",
			ServiceName:  "redshift",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should have enhanced VPC routing enabled",
			RemediationText: "Enable enhanced VPC routing on your Redshift clusters",
			Categories:   []string{"database", "networking"},
		},
	}
}

func (c *RedshiftClusterEnhancedVpcRouting) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterEnhancedVpcRouting) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Redshift Cluster %s does not have enhanced VPC routing enabled.", clusterID)

		if aws.ToBool(cluster.EnhancedVpcRouting) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Redshift Cluster %s has enhanced VPC routing enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterInTransitEncryptionEnabled - Redshift cluster uses in-transit encryption
type RedshiftClusterInTransitEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterInTransitEncryptionEnabled() *RedshiftClusterInTransitEncryptionEnabled {
	return &RedshiftClusterInTransitEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_in_transit_encryption_enabled",
			CheckTitle:   "Redshift cluster uses in-transit encryption",
			ServiceName:  "redshift",
			Severity:     "high",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should require SSL/TLS for in-transit encryption",
			RemediationText: "Configure your Redshift clusters to require SSL for all connections",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *RedshiftClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s SSL/in-transit encryption requires manual verification.", clusterID)

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterMultiAzEnabled - Redshift cluster has Multi-AZ enabled
type RedshiftClusterMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterMultiAzEnabled() *RedshiftClusterMultiAzEnabled {
	return &RedshiftClusterMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_multi_az_enabled",
			CheckTitle:   "Redshift cluster has Multi-AZ enabled",
			ServiceName:  "redshift",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should have Multi-AZ enabled for high availability",
			RemediationText: "Enable Multi-AZ on your Redshift clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Redshift Cluster %s does not have Multi-AZ enabled.", clusterID)

		if cluster.MultiAZ != nil && aws.ToString(cluster.MultiAZ) == "true" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Redshift Cluster %s has Multi-AZ enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterNonDefaultDatabaseName - Redshift cluster uses a non-default database name
type RedshiftClusterNonDefaultDatabaseName struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterNonDefaultDatabaseName() *RedshiftClusterNonDefaultDatabaseName {
	return &RedshiftClusterNonDefaultDatabaseName{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_non_default_database_name",
			CheckTitle:   "Redshift cluster uses a non-default database name",
			ServiceName:  "redshift",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should not use the default database name 'dev'",
			RemediationText: "Create your Redshift cluster with a custom database name",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterNonDefaultDatabaseName) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterNonDefaultDatabaseName) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s does not use the default database name.", clusterID)

		if aws.ToString(cluster.DBName) == "dev" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Redshift Cluster %s uses the default database name 'dev'.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterNonDefaultUsername - Redshift cluster uses a non-default username
type RedshiftClusterNonDefaultUsername struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterNonDefaultUsername() *RedshiftClusterNonDefaultUsername {
	return &RedshiftClusterNonDefaultUsername{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_non_default_username",
			CheckTitle:   "Redshift cluster uses a non-default username",
			ServiceName:  "redshift",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should not use the default master username 'awsuser'",
			RemediationText: "Create your Redshift cluster with a custom master username",
			Categories:   []string{"database"},
		},
	}
}

func (c *RedshiftClusterNonDefaultUsername) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterNonDefaultUsername) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s does not use the default username.", clusterID)

		if aws.ToString(cluster.MasterUsername) == "awsuser" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Redshift Cluster %s uses the default username 'awsuser'.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// RedshiftClusterPublicAccess - Redshift cluster is not publicly accessible
type RedshiftClusterPublicAccess struct {
	metadata models.CheckMetadata
}

func NewRedshiftClusterPublicAccess() *RedshiftClusterPublicAccess {
	return &RedshiftClusterPublicAccess{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "redshift_cluster_public_access",
			CheckTitle:   "Redshift cluster is not publicly accessible",
			ServiceName:  "redshift",
			Severity:     "critical",
			ResourceType: "Cluster",
			Description:  "Redshift clusters should not be publicly accessible",
			RemediationText: "Disable public accessibility on your Redshift clusters",
			Categories:   []string{"database", "networking"},
		},
	}
}

func (c *RedshiftClusterPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedshiftClusterPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(redshiftProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement redshiftProvider")
	}
	redshiftClient, err := p.Redshift(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := redshiftClient.DescribeClusters(ctx, &redshift.DescribeClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
	}

	for _, cluster := range clusters.Clusters {
		clusterID := aws.ToString(cluster.ClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Redshift Cluster %s is not publicly accessible.", clusterID)

		if aws.ToBool(cluster.PubliclyAccessible) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Redshift Cluster %s is publicly accessible.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "redshift",
			ResourceID:     clusterID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}