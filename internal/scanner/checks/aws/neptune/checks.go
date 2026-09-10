package neptune

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type neptuneProvider interface {
	Neptune(ctx context.Context) (*neptune.Client, error)
}

// NeptuneClusterMultiAz - Neptune cluster has Multi-AZ enabled
type NeptuneClusterMultiAz struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterMultiAz() *NeptuneClusterMultiAz {
	return &NeptuneClusterMultiAz{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_multi_az",
			CheckTitle:   "Neptune cluster has Multi-AZ enabled",
			ServiceName:  "neptune",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should have Multi-AZ enabled for high availability",
			RemediationText: "Enable Multi-AZ on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterMultiAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not have Multi-AZ enabled.", clusterName)

		if aws.ToBool(cluster.MultiAZ) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s has Multi-AZ enabled.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterCopyTagsToSnapshots - Neptune cluster copies tags to snapshots
type NeptuneClusterCopyTagsToSnapshots struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterCopyTagsToSnapshots() *NeptuneClusterCopyTagsToSnapshots {
	return &NeptuneClusterCopyTagsToSnapshots{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_copy_tags_to_snapshots",
			CheckTitle:   "Neptune cluster copies tags to snapshots",
			ServiceName:  "neptune",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should copy tags to snapshots for better resource management",
			RemediationText: "Enable CopyTagsToSnapshot on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterCopyTagsToSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune DB Cluster %s is not configured to copy tags to snapshots.", clusterName)

		if aws.ToBool(cluster.CopyTagsToSnapshot) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune DB Cluster %s is configured to copy tags to snapshots.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterUsesPublicSubnet - Neptune cluster does not use public subnets
type NeptuneClusterUsesPublicSubnet struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterUsesPublicSubnet() *NeptuneClusterUsesPublicSubnet {
	return &NeptuneClusterUsesPublicSubnet{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_uses_public_subnet",
			CheckTitle:   "Neptune cluster does not use public subnets",
			ServiceName:  "neptune",
			Severity:     "high",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should not use public subnets to minimize exposure",
			RemediationText: "Move your Neptune cluster to private subnets",
			Categories:   []string{"database", "networking"},
		},
	}
}

func (c *NeptuneClusterUsesPublicSubnet) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterUsesPublicSubnet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not use public subnets.", clusterName)

		if cluster.DBSubnetGroup != nil {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Neptune Cluster %s may be using public subnets.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterIamAuthenticationEnabled - Neptune cluster has IAM authentication enabled
type NeptuneClusterIamAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterIamAuthenticationEnabled() *NeptuneClusterIamAuthenticationEnabled {
	return &NeptuneClusterIamAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_iam_authentication_enabled",
			CheckTitle:   "Neptune cluster has IAM authentication enabled",
			ServiceName:  "neptune",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should have IAM database authentication enabled",
			RemediationText: "Enable IAM database authentication on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterIamAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not have IAM authentication enabled.", clusterName)

		if aws.ToBool(cluster.IAMDatabaseAuthenticationEnabled) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s has IAM authentication enabled.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterStorageEncrypted - Neptune cluster storage is encrypted
type NeptuneClusterStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterStorageEncrypted() *NeptuneClusterStorageEncrypted {
	return &NeptuneClusterStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_storage_encrypted",
			CheckTitle:   "Neptune cluster storage is encrypted",
			ServiceName:  "neptune",
			Severity:     "high",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should have storage encryption enabled",
			RemediationText: "Enable storage encryption on your Neptune clusters",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *NeptuneClusterStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s storage is not encrypted.", clusterName)

		if aws.ToBool(cluster.StorageEncrypted) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s storage is encrypted.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterBackupEnabled - Neptune cluster has backup retention enabled
type NeptuneClusterBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterBackupEnabled() *NeptuneClusterBackupEnabled {
	return &NeptuneClusterBackupEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_backup_enabled",
			CheckTitle:   "Neptune cluster has backup retention enabled",
			ServiceName:  "neptune",
			Severity:     "medium",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should have backup retention period of at least 7 days",
			RemediationText: "Set backup retention period to at least 7 days on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not have backup enabled.", clusterName)

		if aws.ToInt32(cluster.BackupRetentionPeriod) >= 7 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s has backup retention of %d days.", clusterName, aws.ToInt32(cluster.BackupRetentionPeriod))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterPublicSnapshot - Neptune cluster snapshots are not public
type NeptuneClusterPublicSnapshot struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterPublicSnapshot() *NeptuneClusterPublicSnapshot {
	return &NeptuneClusterPublicSnapshot{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_public_snapshot",
			CheckTitle:   "Neptune cluster snapshots are not public",
			ServiceName:  "neptune",
			Severity:     "high",
			ResourceType: "Snapshot",
			Description:  "Neptune cluster snapshots should not be publicly accessible",
			RemediationText: "Remove public access from your Neptune cluster snapshots",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterPublicSnapshot) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	snapshots, err := client.DescribeDBClusterSnapshots(ctx, &neptune.DescribeDBClusterSnapshotsInput{
		SnapshotType: aws.String("manual"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune snapshots: %w", err)
	}

	for _, snapshot := range snapshots.DBClusterSnapshots {
		snapshotID := aws.ToString(snapshot.DBClusterSnapshotIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Neptune Cluster Snapshot %s is not public.", snapshotID)

		// Check if snapshot is publicly accessible
		attrs, err := client.DescribeDBClusterSnapshotAttributes(ctx, &neptune.DescribeDBClusterSnapshotAttributesInput{
			DBClusterSnapshotIdentifier: snapshot.DBClusterSnapshotIdentifier,
		})
		if err == nil {
			for _, attr := range attrs.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
				if aws.ToString(attr.AttributeName) == "restore" {
					for _, value := range attr.AttributeValues {
						if value == "all" {
							status = models.StatusFail
							statusExtended = fmt.Sprintf("Neptune Cluster Snapshot %s is public.", snapshotID)
						}
					}
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     snapshotID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterIntegrationCloudwatchLogs - Neptune cluster integrates with CloudWatch Logs
type NeptuneClusterIntegrationCloudwatchLogs struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterIntegrationCloudwatchLogs() *NeptuneClusterIntegrationCloudwatchLogs {
	return &NeptuneClusterIntegrationCloudwatchLogs{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_integration_cloudwatch_logs",
			CheckTitle:   "Neptune cluster integrates with CloudWatch Logs",
			ServiceName:  "neptune",
			Severity:     "low",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should integrate with CloudWatch Logs for monitoring",
			RemediationText: "Enable CloudWatch Logs exports on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterIntegrationCloudwatchLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not integrate with CloudWatch Logs.", clusterName)

		if cluster.EnabledCloudwatchLogsExports != nil && len(cluster.EnabledCloudwatchLogsExports) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s integrates with CloudWatch Logs.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterDeletionProtection - Neptune cluster has deletion protection
type NeptuneClusterDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterDeletionProtection() *NeptuneClusterDeletionProtection {
	return &NeptuneClusterDeletionProtection{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_deletion_protection",
			CheckTitle:   "Neptune cluster has deletion protection",
			ServiceName:  "neptune",
			Severity:     "high",
			ResourceType: "Cluster",
			Description:  "Neptune clusters should have deletion protection enabled to prevent accidental deletion",
			RemediationText: "Enable deletion protection on your Neptune clusters",
			Categories:   []string{"database"},
		},
	}
}

func (c *NeptuneClusterDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterName := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Neptune Cluster %s does not have deletion protection enabled.", clusterName)

		if aws.ToBool(cluster.DeletionProtection) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Neptune Cluster %s has deletion protection enabled.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     clusterName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// NeptuneClusterSnapshotEncrypted - Neptune cluster snapshots are encrypted
type NeptuneClusterSnapshotEncrypted struct {
	metadata models.CheckMetadata
}

func NewNeptuneClusterSnapshotEncrypted() *NeptuneClusterSnapshotEncrypted {
	return &NeptuneClusterSnapshotEncrypted{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "neptune_cluster_snapshot_encrypted",
			CheckTitle:   "Neptune cluster snapshots are encrypted",
			ServiceName:  "neptune",
			Severity:     "high",
			ResourceType: "Snapshot",
			Description:  "Neptune cluster snapshots should be encrypted",
			RemediationText: "Enable encryption on your Neptune cluster snapshots",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *NeptuneClusterSnapshotEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *NeptuneClusterSnapshotEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(neptuneProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement neptuneProvider")
	}
	client, err := p.Neptune(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	snapshots, err := client.DescribeDBClusterSnapshots(ctx, &neptune.DescribeDBClusterSnapshotsInput{
		SnapshotType: aws.String("manual"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe Neptune snapshots: %w", err)
	}

	for _, snapshot := range snapshots.DBClusterSnapshots {
		snapshotID := aws.ToString(snapshot.DBClusterSnapshotIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Neptune Cluster Snapshot %s is encrypted.", snapshotID)

		if !aws.ToBool(snapshot.StorageEncrypted) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Neptune Cluster Snapshot %s is not encrypted.", snapshotID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "neptune",
			ResourceID:     snapshotID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}