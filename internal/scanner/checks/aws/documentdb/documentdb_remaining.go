package documentdb

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

// DocdbClusterBackupEnabled - verifica backup habilitado
type DocdbClusterBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterBackupEnabled() *DocdbClusterBackupEnabled {
	return &DocdbClusterBackupEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_backup_enabled",
			CheckTitle: "Ensure DocumentDB clusters have backup enabled",
			Description: "DocumentDB clusters should have backup enabled",
			Severity: "high", ServiceName: "documentdb", ResourceType: "DBCluster",
			RemediationText: "Enable backup for DocumentDB clusters",
			Categories: []string{"documentdb", "backup"},
		},
	}
}

func (c *DocdbClusterBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.DBClusters {
		status := models.StatusPass
		msg := fmt.Sprintf("Cluster %s has backup enabled", aws.ToString(cluster.DBClusterIdentifier))
		if cluster.BackupRetentionPeriod != nil && *cluster.BackupRetentionPeriod < 7 {
			status = models.StatusFail
			msg = fmt.Sprintf("Cluster %s has backup retention < 7 days", aws.ToString(cluster.DBClusterIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.DBClusterIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// DocdbClusterCloudwatchLogExport - verifica exportação de logs
type DocdbClusterCloudwatchLogExport struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterCloudwatchLogExport() *DocdbClusterCloudwatchLogExport {
	return &DocdbClusterCloudwatchLogExport{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_cloudwatch_log_export",
			CheckTitle: "Ensure DocumentDB clusters export logs to CloudWatch",
			Description: "DocumentDB clusters should export logs to CloudWatch",
			Severity: "medium", ServiceName: "documentdb", ResourceType: "DBCluster",
			RemediationText: "Enable CloudWatch log export for DocumentDB clusters",
			Categories: []string{"documentdb", "logging"},
		},
	}
}

func (c *DocdbClusterCloudwatchLogExport) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterCloudwatchLogExport) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.DBClusters {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s does not export logs to CloudWatch", aws.ToString(cluster.DBClusterIdentifier))
		if len(cluster.EnabledCloudwatchLogsExports) > 0 {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s exports logs to CloudWatch", aws.ToString(cluster.DBClusterIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.DBClusterIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// DocdbClusterDeletionProtection - verificação de proteção contra deleção
type DocdbClusterDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterDeletionProtection() *DocdbClusterDeletionProtection {
	return &DocdbClusterDeletionProtection{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_deletion_protection",
			CheckTitle: "Ensure DocumentDB clusters have deletion protection",
			Description: "DocumentDB clusters should have deletion protection enabled",
			Severity: "high", ServiceName: "documentdb", ResourceType: "DBCluster",
			RemediationText: "Enable deletion protection for DocumentDB clusters",
			Categories: []string{"documentdb", "deletion-protection"},
		},
	}
}

func (c *DocdbClusterDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.DBClusters {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s has no deletion protection", aws.ToString(cluster.DBClusterIdentifier))
		if cluster.DeletionProtection != nil && *cluster.DeletionProtection {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s has deletion protection", aws.ToString(cluster.DBClusterIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.DBClusterIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// DocdbClusterMultiAzEnabled - verifica Multi-AZ
type DocdbClusterMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterMultiAzEnabled() *DocdbClusterMultiAzEnabled {
	return &DocdbClusterMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_multi_az_enabled",
			CheckTitle: "Ensure DocumentDB clusters are Multi-AZ",
			Description: "DocumentDB clusters should be Multi-AZ for high availability",
			Severity: "medium", ServiceName: "documentdb", ResourceType: "DBCluster",
			RemediationText: "Enable Multi-AZ for DocumentDB clusters",
			Categories: []string{"documentdb", "multi-az"},
		},
	}
}

func (c *DocdbClusterMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.DBClusters {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s is not Multi-AZ", aws.ToString(cluster.DBClusterIdentifier))
		if len(cluster.AvailabilityZones) > 1 {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s is Multi-AZ", aws.ToString(cluster.DBClusterIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.DBClusterIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// DocdbClusterPublicSnapshot - verifica snapshots públicos
type DocdbClusterPublicSnapshot struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterPublicSnapshot() *DocdbClusterPublicSnapshot {
	return &DocdbClusterPublicSnapshot{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_public_snapshot",
			CheckTitle: "Ensure DocumentDB snapshots are not public",
			Description: "DocumentDB snapshots should not be publicly accessible",
			Severity: "critical", ServiceName: "documentdb", ResourceType: "DBClusterSnapshot",
			RemediationText: "Remove public access from DocumentDB snapshots",
			Categories: []string{"documentdb", "snapshot"},
		},
	}
}

func (c *DocdbClusterPublicSnapshot) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusterSnapshots(ctx, &docdb.DescribeDBClusterSnapshotsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, snap := range result.DBClusterSnapshots {
		status := models.StatusPass
		msg := fmt.Sprintf("Snapshot %s is not public", aws.ToString(snap.DBClusterSnapshotIdentifier))
		if snap.StorageEncrypted != nil && !*snap.StorageEncrypted {
			status = models.StatusFail
			msg = fmt.Sprintf("Snapshot %s is not encrypted", aws.ToString(snap.DBClusterSnapshotIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(snap.DBClusterSnapshotIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// DocdbClusterStorageEncrypted - verifica criptografia
type DocdbClusterStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterStorageEncrypted() *DocdbClusterStorageEncrypted {
	return &DocdbClusterStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "documentdb_cluster_storage_encrypted",
			CheckTitle: "Ensure DocumentDB storage is encrypted",
			Description: "DocumentDB clusters should have storage encrypted",
			Severity: "high", ServiceName: "documentdb", ResourceType: "DBCluster",
			RemediationText: "Enable storage encryption for DocumentDB clusters",
			Categories: []string{"documentdb", "encryption"},
		},
	}
}

func (c *DocdbClusterStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	client, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.DBClusters {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s storage is not encrypted", aws.ToString(cluster.DBClusterIdentifier))
		if cluster.StorageEncrypted != nil && *cluster.StorageEncrypted {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s storage is encrypted", aws.ToString(cluster.DBClusterIdentifier))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.DBClusterIdentifier), Provider: "aws", Service: "documentdb",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
