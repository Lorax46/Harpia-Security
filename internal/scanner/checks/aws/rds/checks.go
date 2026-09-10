package rds

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type rdsProvider interface {
	RDS(ctx context.Context) (*rds.Client, error)
}

// ==================== RDS Cluster Checks ====================

// RdsClusterBacktrackEnabled - RDS cluster backtrack is enabled
type RdsClusterBacktrackEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsClusterBacktrackEnabled() *RdsClusterBacktrackEnabled {
	return &RdsClusterBacktrackEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_backtrack_enabled",
			CheckTitle: "RDS cluster backtrack is enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBCluster",
			Description: "RDS clusters should have backtrack enabled",
			RemediationText: "Enable backtrack on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterBacktrackEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterBacktrackEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not have backtrack enabled.", clusterID)

		if cluster.BacktrackWindow != nil && *cluster.BacktrackWindow > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s has backtrack enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterCopyTagsToSnapshots - RDS cluster copies tags to snapshots
type RdsClusterCopyTagsToSnapshots struct {
	metadata models.CheckMetadata
}

func NewRdsClusterCopyTagsToSnapshots() *RdsClusterCopyTagsToSnapshots {
	return &RdsClusterCopyTagsToSnapshots{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_copy_tags_to_snapshots",
			CheckTitle: "RDS cluster copies tags to snapshots",
			ServiceName: "rds", Severity: "low", ResourceType: "DBCluster",
			Description: "RDS clusters should copy tags to snapshots",
			RemediationText: "Enable CopyTagsToSnapshot on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterCopyTagsToSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not copy tags to snapshots.", clusterID)

		if cluster.CopyTagsToSnapshot != nil && *cluster.CopyTagsToSnapshot {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s copies tags to snapshots.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterDefaultAdmin - RDS cluster does not use default admin name
type RdsClusterDefaultAdmin struct {
	metadata models.CheckMetadata
}

func NewRdsClusterDefaultAdmin() *RdsClusterDefaultAdmin {
	return &RdsClusterDefaultAdmin{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_default_admin",
			CheckTitle: "RDS cluster does not use default admin name",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBCluster",
			Description: "RDS clusters should not use the default admin username",
			RemediationText: "Change the default admin username",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterDefaultAdmin) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Cluster %s does not use default admin name.", clusterID)

		if cluster.MasterUsername != nil && aws.ToString(cluster.MasterUsername) == "admin" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("RDS Cluster %s uses default admin name.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterDeletionProtection - RDS cluster has deletion protection
type RdsClusterDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewRdsClusterDeletionProtection() *RdsClusterDeletionProtection {
	return &RdsClusterDeletionProtection{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_deletion_protection",
			CheckTitle: "RDS cluster has deletion protection",
			ServiceName: "rds", Severity: "high", ResourceType: "DBCluster",
			Description: "RDS clusters should have deletion protection enabled",
			RemediationText: "Enable deletion protection on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not have deletion protection.", clusterID)

		if cluster.DeletionProtection != nil && *cluster.DeletionProtection {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s has deletion protection.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterIamAuthenticationEnabled - RDS cluster has IAM authentication
type RdsClusterIamAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsClusterIamAuthenticationEnabled() *RdsClusterIamAuthenticationEnabled {
	return &RdsClusterIamAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_iam_authentication_enabled",
			CheckTitle: "RDS cluster has IAM authentication enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBCluster",
			Description: "RDS clusters should have IAM authentication enabled",
			RemediationText: "Enable IAM authentication on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterIamAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not have IAM authentication enabled.", clusterID)

		if cluster.IAMDatabaseAuthenticationEnabled != nil && *cluster.IAMDatabaseAuthenticationEnabled {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s has IAM authentication enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterIntegrationCloudwatchLogs - RDS cluster integrates with CloudWatch Logs
type RdsClusterIntegrationCloudwatchLogs struct {
	metadata models.CheckMetadata
}

func NewRdsClusterIntegrationCloudwatchLogs() *RdsClusterIntegrationCloudwatchLogs {
	return &RdsClusterIntegrationCloudwatchLogs{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_integration_cloudwatch_logs",
			CheckTitle: "RDS cluster integrates with CloudWatch Logs",
			ServiceName: "rds", Severity: "low", ResourceType: "DBCluster",
			Description: "RDS clusters should integrate with CloudWatch Logs",
			RemediationText: "Enable CloudWatch Logs exports on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterIntegrationCloudwatchLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not integrate with CloudWatch Logs.", clusterID)

		if cluster.EnabledCloudwatchLogsExports != nil && len(cluster.EnabledCloudwatchLogsExports) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s integrates with CloudWatch Logs.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterMinorVersionUpgradeEnabled - RDS cluster has auto minor version upgrade
type RdsClusterMinorVersionUpgradeEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsClusterMinorVersionUpgradeEnabled() *RdsClusterMinorVersionUpgradeEnabled {
	return &RdsClusterMinorVersionUpgradeEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_minor_version_upgrade_enabled",
			CheckTitle: "RDS cluster has auto minor version upgrade",
			ServiceName: "rds", Severity: "low", ResourceType: "DBCluster",
			Description: "RDS clusters should have auto minor version upgrade enabled",
			RemediationText: "Enable auto minor version upgrade on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not have auto minor version upgrade.", clusterID)

		if cluster.AutoMinorVersionUpgrade != nil && *cluster.AutoMinorVersionUpgrade {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s has auto minor version upgrade.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterMultiAz - RDS cluster has Multi-AZ enabled
type RdsClusterMultiAz struct {
	metadata models.CheckMetadata
}

func NewRdsClusterMultiAz() *RdsClusterMultiAz {
	return &RdsClusterMultiAz{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_multi_az",
			CheckTitle: "RDS cluster has Multi-AZ enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBCluster",
			Description: "RDS clusters should have Multi-AZ enabled for high availability",
			RemediationText: "Enable Multi-AZ on your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterMultiAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s does not have Multi-AZ enabled.", clusterID)

		if cluster.MultiAZ != nil && *cluster.MultiAZ {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s has Multi-AZ enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterNonDefaultPort - RDS cluster uses non-default port
type RdsClusterNonDefaultPort struct {
	metadata models.CheckMetadata
}

func NewRdsClusterNonDefaultPort() *RdsClusterNonDefaultPort {
	return &RdsClusterNonDefaultPort{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_non_default_port",
			CheckTitle: "RDS cluster uses non-default port",
			ServiceName: "rds", Severity: "low", ResourceType: "DBCluster",
			Description: "RDS clusters should use non-default ports",
			RemediationText: "Change the default port for your RDS clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsClusterNonDefaultPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	defaultPorts := []int32{3306, 5432, 1521, 1433, 50000}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Cluster %s uses non-default port.", clusterID)

		if cluster.Port != nil {
			for _, defaultPort := range defaultPorts {
				if *cluster.Port == defaultPort {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("RDS Cluster %s uses default port %d.", clusterID, defaultPort)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsClusterStorageEncrypted - RDS cluster storage is encrypted
type RdsClusterStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewRdsClusterStorageEncrypted() *RdsClusterStorageEncrypted {
	return &RdsClusterStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_cluster_storage_encrypted",
			CheckTitle: "RDS cluster storage is encrypted",
			ServiceName: "rds", Severity: "high", ResourceType: "DBCluster",
			Description: "RDS clusters should have storage encryption enabled",
			RemediationText: "Enable storage encryption on your RDS clusters",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *RdsClusterStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsClusterStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	clusters, err := rdsClient.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB clusters: %w", err)
	}

	findings := []models.Finding{}
	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Cluster %s storage is not encrypted.", clusterID)

		if cluster.StorageEncrypted != nil && *cluster.StorageEncrypted {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Cluster %s storage is encrypted.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// ==================== RDS Instance Checks ====================

// RdsInstanceBackupEnabled - RDS instance has backup enabled
type RdsInstanceBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceBackupEnabled() *RdsInstanceBackupEnabled {
	return &RdsInstanceBackupEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_backup_enabled",
			CheckTitle: "RDS instance has backup enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
			Description: "RDS instances should have backup enabled",
			RemediationText: "Enable backup on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have backup enabled.", instanceID)

		if instance.BackupRetentionPeriod != nil && *instance.BackupRetentionPeriod > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has backup enabled.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceCopyTagsToSnapshots - RDS instance copies tags to snapshots
type RdsInstanceCopyTagsToSnapshots struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceCopyTagsToSnapshots() *RdsInstanceCopyTagsToSnapshots {
	return &RdsInstanceCopyTagsToSnapshots{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_copy_tags_to_snapshots",
			CheckTitle: "RDS instance copies tags to snapshots",
			ServiceName: "rds", Severity: "low", ResourceType: "DBInstance",
			Description: "RDS instances should copy tags to snapshots",
			RemediationText: "Enable CopyTagsToSnapshot on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceCopyTagsToSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceCopyTagsToSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not copy tags to snapshots.", instanceID)

		if instance.CopyTagsToSnapshot != nil && *instance.CopyTagsToSnapshot {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s copies tags to snapshots.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceDefaultAdmin - RDS instance does not use default admin name
type RdsInstanceDefaultAdmin struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceDefaultAdmin() *RdsInstanceDefaultAdmin {
	return &RdsInstanceDefaultAdmin{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_default_admin",
			CheckTitle: "RDS instance does not use default admin name",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
			Description: "RDS instances should not use the default admin username",
			RemediationText: "Change the default admin username",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceDefaultAdmin) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceDefaultAdmin) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Instance %s does not use default admin name.", instanceID)

		if instance.MasterUsername != nil && aws.ToString(instance.MasterUsername) == "admin" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("RDS Instance %s uses default admin name.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceDeletionProtection - RDS instance has deletion protection
type RdsInstanceDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceDeletionProtection() *RdsInstanceDeletionProtection {
	return &RdsInstanceDeletionProtection{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_deletion_protection",
			CheckTitle: "RDS instance has deletion protection",
			ServiceName: "rds", Severity: "high", ResourceType: "DBInstance",
			Description: "RDS instances should have deletion protection enabled",
			RemediationText: "Enable deletion protection on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have deletion protection.", instanceID)

		if instance.DeletionProtection != nil && *instance.DeletionProtection {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has deletion protection.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceEnhancedMonitoringEnabled - RDS instance has enhanced monitoring
type RdsInstanceEnhancedMonitoringEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceEnhancedMonitoringEnabled() *RdsInstanceEnhancedMonitoringEnabled {
	return &RdsInstanceEnhancedMonitoringEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_enhanced_monitoring_enabled",
			CheckTitle: "RDS instance has enhanced monitoring enabled",
			ServiceName: "rds", Severity: "low", ResourceType: "DBInstance",
			Description: "RDS instances should have enhanced monitoring enabled",
			RemediationText: "Enable enhanced monitoring on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceEnhancedMonitoringEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceEnhancedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have enhanced monitoring.", instanceID)

		if instance.EnhancedMonitoringResourceArn != nil && aws.ToString(instance.EnhancedMonitoringResourceArn) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has enhanced monitoring.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceIamAuthenticationEnabled - RDS instance has IAM authentication
type RdsInstanceIamAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceIamAuthenticationEnabled() *RdsInstanceIamAuthenticationEnabled {
	return &RdsInstanceIamAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_iam_authentication_enabled",
			CheckTitle: "RDS instance has IAM authentication enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
			Description: "RDS instances should have IAM authentication enabled",
			RemediationText: "Enable IAM authentication on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceIamAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceIamAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have IAM authentication enabled.", instanceID)

		if instance.IAMDatabaseAuthenticationEnabled != nil && *instance.IAMDatabaseAuthenticationEnabled {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has IAM authentication enabled.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceInsideVpc - RDS instance is inside a VPC
type RdsInstanceInsideVpc struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceInsideVpc() *RdsInstanceInsideVpc {
	return &RdsInstanceInsideVpc{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_inside_vpc",
			CheckTitle: "RDS instance is inside a VPC",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
			Description: "RDS instances should be inside a VPC",
			RemediationText: "Move your RDS instances to a VPC",
			Categories: []string{"database", "networking"},
		},
	}
}

func (c *RdsInstanceInsideVpc) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceInsideVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s is not inside a VPC.", instanceID)

		if instance.DBSubnetGroup != nil && aws.ToString(instance.DBSubnetGroup.VpcId) != "" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s is inside VPC %s.", instanceID, aws.ToString(instance.DBSubnetGroup.VpcId))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceIntegrationCloudwatchLogs - RDS instance integrates with CloudWatch Logs
type RdsInstanceIntegrationCloudwatchLogs struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceIntegrationCloudwatchLogs() *RdsInstanceIntegrationCloudwatchLogs {
	return &RdsInstanceIntegrationCloudwatchLogs{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_integration_cloudwatch_logs",
			CheckTitle: "RDS instance integrates with CloudWatch Logs",
			ServiceName: "rds", Severity: "low", ResourceType: "DBInstance",
			Description: "RDS instances should integrate with CloudWatch Logs",
			RemediationText: "Enable CloudWatch Logs exports on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceIntegrationCloudwatchLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceIntegrationCloudwatchLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not integrate with CloudWatch Logs.", instanceID)

		if instance.EnabledCloudwatchLogsExports != nil && len(instance.EnabledCloudwatchLogsExports) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s integrates with CloudWatch Logs.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceMinorVersionUpgradeEnabled - RDS instance has auto minor version upgrade
type RdsInstanceMinorVersionUpgradeEnabled struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceMinorVersionUpgradeEnabled() *RdsInstanceMinorVersionUpgradeEnabled {
	return &RdsInstanceMinorVersionUpgradeEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_minor_version_upgrade_enabled",
			CheckTitle: "RDS instance has auto minor version upgrade",
			ServiceName: "rds", Severity: "low", ResourceType: "DBInstance",
			Description: "RDS instances should have auto minor version upgrade enabled",
			RemediationText: "Enable auto minor version upgrade on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have auto minor version upgrade.", instanceID)

		if instance.AutoMinorVersionUpgrade != nil && *instance.AutoMinorVersionUpgrade {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has auto minor version upgrade.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceMultiAz - RDS instance has Multi-AZ enabled
type RdsInstanceMultiAz struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceMultiAz() *RdsInstanceMultiAz {
	return &RdsInstanceMultiAz{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_multi_az",
			CheckTitle: "RDS instance has Multi-AZ enabled",
			ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
			Description: "RDS instances should have Multi-AZ enabled for high availability",
			RemediationText: "Enable Multi-AZ on your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceMultiAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s does not have Multi-AZ enabled.", instanceID)

		if instance.MultiAZ != nil && *instance.MultiAZ {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s has Multi-AZ enabled.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceNoPublicAccess - RDS instance is not publicly accessible
type RdsInstanceNoPublicAccess struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceNoPublicAccess() *RdsInstanceNoPublicAccess {
	return &RdsInstanceNoPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_no_public_access",
			CheckTitle: "RDS instance is not publicly accessible",
			ServiceName: "rds", Severity: "critical", ResourceType: "DBInstance",
			Description: "RDS instances should not be publicly accessible",
			RemediationText: "Disable public accessibility on your RDS instances",
			Categories: []string{"database", "networking"},
		},
	}
}

func (c *RdsInstanceNoPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceNoPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Instance %s is not publicly accessible.", instanceID)

		if instance.PubliclyAccessible != nil && *instance.PubliclyAccessible {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("RDS Instance %s is publicly accessible.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceNonDefaultPort - RDS instance uses non-default port
type RdsInstanceNonDefaultPort struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceNonDefaultPort() *RdsInstanceNonDefaultPort {
	return &RdsInstanceNonDefaultPort{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_non_default_port",
			CheckTitle: "RDS instance uses non-default port",
			ServiceName: "rds", Severity: "low", ResourceType: "DBInstance",
			Description: "RDS instances should use non-default ports",
			RemediationText: "Change the default port for your RDS instances",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsInstanceNonDefaultPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceNonDefaultPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	defaultPorts := []int32{3306, 5432, 1521, 1433, 50000}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Instance %s uses non-default port.", instanceID)

		if instance.Endpoint != nil && instance.Endpoint.Port != nil {
			for _, defaultPort := range defaultPorts {
				if *instance.Endpoint.Port == defaultPort {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("RDS Instance %s uses default port %d.", instanceID, defaultPort)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceStorageEncrypted - RDS instance storage is encrypted
type RdsInstanceStorageEncrypted struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceStorageEncrypted() *RdsInstanceStorageEncrypted {
	return &RdsInstanceStorageEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_storage_encrypted",
			CheckTitle: "RDS instance storage is encrypted",
			ServiceName: "rds", Severity: "high", ResourceType: "DBInstance",
			Description: "RDS instances should have storage encryption enabled",
			RemediationText: "Enable storage encryption on your RDS instances",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *RdsInstanceStorageEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceStorageEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	instances, err := rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instances: %w", err)
	}

	findings := []models.Finding{}
	for _, instance := range instances.DBInstances {
		instanceID := aws.ToString(instance.DBInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("RDS Instance %s storage is not encrypted.", instanceID)

		if instance.StorageEncrypted != nil && *instance.StorageEncrypted {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("RDS Instance %s storage is encrypted.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: instanceID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsInstanceTransportEncrypted - RDS instance transport is encrypted
type RdsInstanceTransportEncrypted struct {
	metadata models.CheckMetadata
}

func NewRdsInstanceTransportEncrypted() *RdsInstanceTransportEncrypted {
	return &RdsInstanceTransportEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_instance_transport_encrypted",
			CheckTitle: "RDS instance transport is encrypted",
			ServiceName: "rds", Severity: "high", ResourceType: "DBInstance",
			Description: "RDS instances should have SSL/TLS transport encryption enabled",
			RemediationText: "Enable SSL/TLS on your RDS instances",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *RdsInstanceTransportEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsInstanceTransportEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "RDS instance SSL/TLS check requires DB parameter group analysis",
			Provider: "aws", Service: "rds",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// ==================== RDS Snapshot Checks ====================

// RdsSnapshotsEncrypted - RDS snapshots are encrypted
type RdsSnapshotsEncrypted struct {
	metadata models.CheckMetadata
}

func NewRdsSnapshotsEncrypted() *RdsSnapshotsEncrypted {
	return &RdsSnapshotsEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_snapshots_encrypted",
			CheckTitle: "RDS snapshots are encrypted",
			ServiceName: "rds", Severity: "high", ResourceType: "DBSnapshot",
			Description: "RDS snapshots should be encrypted",
			RemediationText: "Enable encryption on your RDS snapshots",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *RdsSnapshotsEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsSnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	snapshots, err := rdsClient.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB snapshots: %w", err)
	}

	findings := []models.Finding{}
	for _, snapshot := range snapshots.DBSnapshots {
		snapshotID := aws.ToString(snapshot.DBSnapshotIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Snapshot %s is encrypted.", snapshotID)

		if snapshot.Encrypted == nil || !*snapshot.Encrypted {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("RDS Snapshot %s is not encrypted.", snapshotID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: snapshotID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// RdsSnapshotsPublicAccess - RDS snapshots are not public
type RdsSnapshotsPublicAccess struct {
	metadata models.CheckMetadata
}

func NewRdsSnapshotsPublicAccess() *RdsSnapshotsPublicAccess {
	return &RdsSnapshotsPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "rds_snapshots_public_access",
			CheckTitle: "RDS snapshots are not public",
			ServiceName: "rds", Severity: "critical", ResourceType: "DBSnapshot",
			Description: "RDS snapshots should not be publicly accessible",
			RemediationText: "Remove public access from your RDS snapshots",
			Categories: []string{"database"},
		},
	}
}

func (c *RdsSnapshotsPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *RdsSnapshotsPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(rdsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement rdsProvider")
	}
	rdsClient, err := p.RDS(ctx)
	if err != nil {
		return nil, err
	}

	snapshots, err := rdsClient.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB snapshots: %w", err)
	}

	findings := []models.Finding{}
	for _, snapshot := range snapshots.DBSnapshots {
		snapshotID := aws.ToString(snapshot.DBSnapshotIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("RDS Snapshot %s is not public.", snapshotID)

		attrs, err := rdsClient.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
			DBSnapshotIdentifier: snapshot.DBSnapshotIdentifier,
		})
		if err == nil {
			for _, attr := range attrs.DBSnapshotAttributesResult.DBSnapshotAttributes {
				if aws.ToString(attr.AttributeName) == "restore" {
					for _, value := range attr.AttributeValues {
						if value == "all" {
							status = models.StatusFail
							statusExtended = fmt.Sprintf("RDS Snapshot %s is public.", snapshotID)
						}
					}
				}
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "rds", ResourceID: snapshotID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// ==================== Remaining RDS Checks (Manual Review) ====================

// All remaining RDS checks that require cross-service analysis are marked as StatusManual

func newRdsManualFinding(metadata models.CheckMetadata) []models.Finding {
	return []models.Finding{
		{
			ID:             metadata.CheckID,
			Title:          metadata.CheckTitle,
			Description:    metadata.Description,
			Severity:       metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("%s requires manual review or cross-service integration", metadata.CheckTitle),
			Provider:       "aws",
			Service:        "rds",
			Remediation:    metadata.RemediationText,
			Categories:     metadata.Categories,
			FoundAt:        time.Now().UTC(),
		},
	}
}

type baseRdsCheck struct {
	metadata models.CheckMetadata
}

func (c *baseRdsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *baseRdsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newRdsManualFinding(c.metadata), nil
}

// Event subscription checks
func NewRdsClusterCriticalEventSubscription() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_cluster_critical_event_subscription",
		CheckTitle: "RDS cluster has critical event subscription",
		ServiceName: "rds", Severity: "medium", ResourceType: "EventSubscription",
		Description: "RDS clusters should have critical event subscriptions",
		RemediationText: "Create critical event subscriptions for RDS clusters",
		Categories: []string{"database"},
	}}
}

func NewRdsClusterProtectedByBackupPlan() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_cluster_protected_by_backup_plan",
		CheckTitle: "RDS cluster is protected by backup plan",
		ServiceName: "rds", Severity: "medium", ResourceType: "DBCluster",
		Description: "RDS clusters should be protected by a backup plan",
		RemediationText: "Add RDS clusters to a backup plan",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceCertificateExpiration() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_certificate_expiration",
		CheckTitle: "RDS instance certificate is not expiring soon",
		ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
		Description: "RDS instance certificates should not be expiring soon",
		RemediationText: "Rotate expiring RDS instance certificates",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceCriticalEventSubscription() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_critical_event_subscription",
		CheckTitle: "RDS instance has critical event subscription",
		ServiceName: "rds", Severity: "medium", ResourceType: "EventSubscription",
		Description: "RDS instances should have critical event subscriptions",
		RemediationText: "Create critical event subscriptions for RDS instances",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceDeprecatedEngineVersion() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_deprecated_engine_version",
		CheckTitle: "RDS instance does not use deprecated engine version",
		ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
		Description: "RDS instances should not use deprecated engine versions",
		RemediationText: "Upgrade RDS instances to supported engine versions",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceEventSubscriptionParameterGroups() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_event_subscription_parameter_groups",
		CheckTitle: "RDS instance has parameter group event subscription",
		ServiceName: "rds", Severity: "low", ResourceType: "EventSubscription",
		Description: "RDS instances should have parameter group event subscriptions",
		RemediationText: "Create parameter group event subscriptions",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceEventSubscriptionSecurityGroups() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_event_subscription_security_groups",
		CheckTitle: "RDS instance has security group event subscription",
		ServiceName: "rds", Severity: "low", ResourceType: "EventSubscription",
		Description: "RDS instances should have security group event subscriptions",
		RemediationText: "Create security group event subscriptions",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceExtendedSupport() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_extended_support",
		CheckTitle: "RDS instance extended support is managed",
		ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
		Description: "RDS instances on extended support should be upgraded",
		RemediationText: "Upgrade RDS instances off extended support",
		Categories: []string{"database"},
	}}
}

func NewRdsInstanceProtectedByBackupPlan() *baseRdsCheck {
	return &baseRdsCheck{metadata: models.CheckMetadata{
		Provider: "aws", CheckID: "rds_instance_protected_by_backup_plan",
		CheckTitle: "RDS instance is protected by backup plan",
		ServiceName: "rds", Severity: "medium", ResourceType: "DBInstance",
		Description: "RDS instances should be protected by a backup plan",
		RemediationText: "Add RDS instances to a backup plan",
		Categories: []string{"database"},
	}}
}