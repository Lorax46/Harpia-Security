package documentdb

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type documentdbProvider interface {
	DocDB(ctx context.Context) (*docdb.Client, error)
}

// DocdbClusterEncryptionAtRest - DocDB cluster encryption at rest
type DocdbClusterEncryptionAtRest struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterEncryptionAtRest() *DocdbClusterEncryptionAtRest {
	return &DocdbClusterEncryptionAtRest{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_encryption_at_rest",
			CheckTitle: "DocDB cluster encryption at rest",
			ServiceName: "documentdb", Severity: "high", ResourceType: "DBCluster",
			Description: "DocDB clusters should have encryption at rest enabled",
			RemediationText: "Enable encryption at rest on DocDB clusters",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *DocdbClusterEncryptionAtRest) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterEncryptionAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	dbClient, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := dbClient.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DocDB cluster %s does not have encryption at rest enabled.", clusterID)

		if cluster.StorageEncrypted != nil && *cluster.StorageEncrypted {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DocDB cluster %s has encryption at rest enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "documentdb", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// DocdbClusterLoggingEnabled - DocDB cluster logging enabled
type DocdbClusterLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterLoggingEnabled() *DocdbClusterLoggingEnabled {
	return &DocdbClusterLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_logging_enabled",
			CheckTitle: "DocDB cluster logging enabled",
			ServiceName: "documentdb", Severity: "medium", ResourceType: "DBCluster",
			Description: "DocDB clusters should have logging enabled",
			RemediationText: "Enable logging on DocDB clusters",
			Categories: []string{"database", "logging"},
		},
	}
}

func (c *DocdbClusterLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	dbClient, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := dbClient.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DocDB cluster %s does not have logging enabled.", clusterID)

		if cluster.EnabledCloudwatchLogsExports != nil && len(cluster.EnabledCloudwatchLogsExports) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DocDB cluster %s has logging enabled.", clusterID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "documentdb", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// DocdbClusterPublicAccess - DocDB cluster public access
type DocdbClusterPublicAccess struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterPublicAccess() *DocdbClusterPublicAccess {
	return &DocdbClusterPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_public_access",
			CheckTitle: "DocDB cluster public access",
			ServiceName: "documentdb", Severity: "high", ResourceType: "DBCluster",
			Description: "DocDB clusters should not be publicly accessible",
			RemediationText: "Disable public access on DocDB clusters",
			Categories: []string{"database", "networking"},
		},
	}
}

func (c *DocdbClusterPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "DocDB public access check requires detailed configuration analysis",
			Provider: "aws", Service: "documentdb",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// DocdbClusterRetentionPolicy - DocDB cluster retention policy
type DocdbClusterRetentionPolicy struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterRetentionPolicy() *DocdbClusterRetentionPolicy {
	return &DocdbClusterRetentionPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_retention_policy",
			CheckTitle: "DocDB cluster retention policy",
			ServiceName: "documentdb", Severity: "medium", ResourceType: "DBCluster",
			Description: "DocDB clusters should have retention policy configured",
			RemediationText: "Configure retention policy on DocDB clusters",
			Categories: []string{"database"},
		},
	}
}

func (c *DocdbClusterRetentionPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterRetentionPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(documentdbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement documentdbProvider")
	}
	dbClient, err := p.DocDB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := dbClient.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe clusters: %w", err)
	}

	for _, cluster := range clusters.DBClusters {
		clusterID := aws.ToString(cluster.DBClusterIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DocDB cluster %s does not have retention policy.", clusterID)

		if cluster.BackupRetentionPeriod != nil && *cluster.BackupRetentionPeriod >= 7 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DocDB cluster %s has retention policy of %d days.", clusterID, *cluster.BackupRetentionPeriod)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "documentdb", ResourceID: clusterID,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// DocdbClusterSnapshotEncryption - DocDB cluster snapshot encryption
type DocdbClusterSnapshotEncryption struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterSnapshotEncryption() *DocdbClusterSnapshotEncryption {
	return &DocdbClusterSnapshotEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_snapshot_encryption",
			CheckTitle: "DocDB cluster snapshot encryption",
			ServiceName: "documentdb", Severity: "medium", ResourceType: "DBCluster",
			Description: "DocDB cluster snapshots should be encrypted",
			RemediationText: "Enable encryption on DocDB cluster snapshots",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *DocdbClusterSnapshotEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterSnapshotEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "DocDB snapshot encryption check requires detailed configuration analysis",
			Provider: "aws", Service: "documentdb",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// DocdbClusterTlsEnabled - DocDB cluster TLS enabled
type DocdbClusterTlsEnabled struct {
	metadata models.CheckMetadata
}

func NewDocdbClusterTlsEnabled() *DocdbClusterTlsEnabled {
	return &DocdbClusterTlsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "docdb_cluster_tls_enabled",
			CheckTitle: "DocDB cluster TLS enabled",
			ServiceName: "documentdb", Severity: "medium", ResourceType: "DBCluster",
			Description: "DocDB clusters should have TLS enabled",
			RemediationText: "Enable TLS on DocDB clusters",
			Categories: []string{"database", "encryption"},
		},
	}
}

func (c *DocdbClusterTlsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DocdbClusterTlsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "DocDB TLS check requires detailed configuration analysis",
			Provider: "aws", Service: "documentdb",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}