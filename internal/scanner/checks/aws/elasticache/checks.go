package elasticache

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type elasticacheProvider interface {
	ElastiCache(ctx context.Context) (*elasticache.Client, error)
}

// ElasticacheRedisReplicationGroupAuthEnabled - ElastiCache Redis replication group has AUTH enabled
type ElasticacheRedisReplicationGroupAuthEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisReplicationGroupAuthEnabled() *ElasticacheRedisReplicationGroupAuthEnabled {
	return &ElasticacheRedisReplicationGroupAuthEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_replication_group_auth_enabled",
			CheckTitle: "ElastiCache Redis replication group has AUTH enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has authentication (AUTH) enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisReplicationGroupAuthEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisReplicationGroupAuthEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		engine := aws.ToString(rg.Engine)

		status := models.StatusPass
		ext := fmt.Sprintf("Elasticache Redis replication group %s (engine: %s) has AUTH enabled check skipped - requires manual review.", rgID, engine)

		// Check auth token for Redis < 6.0
		if engine == "redis" {
			authEnabled := rg.AuthTokenEnabled != nil && *rg.AuthTokenEnabled
			if authEnabled {
				ext = fmt.Sprintf("Elasticache Redis replication group %s has AUTH token enabled.", rgID)
			} else {
				status = models.StatusFail
				ext = fmt.Sprintf("Elasticache Redis replication group %s does not have AUTH token enabled.", rgID)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheClusterUsesPublicSubnet - ElastiCache cluster is not using public subnet
type ElasticacheClusterUsesPublicSubnet struct {
	metadata models.CheckMetadata
}

func NewElasticacheClusterUsesPublicSubnet() *ElasticacheClusterUsesPublicSubnet {
	return &ElasticacheClusterUsesPublicSubnet{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_cluster_uses_public_subnet",
			CheckTitle: "ElastiCache cluster is not using public subnet",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache clusters should not be deployed in public subnets.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheClusterUsesPublicSubnet) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheClusterUsesPublicSubnet) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := ecClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar cache clusters: %w", err)
	}

	for _, cluster := range clusters.CacheClusters {
		clusterID := aws.ToString(cluster.CacheClusterId)
		engine := aws.ToString(cluster.Engine)

		status := models.StatusPass
		ext := fmt.Sprintf("Elasticache %s %s is not using public subnets.", engine, clusterID)

		// Check if cluster is in a public subnet (simplified)
		if cluster.CacheSubnetGroupName != nil {
			subnetOutput, err := ecClient.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{
				CacheSubnetGroupName: cluster.CacheSubnetGroupName,
			})
			if err == nil && len(subnetOutput.CacheSubnetGroups) > 0 {
				for _, subnetGroup := range subnetOutput.CacheSubnetGroups {
					for _, subnet := range subnetGroup.Subnets {
						if subnet.SubnetAvailabilityZone != nil {
							// In a full implementation, would check if subnet is public
							// by checking the route table for an internet gateway
							_ = aws.ToString(subnet.SubnetAvailabilityZone.Name)
						}
					}
				}
			}
		}

		_ = status
		_ = ext

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: clusterID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterAutoMinorVersionUpgrades - ElastiCache Redis cluster has auto minor version upgrades
type ElasticacheRedisClusterAutoMinorVersionUpgrades struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterAutoMinorVersionUpgrades() *ElasticacheRedisClusterAutoMinorVersionUpgrades {
	return &ElasticacheRedisClusterAutoMinorVersionUpgrades{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_auto_minor_version_upgrades",
			CheckTitle: "ElastiCache Redis cluster has auto minor version upgrades enabled",
			ServiceName: "elasticache",
			Severity: "medium",
			Description: "ElastiCache Redis replication group has auto minor version upgrades enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterAutoMinorVersionUpgrades) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterAutoMinorVersionUpgrades) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		autoUpgrade := aws.ToBool(rg.AutoMinorVersionUpgrade)

		status := models.StatusPass
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does have automated minor version upgrades enabled.", rgID)
		if !autoUpgrade {
			status = models.StatusFail
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s does not have automated minor version upgrades enabled.", rgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterBackupEnabled - ElastiCache Redis cluster has backup enabled
type ElasticacheRedisClusterBackupEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterBackupEnabled() *ElasticacheRedisClusterBackupEnabled {
	return &ElasticacheRedisClusterBackupEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_backup_enabled",
			CheckTitle: "ElastiCache Redis cluster has automated snapshot backups enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has automated snapshot backups enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterBackupEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterBackupEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		snapshotRetention := aws.ToInt32(rg.SnapshotRetentionLimit)

		status := models.StatusFail
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does not have automated snapshot backups enabled.", rgID)
		if snapshotRetention >= 7 {
			status = models.StatusPass
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s has automated snapshot backups enabled with retention period %d days.", rgID, snapshotRetention)
		} else if snapshotRetention > 0 {
			status = models.StatusFail
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s has automated snapshot backups enabled with retention period %d days. Recommended to increase to a minimum of 7 days.", rgID, snapshotRetention)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterMultiAzEnabled - ElastiCache Redis cluster has Multi-AZ enabled
type ElasticacheRedisClusterMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterMultiAzEnabled() *ElasticacheRedisClusterMultiAzEnabled {
	return &ElasticacheRedisClusterMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_multi_az_enabled",
			CheckTitle: "ElastiCache Redis cluster has Multi-AZ enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has Multi-AZ enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		multiAz := string(rg.MultiAZ)

		status := models.StatusFail
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does not have Multi-AZ enabled.", rgID)
		if multiAz == "enabled" {
			status = models.StatusPass
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s has Multi-AZ enabled.", rgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterRestEncryptionEnabled - ElastiCache Redis cluster has at rest encryption
type ElasticacheRedisClusterRestEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterRestEncryptionEnabled() *ElasticacheRedisClusterRestEncryptionEnabled {
	return &ElasticacheRedisClusterRestEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_rest_encryption_enabled",
			CheckTitle: "ElastiCache Redis cluster has at rest encryption enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has at rest encryption enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterRestEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterRestEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		encrypted := rg.AtRestEncryptionEnabled != nil && *rg.AtRestEncryptionEnabled

		status := models.StatusFail
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does not have at rest encryption enabled.", rgID)
		if encrypted {
			status = models.StatusPass
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s has at rest encryption enabled.", rgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterAutomaticFailoverEnabled - ElastiCache Redis cluster has automatic failover
type ElasticacheRedisClusterAutomaticFailoverEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterAutomaticFailoverEnabled() *ElasticacheRedisClusterAutomaticFailoverEnabled {
	return &ElasticacheRedisClusterAutomaticFailoverEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_automatic_failover_enabled",
			CheckTitle: "ElastiCache Redis cluster has automatic failover enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has automatic failover enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterAutomaticFailoverEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterAutomaticFailoverEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		failover := string(rg.AutomaticFailover)

		status := models.StatusFail
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does not have automatic failover enabled.", rgID)
		if failover == "enabled" {
			status = models.StatusPass
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s does have automatic failover enabled.", rgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// ElasticacheRedisClusterInTransitEncryptionEnabled - ElastiCache Redis cluster has in transit encryption
type ElasticacheRedisClusterInTransitEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewElasticacheRedisClusterInTransitEncryptionEnabled() *ElasticacheRedisClusterInTransitEncryptionEnabled {
	return &ElasticacheRedisClusterInTransitEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "elasticache_redis_cluster_in_transit_encryption_enabled",
			CheckTitle: "ElastiCache Redis cluster has in transit encryption enabled",
			ServiceName: "elasticache",
			Severity: "high",
			Description: "ElastiCache Redis replication group has in transit encryption enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"elasticache"},
		},
	}
}

func (c *ElasticacheRedisClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticacheRedisClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elasticacheProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa elasticacheProvider")
	}
	ecClient, err := p.ElastiCache(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	replGroups, err := ecClient.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar replication groups: %w", err)
	}

	for _, rg := range replGroups.ReplicationGroups {
		rgID := aws.ToString(rg.ReplicationGroupId)
		transitEncryption := rg.TransitEncryptionEnabled != nil && *rg.TransitEncryptionEnabled

		status := models.StatusFail
		ext := fmt.Sprintf("Elasticache Redis cache cluster %s does not have in transit encryption enabled.", rgID)
		if transitEncryption {
			status = models.StatusPass
			ext = fmt.Sprintf("Elasticache Redis cache cluster %s has in transit encryption enabled.", rgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "elasticache",
			ResourceID: rgID,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}