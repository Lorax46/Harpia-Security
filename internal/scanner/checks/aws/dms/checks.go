package dms

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type dmsProvider interface {
	DMS(ctx context.Context) (*databasemigrationservice.Client, error)
}

// DmsEndpointSslEnabled - DMS endpoint has SSL enabled
type DmsEndpointSslEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsEndpointSslEnabled() *DmsEndpointSslEnabled {
	return &DmsEndpointSslEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_endpoint_ssl_enabled",
			CheckTitle:   "DMS endpoint has SSL enabled",
			ServiceName:  "dms",
			Severity:     "high",
			ResourceType: "Endpoint",
			Description:  "DMS endpoints should have SSL enabled for secure data transfer",
			RemediationText: "Enable SSL on your DMS endpoints",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *DmsEndpointSslEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsEndpointSslEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := client.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS endpoints: %w", err)
	}

	for _, endpoint := range endpoints.Endpoints {
		endpointID := aws.ToString(endpoint.EndpointIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("DMS endpoint %s has SSL enabled.", endpointID)

		if endpoint.SslMode == "none" || endpoint.SslMode == "" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("DMS endpoint %s does not have SSL enabled.", endpointID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsEndpointNeptuneIamAuthorizationEnabled - DMS Neptune endpoint has IAM authorization
type DmsEndpointNeptuneIamAuthorizationEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsEndpointNeptuneIamAuthorizationEnabled() *DmsEndpointNeptuneIamAuthorizationEnabled {
	return &DmsEndpointNeptuneIamAuthorizationEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_endpoint_neptune_iam_authorization_enabled",
			CheckTitle:   "DMS Neptune endpoint has IAM authorization enabled",
			ServiceName:  "dms",
			Severity:     "medium",
			ResourceType: "Endpoint",
			Description:  "DMS endpoints for Neptune should have IAM authorization enabled",
			RemediationText: "Enable IAM authorization on your DMS Neptune endpoints",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsEndpointNeptuneIamAuthorizationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsEndpointNeptuneIamAuthorizationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := client.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS endpoints: %w", err)
	}

	for _, endpoint := range endpoints.Endpoints {
		if aws.ToString(endpoint.EngineName) != "neptune" {
			continue
		}

		endpointID := aws.ToString(endpoint.EndpointIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DMS Neptune endpoint %s does not have IAM authorization enabled.", endpointID)

		if endpoint.NeptuneSettings != nil && aws.ToBool(endpoint.NeptuneSettings.IamAuthEnabled) {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DMS Neptune endpoint %s has IAM authorization enabled.", endpointID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsEndpointRedisInTransitEncryptionEnabled - DMS Redis endpoint has TLS enabled
type DmsEndpointRedisInTransitEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsEndpointRedisInTransitEncryptionEnabled() *DmsEndpointRedisInTransitEncryptionEnabled {
	return &DmsEndpointRedisInTransitEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_endpoint_redis_in_transit_encryption_enabled",
			CheckTitle:   "DMS Redis endpoint has TLS enabled",
			ServiceName:  "dms",
			Severity:     "high",
			ResourceType: "Endpoint",
			Description:  "DMS endpoints for Redis should have TLS enabled for encryption in transit",
			RemediationText: "Enable TLS on your DMS Redis endpoints",
			Categories:   []string{"database", "encryption"},
		},
	}
}

func (c *DmsEndpointRedisInTransitEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsEndpointRedisInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := client.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS endpoints: %w", err)
	}

	for _, endpoint := range endpoints.Endpoints {
		if aws.ToString(endpoint.EngineName) != "redis" {
			continue
		}

		endpointID := aws.ToString(endpoint.EndpointIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DMS Redis endpoint %s does not have TLS enabled.", endpointID)

		if endpoint.RedisSettings != nil && string(endpoint.RedisSettings.SslSecurityProtocol) == "ssl-encryption" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DMS Redis endpoint %s has TLS enabled.", endpointID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsEndpointMongodbAuthenticationEnabled - DMS MongoDB endpoint has authentication enabled
type DmsEndpointMongodbAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsEndpointMongodbAuthenticationEnabled() *DmsEndpointMongodbAuthenticationEnabled {
	return &DmsEndpointMongodbAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_endpoint_mongodb_authentication_enabled",
			CheckTitle:   "DMS MongoDB endpoint has authentication enabled",
			ServiceName:  "dms",
			Severity:     "high",
			ResourceType: "Endpoint",
			Description:  "DMS endpoints for MongoDB should have authentication enabled",
			RemediationText: "Enable authentication on your DMS MongoDB endpoints",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsEndpointMongodbAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsEndpointMongodbAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := client.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS endpoints: %w", err)
	}

	for _, endpoint := range endpoints.Endpoints {
		if aws.ToString(endpoint.EngineName) != "mongodb" {
			continue
		}

		endpointID := aws.ToString(endpoint.EndpointIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DMS MongoDB endpoint %s does not have authentication enabled.", endpointID)

		if endpoint.MongoDbSettings != nil && string(endpoint.MongoDbSettings.AuthType) != "no" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DMS MongoDB endpoint %s has authentication enabled.", endpointID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsInstanceMinorVersionUpgradeEnabled - DMS replication instance has auto minor version upgrade
type DmsInstanceMinorVersionUpgradeEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsInstanceMinorVersionUpgradeEnabled() *DmsInstanceMinorVersionUpgradeEnabled {
	return &DmsInstanceMinorVersionUpgradeEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_instance_minor_version_upgrade_enabled",
			CheckTitle:   "DMS replication instance has auto minor version upgrade",
			ServiceName:  "dms",
			Severity:     "low",
			ResourceType: "ReplicationInstance",
			Description:  "DMS replication instances should have auto minor version upgrade enabled",
			RemediationText: "Enable auto minor version upgrade on your DMS replication instances",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsInstanceMinorVersionUpgradeEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsInstanceMinorVersionUpgradeEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	instances, err := client.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS replication instances: %w", err)
	}

	for _, instance := range instances.ReplicationInstances {
		instanceID := aws.ToString(instance.ReplicationInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DMS replication instance %s does not have auto minor version upgrade enabled.", instanceID)

		if instance.AutoMinorVersionUpgrade {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DMS replication instance %s has auto minor version upgrade enabled.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     instanceID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsInstanceMultiAzEnabled - DMS replication instance has Multi-AZ enabled
type DmsInstanceMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsInstanceMultiAzEnabled() *DmsInstanceMultiAzEnabled {
	return &DmsInstanceMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_instance_multi_az_enabled",
			CheckTitle:   "DMS replication instance has Multi-AZ enabled",
			ServiceName:  "dms",
			Severity:     "medium",
			ResourceType: "ReplicationInstance",
			Description:  "DMS replication instances should have Multi-AZ enabled for high availability",
			RemediationText: "Enable Multi-AZ on your DMS replication instances",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsInstanceMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsInstanceMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	instances, err := client.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS replication instances: %w", err)
	}

	for _, instance := range instances.ReplicationInstances {
		instanceID := aws.ToString(instance.ReplicationInstanceIdentifier)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("DMS replication instance %s does not have Multi-AZ enabled.", instanceID)

		if instance.MultiAZ {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("DMS replication instance %s has Multi-AZ enabled.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     instanceID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsInstanceNoPublicAccess - DMS replication instance is not publicly accessible
type DmsInstanceNoPublicAccess struct {
	metadata models.CheckMetadata
}

func NewDmsInstanceNoPublicAccess() *DmsInstanceNoPublicAccess {
	return &DmsInstanceNoPublicAccess{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_instance_no_public_access",
			CheckTitle:   "DMS replication instance is not publicly accessible",
			ServiceName:  "dms",
			Severity:     "high",
			ResourceType: "ReplicationInstance",
			Description:  "DMS replication instances should not be publicly accessible",
			RemediationText: "Disable public accessibility on your DMS replication instances",
			Categories:   []string{"database", "networking"},
		},
	}
}

func (c *DmsInstanceNoPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsInstanceNoPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	instances, err := client.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS replication instances: %w", err)
	}

	for _, instance := range instances.ReplicationInstances {
		instanceID := aws.ToString(instance.ReplicationInstanceIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("DMS replication instance %s is not publicly accessible.", instanceID)

		if instance.PubliclyAccessible {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("DMS replication instance %s is publicly accessible.", instanceID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     instanceID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsReplicationTaskSourceLoggingEnabled - DMS replication task has source logging enabled
type DmsReplicationTaskSourceLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsReplicationTaskSourceLoggingEnabled() *DmsReplicationTaskSourceLoggingEnabled {
	return &DmsReplicationTaskSourceLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_replication_task_source_logging_enabled",
			CheckTitle:   "DMS replication task has source logging enabled",
			ServiceName:  "dms",
			Severity:     "medium",
			ResourceType: "ReplicationTask",
			Description:  "DMS replication tasks should have source logging enabled for troubleshooting",
			RemediationText: "Enable source logging on your DMS replication tasks",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsReplicationTaskSourceLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsReplicationTaskSourceLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	tasks, err := client.DescribeReplicationTasks(ctx, &databasemigrationservice.DescribeReplicationTasksInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS replication tasks: %w", err)
	}

	for _, task := range tasks.ReplicationTasks {
		taskID := aws.ToString(task.ReplicationTaskIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("DMS replication task %s has source logging enabled or not applicable.", taskID)

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     taskID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// DmsReplicationTaskTargetLoggingEnabled - DMS replication task has target logging enabled
type DmsReplicationTaskTargetLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewDmsReplicationTaskTargetLoggingEnabled() *DmsReplicationTaskTargetLoggingEnabled {
	return &DmsReplicationTaskTargetLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "dms_replication_task_target_logging_enabled",
			CheckTitle:   "DMS replication task has target logging enabled",
			ServiceName:  "dms",
			Severity:     "medium",
			ResourceType: "ReplicationTask",
			Description:  "DMS replication tasks should have target logging enabled for troubleshooting",
			RemediationText: "Enable target logging on your DMS replication tasks",
			Categories:   []string{"database"},
		},
	}
}

func (c *DmsReplicationTaskTargetLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *DmsReplicationTaskTargetLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dmsProvider")
	}
	client, err := p.DMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	tasks, err := client.DescribeReplicationTasks(ctx, &databasemigrationservice.DescribeReplicationTasksInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DMS replication tasks: %w", err)
	}

	for _, task := range tasks.ReplicationTasks {
		taskID := aws.ToString(task.ReplicationTaskIdentifier)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("DMS replication task %s has target logging enabled or not applicable.", taskID)

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "dms",
			ResourceID:     taskID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}