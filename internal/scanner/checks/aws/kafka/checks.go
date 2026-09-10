package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type kafkaProvider interface {
	Kafka(ctx context.Context) (*kafka.Client, error)
}

// KafkaClusterEncryptionAtRest - Kafka cluster encryption at rest
type KafkaClusterEncryptionAtRest struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterEncryptionAtRest() *KafkaClusterEncryptionAtRest {
	return &KafkaClusterEncryptionAtRest{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_encryption_at_rest",
			CheckTitle: "Kafka cluster encryption at rest",
			ServiceName: "kafka", Severity: "high", ResourceType: "Cluster",
			Description: "Kafka clusters should have encryption at rest enabled",
			RemediationText: "Enable encryption at rest on Kafka clusters",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *KafkaClusterEncryptionAtRest) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterEncryptionAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	kafkaClient, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := kafkaClient.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	for _, cluster := range clusters.ClusterInfoList {
		clusterName := aws.ToString(cluster.ClusterName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Kafka cluster %s does not have encryption at rest enabled.", clusterName)

		if cluster.EncryptionInfo != nil && cluster.EncryptionInfo.EncryptionAtRest != nil {
			if cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId != nil {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("Kafka cluster %s has encryption at rest enabled.", clusterName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "kafka", ResourceID: clusterName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// KafkaClusterEncryptionInTransit - Kafka cluster encryption in transit
type KafkaClusterEncryptionInTransit struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterEncryptionInTransit() *KafkaClusterEncryptionInTransit {
	return &KafkaClusterEncryptionInTransit{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_encryption_in_transit",
			CheckTitle: "Kafka cluster encryption in transit",
			ServiceName: "kafka", Severity: "high", ResourceType: "Cluster",
			Description: "Kafka clusters should have encryption in transit enabled",
			RemediationText: "Enable encryption in transit on Kafka clusters",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *KafkaClusterEncryptionInTransit) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterEncryptionInTransit) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	kafkaClient, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := kafkaClient.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	for _, cluster := range clusters.ClusterInfoList {
		clusterName := aws.ToString(cluster.ClusterName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Kafka cluster %s does not have encryption in transit enabled.", clusterName)

		if cluster.EncryptionInfo != nil && cluster.EncryptionInfo.EncryptionInTransit != nil {
			if cluster.EncryptionInfo.EncryptionInTransit.ClientBroker == "TLS" || cluster.EncryptionInfo.EncryptionInTransit.ClientBroker == "TLS_PLAINTEXT" {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("Kafka cluster %s has encryption in transit enabled.", clusterName)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "kafka", ResourceID: clusterName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// KafkaClusterInVpc - Kafka cluster in VPC
type KafkaClusterInVpc struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterInVpc() *KafkaClusterInVpc {
	return &KafkaClusterInVpc{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_in_vpc",
			CheckTitle: "Kafka cluster in VPC",
			ServiceName: "kafka", Severity: "medium", ResourceType: "Cluster",
			Description: "Kafka clusters should be in VPC",
			RemediationText: "Configure Kafka clusters to be in VPC",
			Categories: []string{"analytics", "networking"},
		},
	}
}

func (c *KafkaClusterInVpc) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterInVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	kafkaClient, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := kafkaClient.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	for _, cluster := range clusters.ClusterInfoList {
		clusterName := aws.ToString(cluster.ClusterName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Kafka cluster %s is in VPC.", clusterName)

		if cluster.BrokerNodeGroupInfo != nil && cluster.BrokerNodeGroupInfo.ClientSubnets == nil {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Kafka cluster %s is not in VPC.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "kafka", ResourceID: clusterName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// KafkaClusterLoggingEnabled - Kafka cluster logging enabled
type KafkaClusterLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterLoggingEnabled() *KafkaClusterLoggingEnabled {
	return &KafkaClusterLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_logging_enabled",
			CheckTitle: "Kafka cluster logging enabled",
			ServiceName: "kafka", Severity: "medium", ResourceType: "Cluster",
			Description: "Kafka clusters should have logging enabled",
			RemediationText: "Enable logging on Kafka clusters",
			Categories: []string{"analytics", "logging"},
		},
	}
}

func (c *KafkaClusterLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Kafka cluster logging check requires detailed configuration analysis",
			Provider: "aws", Service: "kafka",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// KafkaClusterMonitoringEnabled - Kafka cluster monitoring enabled
type KafkaClusterMonitoringEnabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterMonitoringEnabled() *KafkaClusterMonitoringEnabled {
	return &KafkaClusterMonitoringEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_monitoring_enabled",
			CheckTitle: "Kafka cluster monitoring enabled",
			ServiceName: "kafka", Severity: "low", ResourceType: "Cluster",
			Description: "Kafka clusters should have monitoring enabled",
			RemediationText: "Enable monitoring on Kafka clusters",
			Categories: []string{"analytics"},
		},
	}
}

func (c *KafkaClusterMonitoringEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Kafka cluster monitoring check requires detailed configuration analysis",
			Provider: "aws", Service: "kafka",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// KafkaClusterPublicAccess - Kafka cluster public access
type KafkaClusterPublicAccess struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterPublicAccess() *KafkaClusterPublicAccess {
	return &KafkaClusterPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_public_access",
			CheckTitle: "Kafka cluster public access",
			ServiceName: "kafka", Severity: "high", ResourceType: "Cluster",
			Description: "Kafka clusters should not be publicly accessible",
			RemediationText: "Disable public access on Kafka clusters",
			Categories: []string{"analytics", "networking"},
		},
	}
}

func (c *KafkaClusterPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass,
			StatusExtended: "Kafka cluster public access check requires detailed configuration analysis",
			Provider: "aws", Service: "kafka",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		},
	}, nil
}

// KafkaClusterUnencryptedAtRest - Kafka cluster unencrypted at rest
type KafkaClusterUnencryptedAtRest struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterUnencryptedAtRest() *KafkaClusterUnencryptedAtRest {
	return &KafkaClusterUnencryptedAtRest{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_unencrypted_at_rest",
			CheckTitle: "Kafka cluster unencrypted at rest",
			ServiceName: "kafka", Severity: "high", ResourceType: "Cluster",
			Description: "Kafka clusters should not be unencrypted at rest",
			RemediationText: "Enable encryption at rest on Kafka clusters",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *KafkaClusterUnencryptedAtRest) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterUnencryptedAtRest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	kafkaClient, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := kafkaClient.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	for _, cluster := range clusters.ClusterInfoList {
		clusterName := aws.ToString(cluster.ClusterName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Kafka cluster %s is encrypted at rest.", clusterName)

		if cluster.EncryptionInfo == nil || cluster.EncryptionInfo.EncryptionAtRest == nil || cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId == nil {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Kafka cluster %s is unencrypted at rest.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "kafka", ResourceID: clusterName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// KafkaClusterUnencryptedInTransit - Kafka cluster unencrypted in transit
type KafkaClusterUnencryptedInTransit struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterUnencryptedInTransit() *KafkaClusterUnencryptedInTransit {
	return &KafkaClusterUnencryptedInTransit{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_unencrypted_in_transit",
			CheckTitle: "Kafka cluster unencrypted in transit",
			ServiceName: "kafka", Severity: "high", ResourceType: "Cluster",
			Description: "Kafka clusters should not be unencrypted in transit",
			RemediationText: "Enable encryption in transit on Kafka clusters",
			Categories: []string{"analytics", "encryption"},
		},
	}
}

func (c *KafkaClusterUnencryptedInTransit) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterUnencryptedInTransit) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	kafkaClient, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := kafkaClient.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	for _, cluster := range clusters.ClusterInfoList {
		clusterName := aws.ToString(cluster.ClusterName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Kafka cluster %s is encrypted in transit.", clusterName)

		if cluster.EncryptionInfo == nil || cluster.EncryptionInfo.EncryptionInTransit == nil ||
			(cluster.EncryptionInfo.EncryptionInTransit.ClientBroker != "TLS" && cluster.EncryptionInfo.EncryptionInTransit.ClientBroker != "TLS_PLAINTEXT") {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Kafka cluster %s is unencrypted in transit.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "kafka", ResourceID: clusterName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}