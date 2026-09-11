package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafka/types"
)

// KafkaClusterEncryptionAtRestUsesCmk - verifica criptografia CMK
type KafkaClusterEncryptionAtRestUsesCmk struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterEncryptionAtRestUsesCmk() *KafkaClusterEncryptionAtRestUsesCmk {
	return &KafkaClusterEncryptionAtRestUsesCmk{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_encryption_at_rest_uses_cmk",
			CheckTitle: "Ensure Kafka uses CMK for encryption at rest",
			Description: "Kafka clusters should use customer-managed KMS keys",
			Severity: "medium", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Configure Kafka to use CMK for encryption",
			Categories: []string{"kafka", "encryption"},
		},
	}
}

func (c *KafkaClusterEncryptionAtRestUsesCmk) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterEncryptionAtRestUsesCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s does not use CMK", aws.ToString(cluster.ClusterName))
		if cluster.EncryptionInfo != nil && cluster.EncryptionInfo.EncryptionAtRest != nil {
			if cluster.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId != nil {
				status = models.StatusPass
				msg = fmt.Sprintf("Cluster %s uses CMK", aws.ToString(cluster.ClusterName))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterEnhancedMonitoringEnabled - verifica monitoramento aprimorado
type KafkaClusterEnhancedMonitoringEnabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterEnhancedMonitoringEnabled() *KafkaClusterEnhancedMonitoringEnabled {
	return &KafkaClusterEnhancedMonitoringEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_enhanced_monitoring_enabled",
			CheckTitle: "Ensure Kafka has enhanced monitoring enabled",
			Description: "Kafka clusters should have enhanced monitoring enabled",
			Severity: "low", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Enable enhanced monitoring for Kafka clusters",
			Categories: []string{"kafka", "monitoring"},
		},
	}
}

func (c *KafkaClusterEnhancedMonitoringEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterEnhancedMonitoringEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s does not have enhanced monitoring", aws.ToString(cluster.ClusterName))
		if cluster.EnhancedMonitoring == types.EnhancedMonitoringPerBroker {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s has enhanced monitoring", aws.ToString(cluster.ClusterName))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterInTransitEncryptionEnabled - verifica criptografia em trânsito
type KafkaClusterInTransitEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterInTransitEncryptionEnabled() *KafkaClusterInTransitEncryptionEnabled {
	return &KafkaClusterInTransitEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_in_transit_encryption_enabled",
			CheckTitle: "Ensure Kafka has in-transit encryption enabled",
			Description: "Kafka clusters should have in-transit encryption enabled",
			Severity: "high", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Enable in-transit encryption for Kafka clusters",
			Categories: []string{"kafka", "encryption"},
		},
	}
}

func (c *KafkaClusterInTransitEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterInTransitEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s does not have in-transit encryption", aws.ToString(cluster.ClusterName))
		if cluster.EncryptionInfo != nil && cluster.EncryptionInfo.EncryptionInTransit != nil {
			if cluster.EncryptionInfo.EncryptionInTransit.ClientBroker == types.ClientBrokerTls {
				status = models.StatusPass
				msg = fmt.Sprintf("Cluster %s has in-transit encryption", aws.ToString(cluster.ClusterName))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterIsPublic - verifica clusters públicos
type KafkaClusterIsPublic struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterIsPublic() *KafkaClusterIsPublic {
	return &KafkaClusterIsPublic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_is_public",
			CheckTitle: "Ensure Kafka clusters are not public",
			Description: "Kafka clusters should not be publicly accessible",
			Severity: "critical", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Remove public access from Kafka clusters",
			Categories: []string{"kafka", "public"},
		},
	}
}

func (c *KafkaClusterIsPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterIsPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusPass
		msg := fmt.Sprintf("Cluster %s is not public", aws.ToString(cluster.ClusterName))
		// Verificar conectividade pública via tags
		if cluster.Tags != nil {
			if _, hasPublic := cluster.Tags["public"]; hasPublic {
				status = models.StatusFail
				msg = fmt.Sprintf("Cluster %s is publicly accessible", aws.ToString(cluster.ClusterName))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterMutualTlsAuthenticationEnabled - verifica mTLS
type KafkaClusterMutualTlsAuthenticationEnabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterMutualTlsAuthenticationEnabled() *KafkaClusterMutualTlsAuthenticationEnabled {
	return &KafkaClusterMutualTlsAuthenticationEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_mutual_tls_authentication_enabled",
			CheckTitle: "Ensure Kafka has mutual TLS authentication",
			Description: "Kafka clusters should have mutual TLS authentication enabled",
			Severity: "medium", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Enable mutual TLS for Kafka clusters",
			Categories: []string{"kafka", "tls"},
		},
	}
}

func (c *KafkaClusterMutualTlsAuthenticationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterMutualTlsAuthenticationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusFail
		msg := fmt.Sprintf("Cluster %s does not have mTLS", aws.ToString(cluster.ClusterName))
		if cluster.ClientAuthentication != nil && cluster.ClientAuthentication.Tls != nil && cluster.ClientAuthentication.Tls.CertificateAuthorityArnList != nil {
			status = models.StatusPass
			msg = fmt.Sprintf("Cluster %s has mTLS enabled", aws.ToString(cluster.ClusterName))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterUnrestrictedAccessDisabled - verifica acesso irrestrito
type KafkaClusterUnrestrictedAccessDisabled struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterUnrestrictedAccessDisabled() *KafkaClusterUnrestrictedAccessDisabled {
	return &KafkaClusterUnrestrictedAccessDisabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_unrestricted_access_disabled",
			CheckTitle: "Ensure Kafka clusters do not have unrestricted access",
			Description: "Kafka clusters should not allow unrestricted access",
			Severity: "high", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Restrict access to Kafka clusters",
			Categories: []string{"kafka", "access"},
		},
	}
}

func (c *KafkaClusterUnrestrictedAccessDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterUnrestrictedAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusPass
		msg := fmt.Sprintf("Cluster %s has restricted access", aws.ToString(cluster.ClusterName))
		if cluster.Tags != nil {
			if _, hasPublic := cluster.Tags["public"]; hasPublic {
				status = models.StatusFail
				msg = fmt.Sprintf("Cluster %s has unrestricted access", aws.ToString(cluster.ClusterName))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// KafkaClusterUsesLatestVersion - verifica versão mais recente
type KafkaClusterUsesLatestVersion struct {
	metadata models.CheckMetadata
}

func NewKafkaClusterUsesLatestVersion() *KafkaClusterUsesLatestVersion {
	return &KafkaClusterUsesLatestVersion{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "kafka_cluster_uses_latest_version",
			CheckTitle: "Ensure Kafka clusters use latest version",
			Description: "Kafka clusters should use the latest supported version",
			Severity: "low", ServiceName: "kafka", ResourceType: "Cluster",
			RemediationText: "Upgrade Kafka clusters to latest version",
			Categories: []string{"kafka", "version"},
		},
	}
}

func (c *KafkaClusterUsesLatestVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *KafkaClusterUsesLatestVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kafkaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kafkaProvider")
	}
	client, err := p.Kafka(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListClusters(ctx, &kafka.ListClustersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cluster := range result.ClusterInfoList {
		status := models.StatusPass
		msg := fmt.Sprintf("Cluster %s uses version %s", aws.ToString(cluster.ClusterName), aws.ToString(cluster.CurrentVersion))
		// Versões mais antigas conhecidas
		oldVersions := map[string]bool{"2.6.2": true, "2.6.1": true, "2.6.0": true, "2.5.1": true, "2.4.1.1": true}
		if cluster.CurrentVersion != nil && oldVersions[*cluster.CurrentVersion] {
			status = models.StatusFail
			msg = fmt.Sprintf("Cluster %s uses older version %s", aws.ToString(cluster.ClusterName), aws.ToString(cluster.CurrentVersion))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(cluster.ClusterName), Provider: "aws", Service: "kafka",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
