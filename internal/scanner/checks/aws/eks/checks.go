package eks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type eksProvider interface {
	EKS(ctx context.Context) (*eks.Client, error)
}

// EksClusterNotPubliclyAccessible - EKS cluster endpoint is not publicly accessible from 0.0.0.0/0
type EksClusterNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewEksClusterNotPubliclyAccessible() *EksClusterNotPubliclyAccessible {
	return &EksClusterNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_not_publicly_accessible",
			CheckTitle: "EKS cluster endpoint is not publicly accessible from 0.0.0.0/0",
			ServiceName: "eks",
			Severity: "high",
			Description: "Amazon EKS cluster API server endpoint is evaluated for unrestricted Internet access.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		isPublic := false
		if cluster.Cluster != nil && cluster.Cluster.ResourcesVpcConfig != nil {
			publicAccess := cluster.Cluster.ResourcesVpcConfig.PublicAccessCidrs
			for _, cidr := range publicAccess {
				if cidr == "0.0.0.0/0" {
					isPublic = true
					break
				}
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EKS cluster %s is not publicly accessible from 0.0.0.0/0.", clusterName)
		if isPublic {
			status = models.StatusFail
			ext = fmt.Sprintf("EKS cluster %s is publicly accessible from 0.0.0.0/0.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterPrivateNodesEnabled - EKS cluster has private endpoint access enabled
type EksClusterPrivateNodesEnabled struct {
	metadata models.CheckMetadata
}

func NewEksClusterPrivateNodesEnabled() *EksClusterPrivateNodesEnabled {
	return &EksClusterPrivateNodesEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_private_nodes_enabled",
			CheckTitle: "EKS cluster has private endpoint access enabled",
			ServiceName: "eks",
			Severity: "high",
			Description: "Amazon EKS cluster has private endpoint access enabled for the Kubernetes API server.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterPrivateNodesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterPrivateNodesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		hasPrivateAccess := false
		if cluster.Cluster != nil && cluster.Cluster.ResourcesVpcConfig != nil {
			hasPrivateAccess = cluster.Cluster.ResourcesVpcConfig.EndpointPrivateAccess
		}

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s does not have private endpoint access enabled.", clusterName)
		if hasPrivateAccess {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s has private endpoint access enabled.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterDeletionProtectionEnabled - EKS cluster has deletion protection enabled
type EksClusterDeletionProtectionEnabled struct {
	metadata models.CheckMetadata
}

func NewEksClusterDeletionProtectionEnabled() *EksClusterDeletionProtectionEnabled {
	return &EksClusterDeletionProtectionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_deletion_protection_enabled",
			CheckTitle: "EKS cluster has deletion protection enabled",
			ServiceName: "eks",
			Severity: "medium",
			Description: "Amazon EKS cluster has deletion protection enabled.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterDeletionProtectionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterDeletionProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		hasDeletionProtection := false
		if cluster.Cluster != nil {
			for _, tag := range cluster.Cluster.Tags {
				if tag == "deletion_protection" {
					hasDeletionProtection = true
					break
				}
			}
		}

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s does not have deletion protection enabled.", clusterName)
		if hasDeletionProtection {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s has deletion protection enabled.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksControlPlaneLoggingAllTypesEnabled - EKS control plane logging is enabled for all types
type EksControlPlaneLoggingAllTypesEnabled struct {
	metadata models.CheckMetadata
}

func NewEksControlPlaneLoggingAllTypesEnabled() *EksControlPlaneLoggingAllTypesEnabled {
	return &EksControlPlaneLoggingAllTypesEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_control_plane_logging_all_types_enabled",
			CheckTitle: "EKS control plane logging is enabled for all types",
			ServiceName: "eks",
			Severity: "medium",
			Description: "Amazon EKS control plane logging is enabled for all log types.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksControlPlaneLoggingAllTypesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksControlPlaneLoggingAllTypesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		allEnabled := true
		enabledTypes := []string{}
		disabledTypes := []string{}

		if cluster.Cluster != nil && cluster.Cluster.Logging != nil {
			for _, logSetup := range cluster.Cluster.Logging.ClusterLogging {
				for _, logType := range logSetup.Types {
					if aws.ToBool(logSetup.Enabled) {
						enabledTypes = append(enabledTypes, string(logType))
					} else {
						disabledTypes = append(disabledTypes, string(logType))
						allEnabled = false
					}
				}
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("EKS cluster %s has all control plane logging types enabled: %v.", clusterName, enabledTypes)
		if !allEnabled {
			status = models.StatusFail
			ext = fmt.Sprintf("EKS cluster %s has disabled logging types: %v.", clusterName, disabledTypes)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterKmsCmkEncryptionInSecretsEnabled - EKS cluster has KMS CMK encryption for secrets
type EksClusterKmsCmkEncryptionInSecretsEnabled struct {
	metadata models.CheckMetadata
}

func NewEksClusterKmsCmkEncryptionInSecretsEnabled() *EksClusterKmsCmkEncryptionInSecretsEnabled {
	return &EksClusterKmsCmkEncryptionInSecretsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_kms_cmk_encryption_in_secrets_enabled",
			CheckTitle: "EKS cluster has KMS CMK encryption for secrets",
			ServiceName: "eks",
			Severity: "high",
			Description: "Amazon EKS cluster has KMS CMK encryption for Kubernetes secrets.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterKmsCmkEncryptionInSecretsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterKmsCmkEncryptionInSecretsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		hasEncryption := false
		if cluster.Cluster != nil && cluster.Cluster.EncryptionConfig != nil {
			for _, enc := range cluster.Cluster.EncryptionConfig {
				if enc.Resources != nil {
					for _, resource := range enc.Resources {
						if resource == "secrets" {
							hasEncryption = true
							break
						}
					}
				}
			}
		}

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s does not have KMS CMK encryption for secrets.", clusterName)
		if hasEncryption {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s has KMS CMK encryption for secrets.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterUsesASupportedVersion - EKS cluster uses a supported Kubernetes version
type EksClusterUsesASupportedVersion struct {
	metadata models.CheckMetadata
}

func NewEksClusterUsesASupportedVersion() *EksClusterUsesASupportedVersion {
	return &EksClusterUsesASupportedVersion{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_uses_a_supported_version",
			CheckTitle: "EKS cluster uses a supported Kubernetes version",
			ServiceName: "eks",
			Severity: "high",
			Description: "Amazon EKS cluster uses a supported Kubernetes version.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterUsesASupportedVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterUsesASupportedVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// Get supported versions
	versions, err := eksClient.DescribeAddonVersions(ctx, &eks.DescribeAddonVersionsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao obter versões suportadas: %w", err)
	}

	_ = versions

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		version := ""
		if cluster.Cluster != nil {
			version = aws.ToString(cluster.Cluster.Version)
		}

		// Check if version is supported (simplified - would need to check against AWS docs)
		isSupported := version != "" && version >= "1.21"

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s uses unsupported version %s.", clusterName, version)
		if isSupported {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s uses supported version %s.", clusterName, version)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterVpcCniNetworkPolicyEnforced - EKS cluster VPC CNI enforces network policies
type EksClusterVpcCniNetworkPolicyEnforced struct {
	metadata models.CheckMetadata
}

func NewEksClusterVpcCniNetworkPolicyEnforced() *EksClusterVpcCniNetworkPolicyEnforced {
	return &EksClusterVpcCniNetworkPolicyEnforced{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_vpc_cni_network_policy_enforced",
			CheckTitle: "EKS cluster VPC CNI enforces network policies",
			ServiceName: "eks",
			Severity: "medium",
			Description: "Amazon EKS cluster VPC CNI add-on enforces Kubernetes network policies.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterVpcCniNetworkPolicyEnforced) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterVpcCniNetworkPolicyEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		// Check if vpc-cni addon exists and has network policy enabled
		addons, err := eksClient.ListAddons(ctx, &eks.ListAddonsInput{
			ClusterName: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		hasNetworkPolicy := false
		for _, addonName := range addons.Addons {
			if addonName == "vpc-cni" {
				addon, err := eksClient.DescribeAddon(ctx, &eks.DescribeAddonInput{
					ClusterName: aws.String(clusterName),
					AddonName: aws.String(addonName),
				})
				if err != nil {
					continue
				}
				if addon.Addon != nil && addon.Addon.ConfigurationValues != nil {
					config := aws.ToString(addon.Addon.ConfigurationValues)
					if config != "" {
						// Check for enableNetworkPolicy=true in config
						hasNetworkPolicy = contains(config, "enableNetworkPolicy=true") || contains(config, "\"enableNetworkPolicy\": \"true\"")
					}
				}
				break
			}
		}

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s VPC CNI does not enforce network policies.", clusterName)
		if hasNetworkPolicy {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s VPC CNI enforces network policies.", clusterName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// EksClusterNetworkPolicyEnabled - EKS cluster has network policy enabled
type EksClusterNetworkPolicyEnabled struct {
	metadata models.CheckMetadata
}

func NewEksClusterNetworkPolicyEnabled() *EksClusterNetworkPolicyEnabled {
	return &EksClusterNetworkPolicyEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws",
			CheckID: "eks_cluster_network_policy_enabled",
			CheckTitle: "EKS cluster has network policy enabled",
			ServiceName: "eks",
			Severity: "medium",
			Description: "Amazon EKS cluster has network policy enabled via cluster security group.",
			RemediationText: "See AWS documentation for remediation",
			Categories: []string{"eks"},
		},
	}
}

func (c *EksClusterNetworkPolicyEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *EksClusterNetworkPolicyEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(eksProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa eksProvider")
	}
	eksClient, err := p.EKS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	clusters, err := eksClient.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao listar clusters EKS: %w", err)
	}

	for _, clusterName := range clusters.Clusters {
		cluster, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		hasNetworkPolicy := false
		sgID := ""
		if cluster.Cluster != nil && cluster.Cluster.ResourcesVpcConfig != nil {
			sgID = aws.ToString(cluster.Cluster.ResourcesVpcConfig.ClusterSecurityGroupId)
			hasNetworkPolicy = sgID != ""
		}

		status := models.StatusFail
		ext := fmt.Sprintf("EKS cluster %s does not have a Network Policy. Cluster security group ID is not set.", clusterName)
		if hasNetworkPolicy {
			status = models.StatusPass
			ext = fmt.Sprintf("EKS cluster %s has a Network Policy with the security group %s.", clusterName, sgID)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID,
			Title: c.metadata.CheckTitle,
			Description: c.metadata.Description,
			Severity: c.metadata.Severity,
			Status: status,
			StatusExtended: ext,
			Provider: "aws",
			Service: "eks",
			ResourceID: clusterName,
			Remediation: c.metadata.RemediationText,
			Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}