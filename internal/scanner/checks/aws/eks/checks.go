package eks

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

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
            Description: "**Amazon EKS** cluster API server endpoint is evaluated for **unrestricted Internet access**, specifically when the public endpoint permits connections from `0.0.0.0/0` instead of private access or limited CIDR ranges.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
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
            Description: "**Amazon EKS cluster** has **private endpoint access** enabled for the **Kubernetes API server**, allowing control plane traffic to use a VPC-resolved private endpoint.  The check evaluates the cluster's `endpointPrivateAccess` setting.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterPrivateNodesEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterPrivateNodesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
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
            Severity: "high",
            Description: "**Amazon EKS clusters** have **deletion protection** enabled blocking cluster removal until protection is explicitly disabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterDeletionProtectionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterDeletionProtectionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EksControlPlaneLoggingAllTypesEnabled - EKS cluster has control plane logging enabled for api, audit, authenticator, controllerManager, and scheduler
type EksControlPlaneLoggingAllTypesEnabled struct {
    metadata models.CheckMetadata
}

func NewEksControlPlaneLoggingAllTypesEnabled() *EksControlPlaneLoggingAllTypesEnabled {
    return &EksControlPlaneLoggingAllTypesEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eks_control_plane_logging_all_types_enabled",
            CheckTitle: "EKS cluster has control plane logging enabled for api, audit, authenticator, controllerManager, and scheduler",
            ServiceName: "eks",
            Severity: "medium",
            Description: "**Amazon EKS clusters** are evaluated for **control plane logging** coverage of required types: `api`, `audit`, `authenticator`, `controllerManager`, `scheduler`.  The finding identifies clusters where any of these log types are not configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksControlPlaneLoggingAllTypesEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksControlPlaneLoggingAllTypesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EksClusterKmsCmkEncryptionInSecretsEnabled - EKS cluster has Kubernetes secrets encryption enabled
type EksClusterKmsCmkEncryptionInSecretsEnabled struct {
    metadata models.CheckMetadata
}

func NewEksClusterKmsCmkEncryptionInSecretsEnabled() *EksClusterKmsCmkEncryptionInSecretsEnabled {
    return &EksClusterKmsCmkEncryptionInSecretsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eks_cluster_kms_cmk_encryption_in_secrets_enabled",
            CheckTitle: "EKS cluster has Kubernetes secrets encryption enabled",
            ServiceName: "eks",
            Severity: "medium",
            Description: "**Amazon EKS** clusters configure **AWS KMS envelope encryption** so Kubernetes **Secrets** are stored in etcd as ciphertext at rest.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterKmsCmkEncryptionInSecretsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterKmsCmkEncryptionInSecretsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
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
            Description: "Amazon EKS clusters use a **supported Kubernetes version** at or above the defined baseline (e.g., `1.28+`). The evaluation compares each cluster's Kubernetes minor version to the minimum supported level and highlights clusters running below that baseline.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterUsesASupportedVersion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterUsesASupportedVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EksClusterVpcCniNetworkPolicyEnforced - EKS cluster enforces Kubernetes network policies through the Amazon VPC CNI add-on
type EksClusterVpcCniNetworkPolicyEnforced struct {
    metadata models.CheckMetadata
}

func NewEksClusterVpcCniNetworkPolicyEnforced() *EksClusterVpcCniNetworkPolicyEnforced {
    return &EksClusterVpcCniNetworkPolicyEnforced{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eks_cluster_vpc_cni_network_policy_enforced",
            CheckTitle: "EKS cluster enforces Kubernetes network policies through the Amazon VPC CNI add-on",
            ServiceName: "eks",
            Severity: "medium",
            Description: "**Amazon EKS clusters** are evaluated for whether the **Amazon VPC CNI** managed add-on sets `enableNetworkPolicy` to `true`, which is what makes the CNI enforce Kubernetes `NetworkPolicy` resources. The policy objects themselves live in the cluster and are not exposed by the EKS API, so only this enforcement precondition is verified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterVpcCniNetworkPolicyEnforced) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterVpcCniNetworkPolicyEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
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
            Severity: "high",
            Description: "**Amazon EKS clusters** are evaluated for **pod-level network isolation** via Kubernetes `NetworkPolicy`, indicating whether traffic between pods and namespaces is restricted according to defined rules.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eks"},
        },
    }
}

func (c *EksClusterNetworkPolicyEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EksClusterNetworkPolicyEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eks",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

