package emr

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// EmrClusterAccountPublicBlockEnabled - EMR account has Block Public Access enabled
type EmrClusterAccountPublicBlockEnabled struct {
    metadata models.CheckMetadata
}

func NewEmrClusterAccountPublicBlockEnabled() *EmrClusterAccountPublicBlockEnabled {
    return &EmrClusterAccountPublicBlockEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "emr_cluster_account_public_block_enabled",
            CheckTitle: "EMR account has Block Public Access enabled",
            ServiceName: "emr",
            Severity: "high",
            Description: "Amazon EMR account-level **Block Public Access** configuration is assessed per Region. When `BlockPublicSecurityGroupRules` is enabled, clusters cannot use security groups that allow inbound public sources (`0.0.0.0/0`, `::/0`) except on permitted ports.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"emr"},
        },
    }
}

func (c *EmrClusterAccountPublicBlockEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EmrClusterAccountPublicBlockEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "emr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EmrClusterPubliclyAccesible - EMR cluster is not publicly accessible
type EmrClusterPubliclyAccesible struct {
    metadata models.CheckMetadata
}

func NewEmrClusterPubliclyAccesible() *EmrClusterPubliclyAccesible {
    return &EmrClusterPubliclyAccesible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "emr_cluster_publicly_accesible",
            CheckTitle: "EMR cluster is not publicly accessible",
            ServiceName: "emr",
            Severity: "medium",
            Description: "**Amazon EMR clusters** are assessed for **public network exposure** by examining master and core/task node security groups for inbound rules that allow any source (`0.0.0.0/0` or `::/0`).  Only active clusters are considered, and findings identify exposure via the specific security groups attached to the cluster nodes.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"emr"},
        },
    }
}

func (c *EmrClusterPubliclyAccesible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EmrClusterPubliclyAccesible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "emr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EmrClusterMasterNodesNoPublicIp - EMR Cluster without Public IP.
type EmrClusterMasterNodesNoPublicIp struct {
    metadata models.CheckMetadata
}

func NewEmrClusterMasterNodesNoPublicIp() *EmrClusterMasterNodesNoPublicIp {
    return &EmrClusterMasterNodesNoPublicIp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "emr_cluster_master_nodes_no_public_ip",
            CheckTitle: "EMR Cluster without Public IP.",
            ServiceName: "emr",
            Severity: "medium",
            Description: "**Amazon EMR clusters** in non-terminated states are assessed for **public IP assignment** on cluster nodes (primary and workers). The finding identifies clusters whose instances are reachable via public IPs rather than private VPC addresses.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"emr"},
        },
    }
}

func (c *EmrClusterMasterNodesNoPublicIp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EmrClusterMasterNodesNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "emr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

