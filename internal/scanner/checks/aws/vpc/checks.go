package vpc

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// VpcPeeringRoutingTablesWithLeastPrivilege - VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes
type VpcPeeringRoutingTablesWithLeastPrivilege struct {
    metadata models.CheckMetadata
}

func NewVpcPeeringRoutingTablesWithLeastPrivilege() *VpcPeeringRoutingTablesWithLeastPrivilege {
    return &VpcPeeringRoutingTablesWithLeastPrivilege{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_peering_routing_tables_with_least_privilege",
            CheckTitle: "VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**AWS VPC peering** route tables are assessed for **least-privilege routing**. Routes that target `0.0.0.0/0` or an entire peer VPC CIDR are considered overly broad; only specific subnets or narrower prefixes should be advertised across the peering link.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcPeeringRoutingTablesWithLeastPrivilege) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcPeeringRoutingTablesWithLeastPrivilege) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcSubnetSeparatePrivatePublic - VPC has both public and private subnets
type VpcSubnetSeparatePrivatePublic struct {
    metadata models.CheckMetadata
}

func NewVpcSubnetSeparatePrivatePublic() *VpcSubnetSeparatePrivatePublic {
    return &VpcSubnetSeparatePrivatePublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_subnet_separate_private_public",
            CheckTitle: "VPC has both public and private subnets",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**Amazon VPCs** are assessed for network segmentation: at least one **public subnet** (internet-routable) and one **private subnet** (non-internet-routable).  It flags VPCs with no subnets, only public subnets, or only private subnets.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcSubnetSeparatePrivatePublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcSubnetSeparatePrivatePublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcVpnConnectionTunnelsUp - AWS Site-to-Site VPN connection has both tunnels up
type VpcVpnConnectionTunnelsUp struct {
    metadata models.CheckMetadata
}

func NewVpcVpnConnectionTunnelsUp() *VpcVpnConnectionTunnelsUp {
    return &VpcVpnConnectionTunnelsUp{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_vpn_connection_tunnels_up",
            CheckTitle: "AWS Site-to-Site VPN connection has both tunnels up",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**AWS Site-to-Site VPN** connections have two IPsec tunnels. This evaluates tunnel status and detects when any tunnel is not `UP`, indicating whether both tunnels are concurrently available for high availability.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcVpnConnectionTunnelsUp) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcVpnConnectionTunnelsUp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcEndpointConnectionsTrustBoundaries - VPC endpoint policy allows access only from trusted AWS accounts
type VpcEndpointConnectionsTrustBoundaries struct {
    metadata models.CheckMetadata
}

func NewVpcEndpointConnectionsTrustBoundaries() *VpcEndpointConnectionsTrustBoundaries {
    return &VpcEndpointConnectionsTrustBoundaries{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_endpoint_connections_trust_boundaries",
            CheckTitle: "VPC endpoint policy allows access only from trusted AWS accounts",
            ServiceName: "vpc",
            Severity: "high",
            Description: "**VPC endpoint policies** are assessed for restriction to configured **trusted AWS accounts**. If `Principal` values (including `*`) or account ARNs permit non-trusted principals, or conditions aren't sufficiently restrictive, the endpoint is identified. *Endpoints without editable policies are excluded.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcEndpointConnectionsTrustBoundaries) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcEndpointConnectionsTrustBoundaries) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcSubnetDifferentAz - VPC has subnets in more than one Availability Zone
type VpcSubnetDifferentAz struct {
    metadata models.CheckMetadata
}

func NewVpcSubnetDifferentAz() *VpcSubnetDifferentAz {
    return &VpcSubnetDifferentAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_subnet_different_az",
            CheckTitle: "VPC has subnets in more than one Availability Zone",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**VPCs** are assessed for **subnets spread across multiple Availability Zones**. The finding distinguishes VPCs with subnets confined to a single AZ or with no subnets from those with subnets in `2+` distinct AZs.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcSubnetDifferentAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcSubnetDifferentAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcEndpointMultiAzEnabled - Amazon VPC interface endpoint has subnets in multiple Availability Zones
type VpcEndpointMultiAzEnabled struct {
    metadata models.CheckMetadata
}

func NewVpcEndpointMultiAzEnabled() *VpcEndpointMultiAzEnabled {
    return &VpcEndpointMultiAzEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_endpoint_multi_az_enabled",
            CheckTitle: "Amazon VPC interface endpoint has subnets in multiple Availability Zones",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**VPC interface endpoints** are evaluated for whether their endpoint network interfaces are placed in **multiple subnets**, which implies distribution across different **Availability Zones**. Endpoints present in only one subnet are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcEndpointMultiAzEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcEndpointMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcDifferentRegions - VPCs are present in more than one region
type VpcDifferentRegions struct {
    metadata models.CheckMetadata
}

func NewVpcDifferentRegions() *VpcDifferentRegions {
    return &VpcDifferentRegions{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_different_regions",
            CheckTitle: "VPCs are present in more than one region",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "Non-default **VPCs** are evaluated across the account to determine whether they exist in **more than one region**. The result reflects if your custom network topology is regionally distributed or concentrated in a single region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcDifferentRegions) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcDifferentRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcFlowLogsEnabled - VPC flow logs are enabled
type VpcFlowLogsEnabled struct {
    metadata models.CheckMetadata
}

func NewVpcFlowLogsEnabled() *VpcFlowLogsEnabled {
    return &VpcFlowLogsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_flow_logs_enabled",
            CheckTitle: "VPC flow logs are enabled",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**AWS VPCs** have **Flow Logs** configured to capture IP traffic for their network interfaces and deliver records to a logging destination.  VPCs lacking an active flow log configuration are highlighted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcFlowLogsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcFlowLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcEndpointForEc2Enabled - VPC has an Amazon EC2 VPC endpoint
type VpcEndpointForEc2Enabled struct {
    metadata models.CheckMetadata
}

func NewVpcEndpointForEc2Enabled() *VpcEndpointForEc2Enabled {
    return &VpcEndpointForEc2Enabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_endpoint_for_ec2_enabled",
            CheckTitle: "VPC has an Amazon EC2 VPC endpoint",
            ServiceName: "vpc",
            Severity: "medium",
            Description: "**Amazon VPCs** are evaluated for an **interface VPC endpoint** to the **Amazon EC2 API** (`ec2`). Its presence indicates private EC2 API connectivity over **AWS PrivateLink** within the VPC.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcEndpointForEc2Enabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcEndpointForEc2Enabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcSubnetNoPublicIpByDefault - VPC subnet does not assign public IP addresses by default
type VpcSubnetNoPublicIpByDefault struct {
    metadata models.CheckMetadata
}

func NewVpcSubnetNoPublicIpByDefault() *VpcSubnetNoPublicIpByDefault {
    return &VpcSubnetNoPublicIpByDefault{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_subnet_no_public_ip_by_default",
            CheckTitle: "VPC subnet does not assign public IP addresses by default",
            ServiceName: "vpc",
            Severity: "high",
            Description: "**VPC subnets** where `MapPublicIpOnLaunch` is `true` automatically assign a public IPv4 address to instances at launch.  This identifies subnets configured for default public IP assignment.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcSubnetNoPublicIpByDefault) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcSubnetNoPublicIpByDefault) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// VpcEndpointServicesAllowedPrincipalsTrustBoundaries - VPC endpoint service allows only trusted principals or none
type VpcEndpointServicesAllowedPrincipalsTrustBoundaries struct {
    metadata models.CheckMetadata
}

func NewVpcEndpointServicesAllowedPrincipalsTrustBoundaries() *VpcEndpointServicesAllowedPrincipalsTrustBoundaries {
    return &VpcEndpointServicesAllowedPrincipalsTrustBoundaries{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "vpc_endpoint_services_allowed_principals_trust_boundaries",
            CheckTitle: "VPC endpoint service allows only trusted principals or none",
            ServiceName: "vpc",
            Severity: "high",
            Description: "**VPC endpoint services** are assessed for their **allowed principals**, comparing each to a configured set of trusted accounts and identifying any **untrusted principals** or a wildcard `*` present in the allowlist.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"vpc"},
        },
    }
}

func (c *VpcEndpointServicesAllowedPrincipalsTrustBoundaries) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *VpcEndpointServicesAllowedPrincipalsTrustBoundaries) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "vpc",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

