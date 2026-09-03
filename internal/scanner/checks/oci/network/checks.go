package network

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// NetworkSecurityGroupIngressFromInternetToRdpPort - high
type NetworkSecurityGroupIngressFromInternetToRdpPort struct {
	metadata models.CheckMetadata
}

// NewNetworkSecurityGroupIngressFromInternetToRdpPort cria nova instância
func NewNetworkSecurityGroupIngressFromInternetToRdpPort() *NetworkSecurityGroupIngressFromInternetToRdpPort {
	return &NetworkSecurityGroupIngressFromInternetToRdpPort{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_security_group_ingress_from_internet_to_rdp_port",
			CheckTitle:     "Network security group restricts ingress from 0.0.0.0/0 to port 3389 (RDP)",
			ServiceName:    "network",
			Severity:       "high",
			Description:    "**OCI Network Security Groups** are evaluated for inbound source `0.0.0.0/0` permitting **RDP** on `TCP 3389`, including broad rules (all TCP or any p",
			RemediationText: "Eliminate open `0.0.0.0/0` rules. Restrict **RDP** to trusted IPs and only when necessary. Prefer **",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkSecurityGroupIngressFromInternetToRdpPort) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkSecurityGroupIngressFromInternetToRdpPort) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// NetworkSecurityGroupIngressFromInternetToSshPort - high
type NetworkSecurityGroupIngressFromInternetToSshPort struct {
	metadata models.CheckMetadata
}

// NewNetworkSecurityGroupIngressFromInternetToSshPort cria nova instância
func NewNetworkSecurityGroupIngressFromInternetToSshPort() *NetworkSecurityGroupIngressFromInternetToSshPort {
	return &NetworkSecurityGroupIngressFromInternetToSshPort{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_security_group_ingress_from_internet_to_ssh_port",
			CheckTitle:     "Network security group restricts ingress from 0.0.0.0/0 to port 22 (SSH)",
			ServiceName:    "network",
			Severity:       "high",
			Description:    "Network security groups with **ingress** from `0.0.0.0/0` exposing **SSH** are identified. This includes rules that explicitly permit `TCP` `22`, use ",
			RemediationText: "Enforce **least privilege**: limit SSH in NSG rules to trusted CIDRs or private networks. Prefer **b",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkSecurityGroupIngressFromInternetToSshPort) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkSecurityGroupIngressFromInternetToSshPort) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// NetworkSecurityListIngressFromInternetToRdpPort - high
type NetworkSecurityListIngressFromInternetToRdpPort struct {
	metadata models.CheckMetadata
}

// NewNetworkSecurityListIngressFromInternetToRdpPort cria nova instância
func NewNetworkSecurityListIngressFromInternetToRdpPort() *NetworkSecurityListIngressFromInternetToRdpPort {
	return &NetworkSecurityListIngressFromInternetToRdpPort{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_security_list_ingress_from_internet_to_rdp_port",
			CheckTitle:     "Security list restricts ingress from 0.0.0.0/0 to port 3389 (RDP)",
			ServiceName:    "network",
			Severity:       "high",
			Description:    "**OCI security lists** are evaluated for rules that permit **inbound RDP** from the Internet: any source `0.0.0.0/0` allowing **TCP 3389**-including r",
			RemediationText: "Block Internet access to RDP.  - Deny `0.0.0.0/0` to `3389`; allow only trusted CIDRs. - Prefer **pr",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkSecurityListIngressFromInternetToRdpPort) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkSecurityListIngressFromInternetToRdpPort) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// NetworkSecurityListIngressFromInternetToSshPort - high
type NetworkSecurityListIngressFromInternetToSshPort struct {
	metadata models.CheckMetadata
}

// NewNetworkSecurityListIngressFromInternetToSshPort cria nova instância
func NewNetworkSecurityListIngressFromInternetToSshPort() *NetworkSecurityListIngressFromInternetToSshPort {
	return &NetworkSecurityListIngressFromInternetToSshPort{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_security_list_ingress_from_internet_to_ssh_port",
			CheckTitle:     "Security list restricts ingress from 0.0.0.0/0 to port 22 (SSH)",
			ServiceName:    "network",
			Severity:       "high",
			Description:    "**OCI security lists** are evaluated for rules that permit **inbound SSH** from `0.0.0.0/0`. Any rule where the destination includes `TCP 22`-or broad",
			RemediationText: "Restrict **SSH** to trusted sources using least-privilege network rules; avoid `0.0.0.0/0`. Prefer *",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkSecurityListIngressFromInternetToSshPort) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkSecurityListIngressFromInternetToSshPort) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// NetworkVcnSubnetFlowLogsEnabled - medium
type NetworkVcnSubnetFlowLogsEnabled struct {
	metadata models.CheckMetadata
}

// NewNetworkVcnSubnetFlowLogsEnabled cria nova instância
func NewNetworkVcnSubnetFlowLogsEnabled() *NetworkVcnSubnetFlowLogsEnabled {
	return &NetworkVcnSubnetFlowLogsEnabled{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_vcn_subnet_flow_logs_enabled",
			CheckTitle:     "Subnet has VCN flow logging enabled",
			ServiceName:    "network",
			Severity:       "medium",
			Description:    "**OCI subnets** in a VCN have **network flow logging** configured. Evaluation considers an active `flowlogs` configuration targeting the `VCN` or the ",
			RemediationText: "Enable **VCN flow logs** for all subnets-prefer VCN-wide enablement for complete coverage-and route ",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkVcnSubnetFlowLogsEnabled) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkVcnSubnetFlowLogsEnabled) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// NetworkDefaultSecurityListRestrictsTraffic - high
type NetworkDefaultSecurityListRestrictsTraffic struct {
	metadata models.CheckMetadata
}

// NewNetworkDefaultSecurityListRestrictsTraffic cria nova instância
func NewNetworkDefaultSecurityListRestrictsTraffic() *NetworkDefaultSecurityListRestrictsTraffic {
	return &NetworkDefaultSecurityListRestrictsTraffic{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "network_default_security_list_restricts_traffic",
			CheckTitle:     "Default security list restricts all traffic except ICMP within VCN",
			ServiceName:    "network",
			Severity:       "high",
			Description:    "**OCI default security list** of each VCN is evaluated to allow only VCN-internal `ICMP`. Non-`ICMP` ingress from `0.0.0.0/0` or sources outside the V",
			RemediationText: "Adopt a **deny-by-default** stance on the default list: allow only VCN-local `ICMP` for diagnostics.",
			Categories:     []string{"network"},
		},
	}
}

// Metadata retorna os metadados
func (c *NetworkDefaultSecurityListRestrictsTraffic) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *NetworkDefaultSecurityListRestrictsTraffic) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

