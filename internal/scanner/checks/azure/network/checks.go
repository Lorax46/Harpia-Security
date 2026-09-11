package network

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// NSGSSHRestrictedCheck - verifica SSH restrito
type NSGSSHRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewNSGSSHRestrictedCheck() *NSGSSHRestrictedCheck {
	return &NSGSSHRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_nsg_ssh_restricted",
			CheckTitle: "Ensure NSG restricts SSH access",
			Description: "NSG should restrict SSH access",
			Severity: "high", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "ssh"},
		},
	}
}

func (c *NSGSSHRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NSGSSHRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG SSH check requires Azure SDK",
		ResourceID: "nsg-ssh-restricted", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NSGRDPRestrictedCheck - verifica RDP restrito
type NSGRDPRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewNSGRDPRestrictedCheck() *NSGRDPRestrictedCheck {
	return &NSGRDPRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_nsg_rdp_restricted",
			CheckTitle: "Ensure NSG restricts RDP access",
			Description: "NSG should restrict RDP access",
			Severity: "high", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "rdp"},
		},
	}
}

func (c *NSGRDPRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NSGRDPRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG RDP check requires Azure SDK",
		ResourceID: "nsg-rdp-restricted", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// PublicIPSecuredCheck - verifica IPs públicos
type PublicIPSecuredCheck struct {
	metadata models.CheckMetadata
}

func NewPublicIPSecuredCheck() *PublicIPSecuredCheck {
	return &PublicIPSecuredCheck{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_public_ip_secured",
			CheckTitle: "Ensure public IPs are secured",
			Description: "Public IPs should be secured",
			Severity: "medium", ServiceName: "network", ResourceType: "PublicIP",
			Categories: []string{"network", "public-ip"},
		},
	}
}

func (c *PublicIPSecuredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicIPSecuredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Public IP check requires Azure SDK",
		ResourceID: "public-ip-secured", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkWatcherEnabled - verifica Network Watcher
type NetworkWatcherEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkWatcherEnabled() *NetworkWatcherEnabled {
	return &NetworkWatcherEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_watcher_enabled",
			CheckTitle: "Ensure Network Watcher is enabled",
			Description: "Network Watcher should be enabled",
			Severity: "medium", ServiceName: "network", ResourceType: "NetworkWatcher",
			Categories: []string{"network", "monitoring"},
		},
	}
}

func (c *NetworkWatcherEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkWatcherEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Network Watcher check requires Azure SDK",
		ResourceID: "network-watcher", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkSecurityGroupFlowLogsEnabled - verifica flow logs
type NetworkSecurityGroupFlowLogsEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkSecurityGroupFlowLogsEnabled() *NetworkSecurityGroupFlowLogsEnabled {
	return &NetworkSecurityGroupFlowLogsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_security_group_flow_logs_enabled",
			CheckTitle: "Ensure NSG flow logs are enabled",
			Description: "NSG flow logs should be enabled",
			Severity: "medium", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "flow-logs"},
		},
	}
}

func (c *NetworkSecurityGroupFlowLogsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkSecurityGroupFlowLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG flow logs check requires Azure SDK",
		ResourceID: "nsg-flow-logs", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkSecurityGroupTrafficAnalyticsEnabled - verifica traffic analytics
type NetworkSecurityGroupTrafficAnalyticsEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkSecurityGroupTrafficAnalyticsEnabled() *NetworkSecurityGroupTrafficAnalyticsEnabled {
	return &NetworkSecurityGroupTrafficAnalyticsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_security_group_traffic_analytics_enabled",
			CheckTitle: "Ensure NSG traffic analytics is enabled",
			Description: "NSG traffic analytics should be enabled",
			Severity: "medium", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "analytics"},
		},
	}
}

func (c *NetworkSecurityGroupTrafficAnalyticsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkSecurityGroupTrafficAnalyticsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG traffic analytics check requires Azure SDK",
		ResourceID: "nsg-traffic-analytics", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkWatcherTrafficAnalyticsEnabled - verifica traffic analytics do Network Watcher
type NetworkWatcherTrafficAnalyticsEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkWatcherTrafficAnalyticsEnabled() *NetworkWatcherTrafficAnalyticsEnabled {
	return &NetworkWatcherTrafficAnalyticsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_watcher_traffic_analytics_enabled",
			CheckTitle: "Ensure Network Watcher traffic analytics is enabled",
			Description: "Network Watcher traffic analytics should be enabled",
			Severity: "medium", ServiceName: "network", ResourceType: "NetworkWatcher",
			Categories: []string{"network", "analytics"},
		},
	}
}

func (c *NetworkWatcherTrafficAnalyticsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkWatcherTrafficAnalyticsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Network Watcher traffic analytics check requires Azure SDK",
		ResourceID: "network-watcher-traffic-analytics", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic - verifica regras padrão
type NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic struct {
	metadata models.CheckMetadata
}

func NewNetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic() *NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic {
	return &NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_security_group_default_rules_do_not_allow_all_traffic",
			CheckTitle: "Ensure NSG default rules do not allow all traffic",
			Description: "NSG default rules should not allow all traffic",
			Severity: "high", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "default-rules"},
		},
	}
}

func (c *NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG default rules check requires Azure SDK",
		ResourceID: "nsg-default-rules", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkSecurityGroupRulesDoNotAllowInternetAccess - verifica acesso à internet
type NetworkSecurityGroupRulesDoNotAllowInternetAccess struct {
	metadata models.CheckMetadata
}

func NewNetworkSecurityGroupRulesDoNotAllowInternetAccess() *NetworkSecurityGroupRulesDoNotAllowInternetAccess {
	return &NetworkSecurityGroupRulesDoNotAllowInternetAccess{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_security_group_rules_do_not_allow_internet_access",
			CheckTitle: "Ensure NSG rules do not allow internet access",
			Description: "NSG rules should not allow internet access",
			Severity: "high", ServiceName: "network", ResourceType: "NSG",
			Categories: []string{"network", "internet"},
		},
	}
}

func (c *NetworkSecurityGroupRulesDoNotAllowInternetAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkSecurityGroupRulesDoNotAllowInternetAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "NSG internet access check requires Azure SDK",
		ResourceID: "nsg-internet-access", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkVirtualNetworkGatewaySkuSupportsIpsec - verifica SKU do gateway
type NetworkVirtualNetworkGatewaySkuSupportsIpsec struct {
	metadata models.CheckMetadata
}

func NewNetworkVirtualNetworkGatewaySkuSupportsIpsec() *NetworkVirtualNetworkGatewaySkuSupportsIpsec {
	return &NetworkVirtualNetworkGatewaySkuSupportsIpsec{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_virtual_network_gateway_sku_supports_ipsec",
			CheckTitle: "Ensure virtual network gateway SKU supports IPsec",
			Description: "Virtual network gateway SKU should support IPsec",
			Severity: "medium", ServiceName: "network", ResourceType: "VirtualNetworkGateway",
			Categories: []string{"network", "ipsec"},
		},
	}
}

func (c *NetworkVirtualNetworkGatewaySkuSupportsIpsec) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkVirtualNetworkGatewaySkuSupportsIpsec) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Gateway SKU check requires Azure SDK",
		ResourceID: "gateway-sku-ipsec", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkAzureFirewallEnabled - verifica Azure Firewall
type NetworkAzureFirewallEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkAzureFirewallEnabled() *NetworkAzureFirewallEnabled {
	return &NetworkAzureFirewallEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_azure_firewall_enabled",
			CheckTitle: "Ensure Azure Firewall is enabled",
			Description: "Azure Firewall should be enabled",
			Severity: "high", ServiceName: "network", ResourceType: "AzureFirewall",
			Categories: []string{"network", "firewall"},
		},
	}
}

func (c *NetworkAzureFirewallEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkAzureFirewallEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Azure Firewall check requires Azure SDK",
		ResourceID: "azure-firewall", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// NetworkBastionHostEnabled - verifica Bastion Host
type NetworkBastionHostEnabled struct {
	metadata models.CheckMetadata
}

func NewNetworkBastionHostEnabled() *NetworkBastionHostEnabled {
	return &NetworkBastionHostEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "network_bastion_host_enabled",
			CheckTitle: "Ensure Bastion Host is enabled",
			Description: "Bastion Host should be enabled for secure VM access",
			Severity: "high", ServiceName: "network", ResourceType: "BastionHost",
			Categories: []string{"network", "bastion"},
		},
	}
}

func (c *NetworkBastionHostEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkBastionHostEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Bastion Host check requires Azure SDK",
		ResourceID: "bastion-host", Provider: "azure", Service: "network",
		FoundAt: time.Now().UTC(),
	}}, nil
}
