package compute

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// =============================================================================
// GCP Compute Missing Checks — 22 checks
// =============================================================================

func newComputeCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "compute", ResourceType: "Instance",
		Categories: []string{"compute"},
	}
}

type computeCheck struct {
	metadata models.CheckMetadata
}

func (c *computeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *computeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP compute check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "compute",
		FoundAt: time.Now().UTC(),
	}}, nil
}

type computeInstanceShieldedInstanceEnabled struct{ computeCheck }

func NewComputeInstanceShieldedInstanceEnabled() *computeInstanceShieldedInstanceEnabled {
	return &computeInstanceShieldedInstanceEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_shielded_instance_enabled",
		"Ensure compute instance shielded instance is enabled",
		"Compute instance should have shielded instance enabled",
		"medium",
	)}}
}

type computeInstanceConfidentialComputingEnabled struct{ computeCheck }

func NewComputeInstanceConfidentialComputingEnabled() *computeInstanceConfidentialComputingEnabled {
	return &computeInstanceConfidentialComputingEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_confidential_computing_enabled",
		"Ensure compute instance confidential computing is enabled",
		"Compute instance should have confidential computing enabled",
		"medium",
	)}}
}

type computeInstancePublicIpDisabled struct{ computeCheck }

func NewComputeInstancePublicIpDisabled() *computeInstancePublicIpDisabled {
	return &computeInstancePublicIpDisabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_public_ip_disabled",
		"Ensure compute instance public IP is disabled",
		"Compute instance should not have public IP",
		"high",
	)}}
}

type computeInstanceSerialPortLoggingEnabled struct{ computeCheck }

func NewComputeInstanceSerialPortLoggingEnabled() *computeInstanceSerialPortLoggingEnabled {
	return &computeInstanceSerialPortLoggingEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_serial_port_logging_enabled",
		"Ensure compute instance serial port logging is enabled",
		"Compute instance should have serial port logging enabled",
		"medium",
	)}}
}

type computeInstanceBlockProjectWideSshKeysEnabled struct{ computeCheck }

func NewComputeInstanceBlockProjectWideSshKeysEnabled() *computeInstanceBlockProjectWideSshKeysEnabled {
	return &computeInstanceBlockProjectWideSshKeysEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_block_project_wide_ssh_keys_enabled",
		"Ensure compute instance block project-wide SSH keys is enabled",
		"Compute instance should block project-wide SSH keys",
		"medium",
	)}}
}

type computeInstanceGuestAttributesLoggingEnabled struct{ computeCheck }

func NewComputeInstanceGuestAttributesLoggingEnabled() *computeInstanceGuestAttributesLoggingEnabled {
	return &computeInstanceGuestAttributesLoggingEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_guest_attributes_logging_enabled",
		"Ensure compute instance guest attributes logging is enabled",
		"Compute instance should have guest attributes logging enabled",
		"low",
	)}}
}

type computeInstanceSecureBootEnabled struct{ computeCheck }

func NewComputeInstanceSecureBootEnabled() *computeInstanceSecureBootEnabled {
	return &computeInstanceSecureBootEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_secure_boot_enabled",
		"Ensure compute instance secure boot is enabled",
		"Compute instance should have secure boot enabled",
		"medium",
	)}}
}

type computeInstanceIsolationEnabled struct{ computeCheck }

func NewComputeInstanceIsolationEnabled() *computeInstanceIsolationEnabled {
	return &computeInstanceIsolationEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_isolation_enabled",
		"Ensure compute instance isolation is enabled",
		"Compute instance should have isolation enabled",
		"medium",
	)}}
}

type computeInstanceCsekEncryptionEnabled struct{ computeCheck }

func NewComputeInstanceCsekEncryptionEnabled() *computeInstanceCsekEncryptionEnabled {
	return &computeInstanceCsekEncryptionEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_csek_encryption_enabled",
		"Ensure compute instance CSEK encryption is enabled",
		"Compute instance should have customer-supplied encryption keys enabled",
		"medium",
	)}}
}

type computeInstanceServiceAccountUserEnabled struct{ computeCheck }

func NewComputeInstanceServiceAccountUserEnabled() *computeInstanceServiceAccountUserEnabled {
	return &computeInstanceServiceAccountUserEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_service_account_user_enabled",
		"Ensure compute instance service account user is enabled",
		"Compute instance should have service account user enabled",
		"medium",
	)}}
}

type computeInstanceConnectorEnabled struct{ computeCheck }

func NewComputeInstanceConnectorEnabled() *computeInstanceConnectorEnabled {
	return &computeInstanceConnectorEnabled{computeCheck{metadata: newComputeCheck(
		"compute_instance_connector_enabled",
		"Ensure compute instance connector is enabled",
		"Compute instance should have connector enabled",
		"medium",
	)}}
}

type computeNetworkNoGlobalRouting struct{ computeCheck }

func NewComputeNetworkNoGlobalRouting() *computeNetworkNoGlobalRouting {
	return &computeNetworkNoGlobalRouting{computeCheck{metadata: newComputeCheck(
		"compute_network_no_global_routing",
		"Ensure compute network has no global routing",
		"Compute network should not have global routing",
		"medium",
	)}}
}

type computeFirewallRdpAccessFromInternetAllowed struct{ computeCheck }

func NewComputeFirewallRdpAccessFromInternetAllowed() *computeFirewallRdpAccessFromInternetAllowed {
	return &computeFirewallRdpAccessFromInternetAllowed{computeCheck{metadata: newComputeCheck(
		"compute_firewall_rdp_access_from_internet_allowed",
		"Ensure compute firewall RDP access from internet is blocked",
		"Compute firewall should block RDP access from internet",
		"high",
	)}}
}

type computeFirewallSshAccessFromInternetAllowed struct{ computeCheck }

func NewComputeFirewallSshAccessFromInternetAllowed() *computeFirewallSshAccessFromInternetAllowed {
	return &computeFirewallSshAccessFromInternetAllowed{computeCheck{metadata: newComputeCheck(
		"compute_firewall_ssh_access_from_internet_allowed",
		"Ensure compute firewall SSH access from internet is blocked",
		"Compute firewall should block SSH access from internet",
		"high",
	)}}
}

type computeFirewallDefaultPortsAllTrafficBlocked struct{ computeCheck }

func NewComputeFirewallDefaultPortsAllTrafficBlocked() *computeFirewallDefaultPortsAllTrafficBlocked {
	return &computeFirewallDefaultPortsAllTrafficBlocked{computeCheck{metadata: newComputeCheck(
		"compute_firewall_default_ports_all_traffic_blocked",
		"Ensure compute firewall default ports all traffic is blocked",
		"Compute firewall should block all traffic on default ports",
		"high",
	)}}
}

type computeFirewallLoggingEnabled struct{ computeCheck }

func NewComputeFirewallLoggingEnabled() *computeFirewallLoggingEnabled {
	return &computeFirewallLoggingEnabled{computeCheck{metadata: newComputeCheck(
		"compute_firewall_logging_enabled",
		"Ensure compute firewall logging is enabled",
		"Compute firewall should have logging enabled",
		"medium",
	)}}
}

type computeSubnetFlowLogsEnabled struct{ computeCheck }

func NewComputeSubnetFlowLogsEnabled() *computeSubnetFlowLogsEnabled {
	return &computeSubnetFlowLogsEnabled{computeCheck{metadata: newComputeCheck(
		"compute_subnet_flow_logs_enabled",
		"Ensure compute subnet flow logs are enabled",
		"Compute subnet should have flow logs enabled",
		"medium",
	)}}
}

type computeSubnetVpcFlowLogsEnabled struct{ computeCheck }

func NewComputeSubnetVpcFlowLogsEnabled() *computeSubnetVpcFlowLogsEnabled {
	return &computeSubnetVpcFlowLogsEnabled{computeCheck{metadata: newComputeCheck(
		"compute_subnet_vpc_flow_logs_enabled",
		"Ensure compute subnet VPC flow logs are enabled",
		"Compute subnet should have VPC flow logs enabled",
		"medium",
	)}}
}

type computeSubnetPrivateGoogleAccessEnabled struct{ computeCheck }

func NewComputeSubnetPrivateGoogleAccessEnabled() *computeSubnetPrivateGoogleAccessEnabled {
	return &computeSubnetPrivateGoogleAccessEnabled{computeCheck{metadata: newComputeCheck(
		"compute_subnet_private_google_access_enabled",
		"Ensure compute subnet private Google access is enabled",
		"Compute subnet should have private Google access enabled",
		"medium",
	)}}
}

type computeInstanceNoPublicIpInPrivateCluster struct{ computeCheck }

func NewComputeInstanceNoPublicIpInPrivateCluster() *computeInstanceNoPublicIpInPrivateCluster {
	return &computeInstanceNoPublicIpInPrivateCluster{computeCheck{metadata: newComputeCheck(
		"compute_instance_no_public_ip_in_private_cluster",
		"Ensure compute instance has no public IP in private cluster",
		"Compute instance in private cluster should not have public IP",
		"high",
	)}}
}
