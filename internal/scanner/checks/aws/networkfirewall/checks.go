package networkfirewall

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// NetworkfirewallPolicyDefaultActionFragmentedPackets - Network Firewall policy drops or forwards fragmented packets by default
type NetworkfirewallPolicyDefaultActionFragmentedPackets struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallPolicyDefaultActionFragmentedPackets() *NetworkfirewallPolicyDefaultActionFragmentedPackets {
    return &NetworkfirewallPolicyDefaultActionFragmentedPackets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_policy_default_action_fragmented_packets",
            CheckTitle: "Network Firewall policy drops or forwards fragmented packets by default",
            ServiceName: "networkfirewall",
            Severity: "high",
            Description: "**Network Firewall policies** are assessed for the `StatelessFragmentDefaultActions` setting to confirm **fragmented UDP packets** use `aws:drop` or `aws:forward_to_sfe`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallPolicyDefaultActionFragmentedPackets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallPolicyDefaultActionFragmentedPackets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallLoggingEnabled - Network Firewall has logging enabled
type NetworkfirewallLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallLoggingEnabled() *NetworkfirewallLoggingEnabled {
    return &NetworkfirewallLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_logging_enabled",
            CheckTitle: "Network Firewall has logging enabled",
            ServiceName: "networkfirewall",
            Severity: "high",
            Description: "**AWS Network Firewall** has stateful engine logging configured with at least one log type (`FLOW`, `ALERT`, or `TLS`) and an active log destination",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallPolicyDefaultActionFullPackets - Network Firewall firewall policy default stateless action for full packets is drop or forward
type NetworkfirewallPolicyDefaultActionFullPackets struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallPolicyDefaultActionFullPackets() *NetworkfirewallPolicyDefaultActionFullPackets {
    return &NetworkfirewallPolicyDefaultActionFullPackets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_policy_default_action_full_packets",
            CheckTitle: "Network Firewall firewall policy default stateless action for full packets is drop or forward",
            ServiceName: "networkfirewall",
            Severity: "high",
            Description: "**AWS Network Firewall policies** define a **stateless default action** for full packets. This evaluates whether unmatched packets are handled by `aws:drop` or `aws:forward_to_sfe`, meaning they are either discarded or sent to the stateful engine rather than allowed to pass.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallPolicyDefaultActionFullPackets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallPolicyDefaultActionFullPackets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallInAllVpc - VPC has Network Firewall enabled
type NetworkfirewallInAllVpc struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallInAllVpc() *NetworkfirewallInAllVpc {
    return &NetworkfirewallInAllVpc{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_in_all_vpc",
            CheckTitle: "VPC has Network Firewall enabled",
            ServiceName: "networkfirewall",
            Severity: "medium",
            Description: "**VPCs** with an **AWS Network Firewall** associated to the same VPC to inspect and filter network traffic.  Identifies VPCs that do not have a Network Firewall resource linked to them.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallInAllVpc) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallInAllVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallPolicyRuleGroupAssociated - Network Firewall policy has at least one rule group associated
type NetworkfirewallPolicyRuleGroupAssociated struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallPolicyRuleGroupAssociated() *NetworkfirewallPolicyRuleGroupAssociated {
    return &NetworkfirewallPolicyRuleGroupAssociated{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_policy_rule_group_associated",
            CheckTitle: "Network Firewall policy has at least one rule group associated",
            ServiceName: "networkfirewall",
            Severity: "high",
            Description: "Network Firewall policies have one or more **stateful** or **stateless rule groups** associated to define packet inspection and handling.  Policies with no rule groups are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallPolicyRuleGroupAssociated) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallPolicyRuleGroupAssociated) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallMultiAz - Network Firewall firewall is deployed across multiple Availability Zones
type NetworkfirewallMultiAz struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallMultiAz() *NetworkfirewallMultiAz {
    return &NetworkfirewallMultiAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_multi_az",
            CheckTitle: "Network Firewall firewall is deployed across multiple Availability Zones",
            ServiceName: "networkfirewall",
            Severity: "high",
            Description: "**AWS Network Firewall firewalls** are assessed for **multi-AZ deployment**, expecting subnet mappings in more than one Availability Zone.  A configuration with only one subnet mapping indicates a single-AZ firewall.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallMultiAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// NetworkfirewallDeletionProtection - Network Firewall has deletion protection enabled
type NetworkfirewallDeletionProtection struct {
    metadata models.CheckMetadata
}

func NewNetworkfirewallDeletionProtection() *NetworkfirewallDeletionProtection {
    return &NetworkfirewallDeletionProtection{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "networkfirewall_deletion_protection",
            CheckTitle: "Network Firewall has deletion protection enabled",
            ServiceName: "networkfirewall",
            Severity: "medium",
            Description: "**AWS Network Firewall firewalls** have **deletion protection** enabled (`DeleteProtection=true`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"networkfirewall"},
        },
    }
}

func (c *NetworkfirewallDeletionProtection) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *NetworkfirewallDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "networkfirewall",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

