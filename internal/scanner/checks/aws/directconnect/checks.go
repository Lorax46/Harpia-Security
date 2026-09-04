package directconnect

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// DirectconnectConnectionRedundancy - Direct Connect connections span at least two locations per region
type DirectconnectConnectionRedundancy struct {
    metadata models.CheckMetadata
}

func NewDirectconnectConnectionRedundancy() *DirectconnectConnectionRedundancy {
    return &DirectconnectConnectionRedundancy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directconnect_connection_redundancy",
            CheckTitle: "Direct Connect connections span at least two locations per region",
            ServiceName: "directconnect",
            Severity: "medium",
            Description: "**AWS Direct Connect** connectivity is provisioned with **connection and location redundancy**-multiple connections spread across **at least two distinct Direct Connect locations** in each Region.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directconnect"},
        },
    }
}

func (c *DirectconnectConnectionRedundancy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectconnectConnectionRedundancy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directconnect",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// DirectconnectVirtualInterfaceRedundancy - Direct Connect gateway or virtual private gateway has at least two virtual interfaces on different Direct Connect connections
type DirectconnectVirtualInterfaceRedundancy struct {
    metadata models.CheckMetadata
}

func NewDirectconnectVirtualInterfaceRedundancy() *DirectconnectVirtualInterfaceRedundancy {
    return &DirectconnectVirtualInterfaceRedundancy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "directconnect_virtual_interface_redundancy",
            CheckTitle: "Direct Connect gateway or virtual private gateway has at least two virtual interfaces on different Direct Connect connections",
            ServiceName: "directconnect",
            Severity: "medium",
            Description: "**Direct Connect gateways** and **virtual private gateways** are assessed for **interface redundancy**: multiple virtual interfaces (`VIFs`) distributed across more than one **Direct Connect connection**.  *Gateways with only one VIF or with all VIFs on a single connection are identified.*",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"directconnect"},
        },
    }
}

func (c *DirectconnectVirtualInterfaceRedundancy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DirectconnectVirtualInterfaceRedundancy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "directconnect",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

