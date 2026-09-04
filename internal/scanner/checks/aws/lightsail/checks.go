package lightsail

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// LightsailDatabasePublic - Lightsail database public access disabled
type LightsailDatabasePublic struct {
    metadata models.CheckMetadata
}

func NewLightsailDatabasePublic() *LightsailDatabasePublic {
    return &LightsailDatabasePublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "lightsail_database_public",
            CheckTitle: "Lightsail database public access disabled",
            ServiceName: "lightsail",
            Severity: "high",
            Description: "**Lightsail managed database** is evaluated for **public accessibility**. When `public mode` is enabled, the database accepts connections from the Internet using its endpoint and port; otherwise, access is limited to authorized Lightsail resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"lightsail"},
        },
    }
}

func (c *LightsailDatabasePublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *LightsailDatabasePublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "lightsail",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// LightsailInstancePublic - Lightsail instance has no publicly accessible ports
type LightsailInstancePublic struct {
    metadata models.CheckMetadata
}

func NewLightsailInstancePublic() *LightsailInstancePublic {
    return &LightsailInstancePublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "lightsail_instance_public",
            CheckTitle: "Lightsail instance has no publicly accessible ports",
            ServiceName: "lightsail",
            Severity: "high",
            Description: "**Lightsail instances** that have a **public IP** and at least one firewall rule allowing **public ports** are treated as publicly exposed. The evaluation inspects instance addressing and port rules to detect any port or range marked `public`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"lightsail"},
        },
    }
}

func (c *LightsailInstancePublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *LightsailInstancePublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "lightsail",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// LightsailInstanceAutomatedSnapshots - Lightsail instance has automated snapshots enabled
type LightsailInstanceAutomatedSnapshots struct {
    metadata models.CheckMetadata
}

func NewLightsailInstanceAutomatedSnapshots() *LightsailInstanceAutomatedSnapshots {
    return &LightsailInstanceAutomatedSnapshots{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "lightsail_instance_automated_snapshots",
            CheckTitle: "Lightsail instance has automated snapshots enabled",
            ServiceName: "lightsail",
            Severity: "medium",
            Description: "**Amazon Lightsail instances** with **automatic daily snapshots** enabled are identified. The evaluation checks if an instance is configured to take recurring snapshots at a scheduled time.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"lightsail"},
        },
    }
}

func (c *LightsailInstanceAutomatedSnapshots) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *LightsailInstanceAutomatedSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "lightsail",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// LightsailStaticIpUnused - Lightsail static IP is associated with an instance
type LightsailStaticIpUnused struct {
    metadata models.CheckMetadata
}

func NewLightsailStaticIpUnused() *LightsailStaticIpUnused {
    return &LightsailStaticIpUnused{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "lightsail_static_ip_unused",
            CheckTitle: "Lightsail static IP is associated with an instance",
            ServiceName: "lightsail",
            Severity: "low",
            Description: "**Amazon Lightsail static IPs** detected as **not associated** with any instance, indicating reserved but unused addresses.  The evaluation focuses on the association state of each static IP to highlight potential leftovers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"lightsail"},
        },
    }
}

func (c *LightsailStaticIpUnused) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *LightsailStaticIpUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "lightsail",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

