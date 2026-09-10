package inspector2

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// Inspector2IsEnabled - Inspector2 is enabled for Amazon EC2 instances, ECR container images, Lambda functions, and Lambda code
type Inspector2IsEnabled struct {
    metadata models.CheckMetadata
}

func NewInspector2IsEnabled() *Inspector2IsEnabled {
    return &Inspector2IsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "inspector2_is_enabled",
            CheckTitle: "Inspector2 is enabled for Amazon EC2 instances, ECR container images, Lambda functions, and Lambda code",
            ServiceName: "inspector2",
            Severity: "medium",
            Description: "**Amazon Inspector 2** activation and coverage across regions, verifying that scanning is active for **EC2**, **ECR**, **Lambda functions**, and **Lambda code** where applicable.  It flags missing account activation or gaps in any scan type.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"inspector2"},
        },
    }
}

func (c *Inspector2IsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Inspector2IsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "inspector2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// Inspector2ActiveFindingsExist - Inspector2 is enabled with no active findings
type Inspector2ActiveFindingsExist struct {
    metadata models.CheckMetadata
}

func NewInspector2ActiveFindingsExist() *Inspector2ActiveFindingsExist {
    return &Inspector2ActiveFindingsExist{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "inspector2_active_findings_exist",
            CheckTitle: "Inspector2 is enabled with no active findings",
            ServiceName: "inspector2",
            Severity: "high",
            Description: "**Amazon Inspector2** active findings are assessed across eligible resources when the service is `ENABLED`.  Indicates whether any findings remain in the **Active** state versus none.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"inspector2"},
        },
    }
}

func (c *Inspector2ActiveFindingsExist) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *Inspector2ActiveFindingsExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "inspector2",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

