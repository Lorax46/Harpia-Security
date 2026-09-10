package ses

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// SesIdentityNotPubliclyAccessible - SES identity resource policy does not allow public access
type SesIdentityNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewSesIdentityNotPubliclyAccessible() *SesIdentityNotPubliclyAccessible {
    return &SesIdentityNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ses_identity_not_publicly_accessible",
            CheckTitle: "SES identity resource policy does not allow public access",
            ServiceName: "ses",
            Severity: "high",
            Description: "**Amazon SES identities** are evaluated for **publicly accessible resource policies**-for example, statements with `Principal:'*'` or broadly trusted principals that permit actions against the identity.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ses"},
        },
    }
}

func (c *SesIdentityNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SesIdentityNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ses",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SesIdentityDkimEnabled - SES identity has DKIM signing enabled
type SesIdentityDkimEnabled struct {
    metadata models.CheckMetadata
}

func NewSesIdentityDkimEnabled() *SesIdentityDkimEnabled {
    return &SesIdentityDkimEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ses_identity_dkim_enabled",
            CheckTitle: "SES identity has DKIM signing enabled",
            ServiceName: "ses",
            Severity: "medium",
            Description: "**Amazon SES identities** are evaluated for **DKIM (DomainKeys Identified Mail)** signing enabled and verified. DKIM adds a cryptographic signature to outgoing emails, allowing recipients to verify that the email was sent by the domain owner and was not altered in transit.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ses"},
        },
    }
}

func (c *SesIdentityDkimEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SesIdentityDkimEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ses",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

