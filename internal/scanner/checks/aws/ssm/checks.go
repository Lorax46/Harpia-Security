package ssm

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SsmManagedCompliantPatching - EC2 managed instance is compliant with Systems Manager patching requirements
type SsmManagedCompliantPatching struct {
    metadata models.CheckMetadata
}

func NewSsmManagedCompliantPatching() *SsmManagedCompliantPatching {
    return &SsmManagedCompliantPatching{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ssm_managed_compliant_patching",
            CheckTitle: "EC2 managed instance is compliant with Systems Manager patching requirements",
            ServiceName: "ssm",
            Severity: "high",
            Description: "**SSM-managed EC2 instances** report **patch compliance** against defined baselines. This evaluates each managed node's compliance status from Patch Manager to determine whether required security updates are applied according to policy.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ssm"},
        },
    }
}

func (c *SsmManagedCompliantPatching) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SsmManagedCompliantPatching) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ssm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SsmDocumentsSetAsPublic - SSM document is not public and shared only with trusted AWS accounts
type SsmDocumentsSetAsPublic struct {
    metadata models.CheckMetadata
}

func NewSsmDocumentsSetAsPublic() *SsmDocumentsSetAsPublic {
    return &SsmDocumentsSetAsPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ssm_documents_set_as_public",
            CheckTitle: "SSM document is not public and shared only with trusted AWS accounts",
            ServiceName: "ssm",
            Severity: "high",
            Description: "**SSM documents** are evaluated for **public sharing** (`all`) and for shares with AWS accounts outside a defined trusted list. Documents that remain private or are shared only with trusted accounts indicate restricted distribution.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ssm"},
        },
    }
}

func (c *SsmDocumentsSetAsPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SsmDocumentsSetAsPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ssm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SsmDocumentSecrets - SSM document contains no secrets
type SsmDocumentSecrets struct {
    metadata models.CheckMetadata
}

func NewSsmDocumentSecrets() *SsmDocumentSecrets {
    return &SsmDocumentSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ssm_document_secrets",
            CheckTitle: "SSM document contains no secrets",
            ServiceName: "ssm",
            Severity: "high",
            Description: "**AWS Systems Manager documents** are inspected for embedded **secrets** within their content. Patterns resembling passwords, access keys, tokens, or private keys in document steps are flagged when values appear hardcoded rather than referenced securely.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ssm"},
        },
    }
}

func (c *SsmDocumentSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SsmDocumentSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ssm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

