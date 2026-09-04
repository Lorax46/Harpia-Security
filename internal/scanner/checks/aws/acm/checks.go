package acm

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AcmCertificatesWithSecureKeyAlgorithms - ACM certificate uses a secure key algorithm
type AcmCertificatesWithSecureKeyAlgorithms struct {
    metadata models.CheckMetadata
}

func NewAcmCertificatesWithSecureKeyAlgorithms() *AcmCertificatesWithSecureKeyAlgorithms {
    return &AcmCertificatesWithSecureKeyAlgorithms{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "acm_certificates_with_secure_key_algorithms",
            CheckTitle: "ACM certificate uses a secure key algorithm",
            ServiceName: "acm",
            Severity: "high",
            Description: "**ACM certificates** are evaluated for the **public key algorithm and size**, identifying those that use weak parameters such as `RSA-1024` or ECDSA `P-192`. Certificates using `RSA-2048+` or ECDSA `P-256+` meet the secure baseline.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"acm"},
        },
    }
}

func (c *AcmCertificatesWithSecureKeyAlgorithms) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AcmCertificatesWithSecureKeyAlgorithms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "acm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AcmCertificatesTransparencyLogsEnabled - ACM certificate is imported or has Certificate Transparency logging enabled
type AcmCertificatesTransparencyLogsEnabled struct {
    metadata models.CheckMetadata
}

func NewAcmCertificatesTransparencyLogsEnabled() *AcmCertificatesTransparencyLogsEnabled {
    return &AcmCertificatesTransparencyLogsEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "acm_certificates_transparency_logs_enabled",
            CheckTitle: "ACM certificate is imported or has Certificate Transparency logging enabled",
            ServiceName: "acm",
            Severity: "medium",
            Description: "**ACM-issued certificates** are checked for **Certificate Transparency (CT) logging** being enabled. Certificates with type `IMPORTED` are excluded from evaluation.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"acm"},
        },
    }
}

func (c *AcmCertificatesTransparencyLogsEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AcmCertificatesTransparencyLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "acm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AcmCertificatesExpirationCheck - ACM certificate expires in more than the configured threshold of days
type AcmCertificatesExpirationCheck struct {
    metadata models.CheckMetadata
}

func NewAcmCertificatesExpirationCheck() *AcmCertificatesExpirationCheck {
    return &AcmCertificatesExpirationCheck{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "acm_certificates_expiration_check",
            CheckTitle: "ACM certificate expires in more than the configured threshold of days",
            ServiceName: "acm",
            Severity: "high",
            Description: "**ACM certificates** are assessed for **time to expiration** against a configurable threshold. Certificates close to end of validity or already expired are surfaced, covering those attached to services and, *if in scope*, unused ones.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"acm"},
        },
    }
}

func (c *AcmCertificatesExpirationCheck) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AcmCertificatesExpirationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "acm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

