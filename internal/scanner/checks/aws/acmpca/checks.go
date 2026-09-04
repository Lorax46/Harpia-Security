package acmpca

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AcmpcaCertificateAuthorityPqcKeyAlgorithm - AWS Private CA certificate authorities use a post-quantum (ML-DSA) key algorithm
type AcmpcaCertificateAuthorityPqcKeyAlgorithm struct {
    metadata models.CheckMetadata
}

func NewAcmpcaCertificateAuthorityPqcKeyAlgorithm() *AcmpcaCertificateAuthorityPqcKeyAlgorithm {
    return &AcmpcaCertificateAuthorityPqcKeyAlgorithm{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "acmpca_certificate_authority_pqc_key_algorithm",
            CheckTitle: "AWS Private CA certificate authorities use a post-quantum (ML-DSA) key algorithm",
            ServiceName: "acmpca",
            Severity: "low",
            Description: "**AWS Private Certificate Authorities (Private CAs)** are assessed for use of a **post-quantum digital signature key algorithm** (`ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`). CAs that still issue certificates with RSA or ECC algorithms produce signatures vulnerable to forgery once a cryptographically relevant quantum computer is available.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"acmpca"},
        },
    }
}

func (c *AcmpcaCertificateAuthorityPqcKeyAlgorithm) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AcmpcaCertificateAuthorityPqcKeyAlgorithm) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "acmpca",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

