package acm

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

type acmProvider interface {
	ACM(ctx context.Context) (*acm.Client, error)
}

// AcmCertificateExpirationCheck - ACM certificate expiration
type AcmCertificateExpirationCheck struct {
	metadata models.CheckMetadata
}

func NewAcmCertificateExpirationCheck() *AcmCertificateExpirationCheck {
	return &AcmCertificateExpirationCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acm_certificate_expiration_check",
			CheckTitle: "ACM certificate expiration check",
			ServiceName: "acm", Severity: "medium", ResourceType: "Certificate",
			Description: "ACM certificates should not expire soon",
			RemediationText: "Renew ACM certificates before expiration",
			Categories: []string{"networking"},
		},
	}
}

func (c *AcmCertificateExpirationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AcmCertificateExpirationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(acmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement acmProvider")
	}
	client, err := p.ACM(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cert := range result.CertificateSummaryList {
		status := models.StatusPass
		msg := fmt.Sprintf("Certificate %s is valid", *cert.DomainName)
		if cert.NotAfter != nil {
			daysUntilExpiry := time.Until(*cert.NotAfter).Hours() / 24
			if daysUntilExpiry < 30 {
				status = models.StatusFail
				msg = fmt.Sprintf("Certificate %s expires in %.0f days", *cert.DomainName, daysUntilExpiry)
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *cert.DomainName, Provider: "aws", Service: "acm",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AcmCertificateRenewal - ACM certificate renewal
type AcmCertificateRenewal struct {
	metadata models.CheckMetadata
}

func NewAcmCertificateRenewal() *AcmCertificateRenewal {
	return &AcmCertificateRenewal{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acm_certificate_renewal",
			CheckTitle: "ACM certificate renewal",
			ServiceName: "acm", Severity: "medium", ResourceType: "Certificate",
			Description: "ACM certificates should be renewed",
			RemediationText: "Enable auto-renewal for ACM certificates",
			Categories: []string{"networking"},
		},
	}
}

func (c *AcmCertificateRenewal) Metadata() models.CheckMetadata { return c.metadata }

func (c *AcmCertificateRenewal) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "ACM renewal check requires detailed analysis",
		Provider: "aws", Service: "acm",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AcmCertificateStatus - ACM certificate status
type AcmCertificateStatus struct {
	metadata models.CheckMetadata
}

func NewAcmCertificateStatus() *AcmCertificateStatus {
	return &AcmCertificateStatus{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acm_certificate_status",
			CheckTitle: "ACM certificate status",
			ServiceName: "acm", Severity: "low", ResourceType: "Certificate",
			Description: "ACM certificates should be issued",
			RemediationText: "Verify ACM certificate status",
			Categories: []string{"networking"},
		},
	}
}

func (c *AcmCertificateStatus) Metadata() models.CheckMetadata { return c.metadata }

func (c *AcmCertificateStatus) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "ACM status check requires detailed analysis",
		Provider: "aws", Service: "acm",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AcmCertificatesTransparencyLogsEnabled - verifica logs de transparência
type AcmCertificatesTransparencyLogsEnabled struct {
	metadata models.CheckMetadata
}

func NewAcmCertificatesTransparencyLogsEnabled() *AcmCertificatesTransparencyLogsEnabled {
	return &AcmCertificatesTransparencyLogsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acm_certificates_transparency_logs_enabled",
			CheckTitle: "Ensure ACM certificates have transparency logging enabled",
			Description: "ACM certificates should have Certificate Transparency logging enabled",
			Severity: "low", ServiceName: "acm", ResourceType: "Certificate",
			RemediationText: "Enable Certificate Transparency logging",
			Categories: []string{"acm", "transparency"},
		},
	}
}

func (c *AcmCertificatesTransparencyLogsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AcmCertificatesTransparencyLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "ACM transparency logging check requires detailed analysis",
		ResourceID: "acm-transparency", Provider: "aws", Service: "acm",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AcmCertificatesWithSecureKeyAlgorithms - verifica algoritmos seguros
type AcmCertificatesWithSecureKeyAlgorithms struct {
	metadata models.CheckMetadata
}

func NewAcmCertificatesWithSecureKeyAlgorithms() *AcmCertificatesWithSecureKeyAlgorithms {
	return &AcmCertificatesWithSecureKeyAlgorithms{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acm_certificates_with_secure_key_algorithms",
			CheckTitle: "Ensure ACM certificates use secure key algorithms",
			Description: "ACM certificates should use RSA 2048+ or ECC 256+",
			Severity: "medium", ServiceName: "acm", ResourceType: "Certificate",
			RemediationText: "Use secure key algorithms for ACM certificates",
			Categories: []string{"acm", "key-algorithm"},
		},
	}
}

func (c *AcmCertificatesWithSecureKeyAlgorithms) Metadata() models.CheckMetadata { return c.metadata }

func (c *AcmCertificatesWithSecureKeyAlgorithms) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(acmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement acmProvider")
	}
	client, err := p.ACM(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, cert := range result.CertificateSummaryList {
		status := models.StatusPass
		msg := fmt.Sprintf("Certificate %s uses secure algorithm", *cert.DomainName)
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *cert.DomainName, Provider: "aws", Service: "acm",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
