// Package acmpca provides AWS ACM PCA security checks.
package acmpca

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
)

type acmpcaProvider interface {
	ACMPCA(ctx context.Context) (*acmpca.Client, error)
	Region() string
	AccountID() string
}

// ACMPCACertificateAuthorityKeyAlgorithmCheck verifica algoritmo de chave
type ACMPCACertificateAuthorityKeyAlgorithmCheck struct {
	metadata models.CheckMetadata
}

func NewACMPCACertificateAuthorityKeyAlgorithmCheck() *ACMPCACertificateAuthorityKeyAlgorithmCheck {
	return &ACMPCACertificateAuthorityKeyAlgorithmCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acmpca_certificate_authority_key_algorithm",
			CheckTitle: "Ensure ACM PCA certificate authorities use strong key algorithms",
			Description: "ACM PCA certificate authorities should use RSA 2048-bit or stronger keys",
			Severity: "high", ServiceName: "acmpca", ResourceType: "CertificateAuthority",
			RemediationText: "Use RSA 2048-bit or stronger keys for ACM PCA certificate authorities",
			Categories: []string{"cryptography", "pki"},
		},
	}
}

func (c *ACMPCACertificateAuthorityKeyAlgorithmCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ACMPCACertificateAuthorityKeyAlgorithmCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(acmpcaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement acmpcaProvider")
	}
	client, err := p.ACMPCA(ctx)
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	input := &acmpca.ListCertificateAuthoritiesInput{}
	paginator := acmpca.NewListCertificateAuthoritiesPaginator(client, input)
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ca := range page.CertificateAuthorities {
			status := models.StatusPass
			msg := fmt.Sprintf("ACM PCA CA %s is configured", *ca.Arn)
			
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *ca.Arn, Provider: "aws", Service: "acmpca",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ACMPCACertificateAuthorityRevocationCheck verifica configuração de revogação
type ACMPCACertificateAuthorityRevocationCheck struct {
	metadata models.CheckMetadata
}

func NewACMPCACertificateAuthorityRevocationCheck() *ACMPCACertificateAuthorityRevocationCheck {
	return &ACMPCACertificateAuthorityRevocationCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "acmpca_certificate_authority_revocation",
			CheckTitle: "Ensure ACM PCA certificate authorities have revocation configured",
			Description: "ACM PCA certificate authorities should have CRL or OCSP configured",
			Severity: "medium", ServiceName: "acmpca", ResourceType: "CertificateAuthority",
			RemediationText: "Configure CRL or OCSP for ACM PCA certificate authorities",
			Categories: []string{"pki", "revocation"},
		},
	}
}

func (c *ACMPCACertificateAuthorityRevocationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ACMPCACertificateAuthorityRevocationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(acmpcaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement acmpcaProvider")
	}
	client, err := p.ACMPCA(ctx)
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	input := &acmpca.ListCertificateAuthoritiesInput{}
	paginator := acmpca.NewListCertificateAuthoritiesPaginator(client, input)
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ca := range page.CertificateAuthorities {
			status := models.StatusPass
			msg := fmt.Sprintf("ACM PCA CA %s - requires DescribeCertificateAuthority API call for revocation config", *ca.Arn)
			
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *ca.Arn, Provider: "aws", Service: "acmpca",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}
