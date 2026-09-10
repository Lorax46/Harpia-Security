package dspm

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type dspmProvider interface {
	Dspm(ctx context.Context) (interface{}, error)
}

// DataDiscoveryCheck - Data discovery is enabled
type DataDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewDataDiscoveryCheck() *DataDiscoveryCheck {
	return &DataDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_discovery",
			CheckTitle:      "Data discovery is enabled",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Data",
			Description:     "Data discovery is enabled",
			RemediationText: "Review and remediate data discovery is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_discovery
	_ = findings
	return findings, nil
}

// DataClassificationCheck - Data classification is enabled
type DataClassificationCheck struct {
	metadata models.CheckMetadata
}

func NewDataClassificationCheck() *DataClassificationCheck {
	return &DataClassificationCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_classification",
			CheckTitle:      "Data classification is enabled",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Data",
			Description:     "Data classification is enabled",
			RemediationText: "Review and remediate data classification is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataClassificationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataClassificationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_classification
	_ = findings
	return findings, nil
}

// DataInventoryCheck - Data inventory is maintained
type DataInventoryCheck struct {
	metadata models.CheckMetadata
}

func NewDataInventoryCheck() *DataInventoryCheck {
	return &DataInventoryCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_inventory",
			CheckTitle:      "Data inventory is maintained",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Inventory",
			Description:     "Data inventory is maintained",
			RemediationText: "Review and remediate data inventory is maintained",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataInventoryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataInventoryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_inventory
	_ = findings
	return findings, nil
}

// SensitiveDataCheck - Sensitive data is identified
type SensitiveDataCheck struct {
	metadata models.CheckMetadata
}

func NewSensitiveDataCheck() *SensitiveDataCheck {
	return &SensitiveDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_sensitive_data",
			CheckTitle:      "Sensitive data is identified",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "SensitiveData",
			Description:     "Sensitive data is identified",
			RemediationText: "Review and remediate sensitive data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *SensitiveDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SensitiveDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_sensitive_data
	_ = findings
	return findings, nil
}

// PiiDetectionCheck - PII detection is enabled
type PiiDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewPiiDetectionCheck() *PiiDetectionCheck {
	return &PiiDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_pii_detection",
			CheckTitle:      "PII detection is enabled",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "PII",
			Description:     "PII detection is enabled",
			RemediationText: "Review and remediate pii detection is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *PiiDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PiiDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_pii_detection
	_ = findings
	return findings, nil
}

// PhiDetectionCheck - PHI detection is enabled
type PhiDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewPhiDetectionCheck() *PhiDetectionCheck {
	return &PhiDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_phi_detection",
			CheckTitle:      "PHI detection is enabled",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "PHI",
			Description:     "PHI detection is enabled",
			RemediationText: "Review and remediate phi detection is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *PhiDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PhiDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_phi_detection
	_ = findings
	return findings, nil
}

// PaymentDataCheck - Payment data is identified
type PaymentDataCheck struct {
	metadata models.CheckMetadata
}

func NewPaymentDataCheck() *PaymentDataCheck {
	return &PaymentDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_payment_data",
			CheckTitle:      "Payment data is identified",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Payment",
			Description:     "Payment data is identified",
			RemediationText: "Review and remediate payment data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *PaymentDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PaymentDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_payment_data
	_ = findings
	return findings, nil
}

// CredentialDetectionCheck - Credentials are detected
type CredentialDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewCredentialDetectionCheck() *CredentialDetectionCheck {
	return &CredentialDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_credential_detection",
			CheckTitle:      "Credentials are detected",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Credential",
			Description:     "Credentials are detected",
			RemediationText: "Review and remediate credentials are detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *CredentialDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CredentialDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_credential_detection
	_ = findings
	return findings, nil
}

// ApiKeyDetectionCheck - API keys are detected
type ApiKeyDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewApiKeyDetectionCheck() *ApiKeyDetectionCheck {
	return &ApiKeyDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_api_key_detection",
			CheckTitle:      "API keys are detected",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "APIKey",
			Description:     "API keys are detected",
			RemediationText: "Review and remediate api keys are detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ApiKeyDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApiKeyDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_api_key_detection
	_ = findings
	return findings, nil
}

// TokenDetectionCheck - Tokens are detected
type TokenDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewTokenDetectionCheck() *TokenDetectionCheck {
	return &TokenDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_token_detection",
			CheckTitle:      "Tokens are detected",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Token",
			Description:     "Tokens are detected",
			RemediationText: "Review and remediate tokens are detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *TokenDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TokenDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_token_detection
	_ = findings
	return findings, nil
}

// CertificateDetectionCheck - Certificates are detected
type CertificateDetectionCheck struct {
	metadata models.CheckMetadata
}

func NewCertificateDetectionCheck() *CertificateDetectionCheck {
	return &CertificateDetectionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_certificate_detection",
			CheckTitle:      "Certificates are detected",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Certificate",
			Description:     "Certificates are detected",
			RemediationText: "Review and remediate certificates are detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *CertificateDetectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CertificateDetectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_certificate_detection
	_ = findings
	return findings, nil
}

// DataFlowCheck - Data flows are mapped
type DataFlowCheck struct {
	metadata models.CheckMetadata
}

func NewDataFlowCheck() *DataFlowCheck {
	return &DataFlowCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_flow",
			CheckTitle:      "Data flows are mapped",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "DataFlow",
			Description:     "Data flows are mapped",
			RemediationText: "Review and remediate data flows are mapped",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataFlowCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataFlowCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_flow
	_ = findings
	return findings, nil
}

// DataLineageCheck - Data lineage is tracked
type DataLineageCheck struct {
	metadata models.CheckMetadata
}

func NewDataLineageCheck() *DataLineageCheck {
	return &DataLineageCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_lineage",
			CheckTitle:      "Data lineage is tracked",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "Lineage",
			Description:     "Data lineage is tracked",
			RemediationText: "Review and remediate data lineage is tracked",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataLineageCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataLineageCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_lineage
	_ = findings
	return findings, nil
}

// DataResidencyCheck - Data residency is enforced
type DataResidencyCheck struct {
	metadata models.CheckMetadata
}

func NewDataResidencyCheck() *DataResidencyCheck {
	return &DataResidencyCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_residency",
			CheckTitle:      "Data residency is enforced",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Residency",
			Description:     "Data residency is enforced",
			RemediationText: "Review and remediate data residency is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataResidencyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataResidencyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_residency
	_ = findings
	return findings, nil
}

// DataSovereigntyCheck - Data sovereignty is enforced
type DataSovereigntyCheck struct {
	metadata models.CheckMetadata
}

func NewDataSovereigntyCheck() *DataSovereigntyCheck {
	return &DataSovereigntyCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_sovereignty",
			CheckTitle:      "Data sovereignty is enforced",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Sovereignty",
			Description:     "Data sovereignty is enforced",
			RemediationText: "Review and remediate data sovereignty is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataSovereigntyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataSovereigntyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_sovereignty
	_ = findings
	return findings, nil
}

// DataRetentionCheck - Data retention is enforced
type DataRetentionCheck struct {
	metadata models.CheckMetadata
}

func NewDataRetentionCheck() *DataRetentionCheck {
	return &DataRetentionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_retention",
			CheckTitle:      "Data retention is enforced",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Retention",
			Description:     "Data retention is enforced",
			RemediationText: "Review and remediate data retention is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataRetentionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataRetentionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_retention
	_ = findings
	return findings, nil
}

// DataArchivalCheck - Data archival is configured
type DataArchivalCheck struct {
	metadata models.CheckMetadata
}

func NewDataArchivalCheck() *DataArchivalCheck {
	return &DataArchivalCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_archival",
			CheckTitle:      "Data archival is configured",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "Archival",
			Description:     "Data archival is configured",
			RemediationText: "Review and remediate data archival is configured",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataArchivalCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataArchivalCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_archival
	_ = findings
	return findings, nil
}

// DataDeletionCheck - Data deletion is configured
type DataDeletionCheck struct {
	metadata models.CheckMetadata
}

func NewDataDeletionCheck() *DataDeletionCheck {
	return &DataDeletionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_deletion",
			CheckTitle:      "Data deletion is configured",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Deletion",
			Description:     "Data deletion is configured",
			RemediationText: "Review and remediate data deletion is configured",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataDeletionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataDeletionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_deletion
	_ = findings
	return findings, nil
}

// DataMaskingCheck - Data masking is enabled
type DataMaskingCheck struct {
	metadata models.CheckMetadata
}

func NewDataMaskingCheck() *DataMaskingCheck {
	return &DataMaskingCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_masking",
			CheckTitle:      "Data masking is enabled",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Masking",
			Description:     "Data masking is enabled",
			RemediationText: "Review and remediate data masking is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataMaskingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataMaskingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_masking
	_ = findings
	return findings, nil
}

// DataTokenizationCheck - Data tokenization is enabled
type DataTokenizationCheck struct {
	metadata models.CheckMetadata
}

func NewDataTokenizationCheck() *DataTokenizationCheck {
	return &DataTokenizationCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_tokenization",
			CheckTitle:      "Data tokenization is enabled",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "Tokenization",
			Description:     "Data tokenization is enabled",
			RemediationText: "Review and remediate data tokenization is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataTokenizationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataTokenizationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_tokenization
	_ = findings
	return findings, nil
}

// DataEncryptionCheck - Data encryption is enforced
type DataEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewDataEncryptionCheck() *DataEncryptionCheck {
	return &DataEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_encryption",
			CheckTitle:      "Data encryption is enforced",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Encryption",
			Description:     "Data encryption is enforced",
			RemediationText: "Review and remediate data encryption is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_encryption
	_ = findings
	return findings, nil
}

// KeyManagementCheck - Key management is configured
type KeyManagementCheck struct {
	metadata models.CheckMetadata
}

func NewKeyManagementCheck() *KeyManagementCheck {
	return &KeyManagementCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_key_management",
			CheckTitle:      "Key management is configured",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "KeyMgmt",
			Description:     "Key management is configured",
			RemediationText: "Review and remediate key management is configured",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *KeyManagementCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *KeyManagementCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_key_management
	_ = findings
	return findings, nil
}

// AccessPolicyCheck - Access policies are configured
type AccessPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewAccessPolicyCheck() *AccessPolicyCheck {
	return &AccessPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_access_policy",
			CheckTitle:      "Access policies are configured",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "AccessPolicy",
			Description:     "Access policies are configured",
			RemediationText: "Review and remediate access policies are configured",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *AccessPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_access_policy
	_ = findings
	return findings, nil
}

// DataAccessCheck - Data access is monitored
type DataAccessCheck struct {
	metadata models.CheckMetadata
}

func NewDataAccessCheck() *DataAccessCheck {
	return &DataAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_access",
			CheckTitle:      "Data access is monitored",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "DataAccess",
			Description:     "Data access is monitored",
			RemediationText: "Review and remediate data access is monitored",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_access
	_ = findings
	return findings, nil
}

// DataSharingCheck - Data sharing is controlled
type DataSharingCheck struct {
	metadata models.CheckMetadata
}

func NewDataSharingCheck() *DataSharingCheck {
	return &DataSharingCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_sharing",
			CheckTitle:      "Data sharing is controlled",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "DataSharing",
			Description:     "Data sharing is controlled",
			RemediationText: "Review and remediate data sharing is controlled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataSharingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataSharingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_sharing
	_ = findings
	return findings, nil
}

// DataExposureCheck - Data exposure is detected
type DataExposureCheck struct {
	metadata models.CheckMetadata
}

func NewDataExposureCheck() *DataExposureCheck {
	return &DataExposureCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_exposure",
			CheckTitle:      "Data exposure is detected",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Exposure",
			Description:     "Data exposure is detected",
			RemediationText: "Review and remediate data exposure is detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataExposureCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataExposureCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_exposure
	_ = findings
	return findings, nil
}

// MisconfigurationCheck - Misconfigurations are detected
type MisconfigurationCheck struct {
	metadata models.CheckMetadata
}

func NewMisconfigurationCheck() *MisconfigurationCheck {
	return &MisconfigurationCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_misconfiguration",
			CheckTitle:      "Misconfigurations are detected",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Misconfig",
			Description:     "Misconfigurations are detected",
			RemediationText: "Review and remediate misconfigurations are detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *MisconfigurationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MisconfigurationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_misconfiguration
	_ = findings
	return findings, nil
}

// OverprivilegedAccessCheck - Overprivileged access is detected
type OverprivilegedAccessCheck struct {
	metadata models.CheckMetadata
}

func NewOverprivilegedAccessCheck() *OverprivilegedAccessCheck {
	return &OverprivilegedAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_overprivileged_access",
			CheckTitle:      "Overprivileged access is detected",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Overprivilege",
			Description:     "Overprivileged access is detected",
			RemediationText: "Review and remediate overprivileged access is detected",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *OverprivilegedAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OverprivilegedAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_overprivileged_access
	_ = findings
	return findings, nil
}

// DormantDataCheck - Dormant data is identified
type DormantDataCheck struct {
	metadata models.CheckMetadata
}

func NewDormantDataCheck() *DormantDataCheck {
	return &DormantDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_dormant_data",
			CheckTitle:      "Dormant data is identified",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "DormantData",
			Description:     "Dormant data is identified",
			RemediationText: "Review and remediate dormant data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DormantDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DormantDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_dormant_data
	_ = findings
	return findings, nil
}

// OrphanedDataCheck - Orphaned data is identified
type OrphanedDataCheck struct {
	metadata models.CheckMetadata
}

func NewOrphanedDataCheck() *OrphanedDataCheck {
	return &OrphanedDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_orphaned_data",
			CheckTitle:      "Orphaned data is identified",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "OrphanedData",
			Description:     "Orphaned data is identified",
			RemediationText: "Review and remediate orphaned data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *OrphanedDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OrphanedDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_orphaned_data
	_ = findings
	return findings, nil
}

// RedundantDataCheck - Redundant data is identified
type RedundantDataCheck struct {
	metadata models.CheckMetadata
}

func NewRedundantDataCheck() *RedundantDataCheck {
	return &RedundantDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_redundant_data",
			CheckTitle:      "Redundant data is identified",
			ServiceName:     "dspm",
			Severity:        "low",
			ResourceType:    "RedundantData",
			Description:     "Redundant data is identified",
			RemediationText: "Review and remediate redundant data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *RedundantDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RedundantDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_redundant_data
	_ = findings
	return findings, nil
}

// ShadowDataCheck - Shadow data is identified
type ShadowDataCheck struct {
	metadata models.CheckMetadata
}

func NewShadowDataCheck() *ShadowDataCheck {
	return &ShadowDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_shadow_data",
			CheckTitle:      "Shadow data is identified",
			ServiceName:     "dspm",
			Severity:        "medium",
			ResourceType:    "ShadowData",
			Description:     "Shadow data is identified",
			RemediationText: "Review and remediate shadow data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ShadowDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ShadowDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_shadow_data
	_ = findings
	return findings, nil
}

// DarkDataCheck - Dark data is identified
type DarkDataCheck struct {
	metadata models.CheckMetadata
}

func NewDarkDataCheck() *DarkDataCheck {
	return &DarkDataCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_dark_data",
			CheckTitle:      "Dark data is identified",
			ServiceName:     "dspm",
			Severity:        "low",
			ResourceType:    "DarkData",
			Description:     "Dark data is identified",
			RemediationText: "Review and remediate dark data is identified",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DarkDataCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DarkDataCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_dark_data
	_ = findings
	return findings, nil
}

// ComplianceGdprCheck - GDPR compliance is enforced
type ComplianceGdprCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceGdprCheck() *ComplianceGdprCheck {
	return &ComplianceGdprCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_compliance_gdpr",
			CheckTitle:      "GDPR compliance is enforced",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "GDPR",
			Description:     "GDPR compliance is enforced",
			RemediationText: "Review and remediate gdpr compliance is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ComplianceGdprCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceGdprCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_compliance_gdpr
	_ = findings
	return findings, nil
}

// ComplianceHipaaCheck - HIPAA compliance is enforced
type ComplianceHipaaCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceHipaaCheck() *ComplianceHipaaCheck {
	return &ComplianceHipaaCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_compliance_hipaa",
			CheckTitle:      "HIPAA compliance is enforced",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "HIPAA",
			Description:     "HIPAA compliance is enforced",
			RemediationText: "Review and remediate hipaa compliance is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ComplianceHipaaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceHipaaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_compliance_hipaa
	_ = findings
	return findings, nil
}

// CompliancePciCheck - PCI DSS compliance is enforced
type CompliancePciCheck struct {
	metadata models.CheckMetadata
}

func NewCompliancePciCheck() *CompliancePciCheck {
	return &CompliancePciCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_compliance_pci",
			CheckTitle:      "PCI DSS compliance is enforced",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "PCI",
			Description:     "PCI DSS compliance is enforced",
			RemediationText: "Review and remediate pci dss compliance is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *CompliancePciCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CompliancePciCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_compliance_pci
	_ = findings
	return findings, nil
}

// ComplianceSoxCheck - SOX compliance is enforced
type ComplianceSoxCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceSoxCheck() *ComplianceSoxCheck {
	return &ComplianceSoxCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_compliance_sox",
			CheckTitle:      "SOX compliance is enforced",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "SOX",
			Description:     "SOX compliance is enforced",
			RemediationText: "Review and remediate sox compliance is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ComplianceSoxCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceSoxCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_compliance_sox
	_ = findings
	return findings, nil
}

// ComplianceCcpaCheck - CCPA compliance is enforced
type ComplianceCcpaCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceCcpaCheck() *ComplianceCcpaCheck {
	return &ComplianceCcpaCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_compliance_ccpa",
			CheckTitle:      "CCPA compliance is enforced",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "CCPA",
			Description:     "CCPA compliance is enforced",
			RemediationText: "Review and remediate ccpa compliance is enforced",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *ComplianceCcpaCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceCcpaCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_compliance_ccpa
	_ = findings
	return findings, nil
}

// RiskAssessmentCheck - Risk assessment is performed
type RiskAssessmentCheck struct {
	metadata models.CheckMetadata
}

func NewRiskAssessmentCheck() *RiskAssessmentCheck {
	return &RiskAssessmentCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_risk_assessment",
			CheckTitle:      "Risk assessment is performed",
			ServiceName:     "dspm",
			Severity:        "high",
			ResourceType:    "Risk",
			Description:     "Risk assessment is performed",
			RemediationText: "Review and remediate risk assessment is performed",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *RiskAssessmentCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RiskAssessmentCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_risk_assessment
	_ = findings
	return findings, nil
}

// DataBreachCheck - Data breach detection is enabled
type DataBreachCheck struct {
	metadata models.CheckMetadata
}

func NewDataBreachCheck() *DataBreachCheck {
	return &DataBreachCheck{
		metadata: models.CheckMetadata{
			Provider:        "dspm",
			CheckID:         "dspm_data_breach",
			CheckTitle:      "Data breach detection is enabled",
			ServiceName:     "dspm",
			Severity:        "critical",
			ResourceType:    "Breach",
			Description:     "Data breach detection is enabled",
			RemediationText: "Review and remediate data breach detection is enabled",
			Categories:      []string{"dspm", "security"},
		},
	}
}

func (c *DataBreachCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataBreachCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(dspmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement dspmProvider")
	}
	client, err := p.Dspm(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement dspm_data_breach
	_ = findings
	return findings, nil
}
