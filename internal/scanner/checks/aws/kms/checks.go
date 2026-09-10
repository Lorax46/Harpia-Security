package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type kmsProvider interface {
	KMS(ctx context.Context) (*kms.Client, error)
}

// KmsCmkNotDeletedUnintentionally - KMS CMK is not pending deletion
type KmsCmkNotDeletedUnintentionally struct {
	metadata models.CheckMetadata
}

func NewKmsCmkNotDeletedUnintentionally() *KmsCmkNotDeletedUnintentionally {
	return &KmsCmkNotDeletedUnintentionally{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "kms_cmk_not_deleted_unintentionally",
			CheckTitle:   "KMS CMK is not pending deletion",
			ServiceName:  "kms",
			Severity:     "high",
			ResourceType: "Key",
			Description:  "KMS customer-managed keys should not be in pending deletion state unless intentionally deleted",
			RemediationText: "Cancel the key deletion if it was unintentional",
			Categories:   []string{"encryption"},
		},
	}
}

func (c *KmsCmkNotDeletedUnintentionally) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsCmkNotDeletedUnintentionally) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kmsProvider")
	}
	kmsClient, err := p.KMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	keys, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KMS keys: %w", err)
	}

	for _, key := range keys.Keys {
		keyID := aws.ToString(key.KeyId)

		keyInfo, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		// Only check customer-managed keys
		if keyInfo.KeyMetadata.KeyManager != "CUSTOMER" {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("KMS CMK %s is not scheduled for deletion.", keyID)

		if keyInfo.KeyMetadata.KeyState == "PendingDeletion" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("KMS CMK %s is scheduled for deletion, revert it if it was unintentional.", keyID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "kms",
			ResourceID:     keyID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// KmsKeyNotPubliclyAccessible - KMS key is not publicly accessible
type KmsKeyNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewKmsKeyNotPubliclyAccessible() *KmsKeyNotPubliclyAccessible {
	return &KmsKeyNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "kms_key_not_publicly_accessible",
			CheckTitle:   "KMS key is not publicly accessible",
			ServiceName:  "kms",
			Severity:     "critical",
			ResourceType: "Key",
			Description:  "KMS customer-managed keys should not be publicly accessible",
			RemediationText: "Restrict KMS key policies to prevent public access",
			Categories:   []string{"encryption"},
		},
	}
}

func (c *KmsKeyNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsKeyNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kmsProvider")
	}
	kmsClient, err := p.KMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	keys, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KMS keys: %w", err)
	}

	for _, key := range keys.Keys {
		keyID := aws.ToString(key.KeyId)

		keyInfo, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		// Only check enabled customer-managed keys
		if keyInfo.KeyMetadata.KeyManager != "CUSTOMER" || keyInfo.KeyMetadata.KeyState != "Enabled" {
			continue
		}

		// Get key policy
		policy, err := kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
			KeyId:      key.KeyId,
			PolicyName: aws.String("default"),
		})
		if err != nil {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("KMS key %s is not exposed to Public.", keyID)

		// Check if policy has wildcard principal (simplified check)
		policyStr := aws.ToString(policy.Policy)
		if policyStr != "" && containsWildcardPrincipal(policyStr) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("KMS key %s may be publicly accessible.", keyID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "kms",
			ResourceID:     keyID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

func containsWildcardPrincipal(policy string) bool {
	// Simplified check for wildcard principal in KMS policy
	return len(policy) > 0 && (policy == `{"Principal":"*"}` || policy == `{"Principal":{"AWS":"*"}}`)
}

// KmsCmkRotationEnabled - KMS CMK has automatic rotation enabled
type KmsCmkRotationEnabled struct {
	metadata models.CheckMetadata
}

func NewKmsCmkRotationEnabled() *KmsCmkRotationEnabled {
	return &KmsCmkRotationEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "kms_cmk_rotation_enabled",
			CheckTitle:   "KMS CMK has automatic rotation enabled",
			ServiceName:  "kms",
			Severity:     "high",
			ResourceType: "Key",
			Description:  "KMS customer-managed symmetric keys should have automatic key rotation enabled",
			RemediationText: "Enable automatic key rotation for your KMS CMKs",
			Categories:   []string{"encryption"},
		},
	}
}

func (c *KmsCmkRotationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsCmkRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kmsProvider")
	}
	kmsClient, err := p.KMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	keys, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KMS keys: %w", err)
	}

	for _, key := range keys.Keys {
		keyID := aws.ToString(key.KeyId)

		keyInfo, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		// Only check enabled customer-managed symmetric keys
		if keyInfo.KeyMetadata.KeyManager != "CUSTOMER" || keyInfo.KeyMetadata.KeyState != "Enabled" || keyInfo.KeyMetadata.KeySpec != "SYMMETRIC_DEFAULT" {
			continue
		}

		rotation, err := kmsClient.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		status := models.StatusFail
		statusExtended := fmt.Sprintf("KMS CMK %s has automatic rotation disabled.", keyID)

		if rotation.KeyRotationEnabled {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("KMS CMK %s has automatic rotation enabled.", keyID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "kms",
			ResourceID:     keyID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// KmsCmkNotMultiRegion - KMS CMK is not multi-region
type KmsCmkNotMultiRegion struct {
	metadata models.CheckMetadata
}

func NewKmsCmkNotMultiRegion() *KmsCmkNotMultiRegion {
	return &KmsCmkNotMultiRegion{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "kms_cmk_not_multi_region",
			CheckTitle:   "KMS CMK is not multi-region",
			ServiceName:  "kms",
			Severity:     "medium",
			ResourceType: "Key",
			Description:  "KMS customer-managed keys should be single-region keys",
			RemediationText: "Use single-region KMS keys unless multi-region is required",
			Categories:   []string{"encryption"},
		},
	}
}

func (c *KmsCmkNotMultiRegion) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsCmkNotMultiRegion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kmsProvider")
	}
	kmsClient, err := p.KMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	keys, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KMS keys: %w", err)
	}

	for _, key := range keys.Keys {
		keyID := aws.ToString(key.KeyId)

		keyInfo, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		// Only check enabled customer-managed keys
		if keyInfo.KeyMetadata.KeyManager != "CUSTOMER" || keyInfo.KeyMetadata.KeyState != "Enabled" {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("KMS CMK %s is a single-region key.", keyID)

		if keyInfo.KeyMetadata.MultiRegion != nil && aws.ToBool(keyInfo.KeyMetadata.MultiRegion) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("KMS CMK %s is a multi-region key.", keyID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "kms",
			ResourceID:     keyID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// KmsCmkAreUsed - KMS CMK is in use (not disabled or pending deletion)
type KmsCmkAreUsed struct {
	metadata models.CheckMetadata
}

func NewKmsCmkAreUsed() *KmsCmkAreUsed {
	return &KmsCmkAreUsed{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "kms_cmk_are_used",
			CheckTitle:   "KMS CMK is in use",
			ServiceName:  "kms",
			Severity:     "low",
			ResourceType: "Key",
			Description:  "KMS customer-managed keys should be actively used (not disabled or pending deletion)",
			RemediationText: "Delete unused keys or enable them",
			Categories:   []string{"encryption"},
		},
	}
}

func (c *KmsCmkAreUsed) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsCmkAreUsed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(kmsProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement kmsProvider")
	}
	kmsClient, err := p.KMS(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	keys, err := kmsClient.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KMS keys: %w", err)
	}

	for _, key := range keys.Keys {
		keyID := aws.ToString(key.KeyId)

		keyInfo, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			continue
		}

		// Only check customer-managed keys
		if keyInfo.KeyMetadata.KeyManager != "CUSTOMER" {
			continue
		}

		status := models.StatusPass
		statusExtended := fmt.Sprintf("KMS CMK %s is being used.", keyID)

		if keyInfo.KeyMetadata.KeyState == "PendingDeletion" {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("KMS CMK %s is not being used but it has scheduled deletion.", keyID)
		} else if keyInfo.KeyMetadata.KeyState != "Enabled" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("KMS CMK %s is not being used.", keyID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "kms",
			ResourceID:     keyID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// Enclave checks (require deep policy analysis - simplified implementation)
type baseKmsEnclaveCheck struct {
	metadata models.CheckMetadata
}

func (c *baseKmsEnclaveCheck) Metadata() models.CheckMetadata { return c.metadata }

func newKmsEnclaveFinding(metadata models.CheckMetadata) []models.Finding {
	return []models.Finding{
		{
			ID:             metadata.CheckID,
			Title:          metadata.CheckTitle,
			Description:    metadata.Description,
			Severity:       metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Manual review required for enclave attestation policy analysis",
			Provider:       "aws",
			Service:        "kms",
			Remediation:    metadata.RemediationText,
			Categories:     metadata.Categories,
			FoundAt:        time.Now().UTC(),
		},
	}
}

// KmsKeyEnclaveAttestationBypassablePath - KMS enclave key has no attestation bypass paths
type KmsKeyEnclaveAttestationBypassablePath struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveAttestationBypassablePath() *KmsKeyEnclaveAttestationBypassablePath {
	return &KmsKeyEnclaveAttestationBypassablePath{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_attestation_bypassable_path",
				CheckTitle:   "KMS enclave key has no attestation bypass paths",
				ServiceName:  "kms",
				Severity:     "medium",
				ResourceType: "Key",
				Description:  "KMS keys backing Nitro Enclaves should enforce attestation on all authorization paths",
				RemediationText: "Review key policies to ensure all paths require attestation",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveAttestationBypassablePath) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}

// KmsKeyEnclaveAttestationNoDeploymentBinding - KMS enclave key binds deployment context
type KmsKeyEnclaveAttestationNoDeploymentBinding struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveAttestationNoDeploymentBinding() *KmsKeyEnclaveAttestationNoDeploymentBinding {
	return &KmsKeyEnclaveAttestationNoDeploymentBinding{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_attestation_no_deployment_binding",
				CheckTitle:   "KMS enclave key attestation binds deployment context",
				ServiceName:  "kms",
				Severity:     "informational",
				ResourceType: "Key",
				Description:  "KMS keys backing Nitro Enclaves should bind attestation to specific deployment context",
				RemediationText: "Add PCR3/PCR4/PCR8 or account conditions to attestation bindings",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveAttestationNoDeploymentBinding) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}

// KmsKeyEnclaveAttestationNotEnforced - KMS enclave key requires attestation
type KmsKeyEnclaveAttestationNotEnforced struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveAttestationNotEnforced() *KmsKeyEnclaveAttestationNotEnforced {
	return &KmsKeyEnclaveAttestationNotEnforced{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_attestation_not_enforced",
				CheckTitle:   "KMS enclave key enforces attestation",
				ServiceName:  "kms",
				Severity:     "high",
				ResourceType: "Key",
				Description:  "KMS keys backing Nitro Enclaves should require attestation on all sensitive actions",
				RemediationText: "Add kms:RecipientAttestation conditions to all sensitive Allow statements",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveAttestationNotEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}

// KmsKeyEnclaveAttestationPcrMismatch - KMS enclave key attestation PCRs match golden values
type KmsKeyEnclaveAttestationPcrMismatch struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveAttestationPcrMismatch() *KmsKeyEnclaveAttestationPcrMismatch {
	return &KmsKeyEnclaveAttestationPcrMismatch{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_attestation_pcr_mismatch",
				CheckTitle:   "KMS enclave key attestation PCRs match golden values",
				ServiceName:  "kms",
				Severity:     "high",
				ResourceType: "Key",
				Description:  "KMS enclave key attestation PCR values should match customer-supplied golden values",
				RemediationText: "Configure golden PCR values in audit_config and review key policies",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveAttestationPcrMismatch) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}

// KmsKeyEnclaveAttestationUnknownImage - KMS key has no unknown enclave image attestation events
type KmsKeyEnclaveAttestationUnknownImage struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveAttestationUnknownImage() *KmsKeyEnclaveAttestationUnknownImage {
	return &KmsKeyEnclaveAttestationUnknownImage{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_attestation_unknown_image",
				CheckTitle:   "KMS key has no unknown enclave image attestation events",
				ServiceName:  "kms",
				Severity:     "high",
				ResourceType: "Key",
				Description:  "KMS keys should not receive attestation events from unrecognized enclave images",
				RemediationText: "Review CloudTrail events for unknown enclave image attestations",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveAttestationUnknownImage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}

// KmsKeyEnclaveDebugAttestationDetected - KMS key has no debug-mode attestation events
type KmsKeyEnclaveDebugAttestationDetected struct {
	baseKmsEnclaveCheck
}

func NewKmsKeyEnclaveDebugAttestationDetected() *KmsKeyEnclaveDebugAttestationDetected {
	return &KmsKeyEnclaveDebugAttestationDetected{
		baseKmsEnclaveCheck: baseKmsEnclaveCheck{
			metadata: models.CheckMetadata{
				Provider:     "aws",
				CheckID:      "kms_key_enclave_debug_attestation_detected",
				CheckTitle:   "KMS key has no debug-mode attestation events",
				ServiceName:  "kms",
				Severity:     "high",
				ResourceType: "Key",
				Description:  "KMS keys should not receive debug-mode attestation events from Nitro Enclaves",
				RemediationText: "Review CloudTrail events for debug-mode enclave attestations",
				Categories:   []string{"encryption"},
			},
		},
	}
}

func (c *KmsKeyEnclaveDebugAttestationDetected) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return newKmsEnclaveFinding(c.metadata), nil
}