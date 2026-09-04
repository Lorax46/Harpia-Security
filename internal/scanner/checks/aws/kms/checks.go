package kms

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// KmsCmkNotDeletedUnintentionally - AWS KMS customer managed key is not scheduled for deletion
type KmsCmkNotDeletedUnintentionally struct {
    metadata models.CheckMetadata
}

func NewKmsCmkNotDeletedUnintentionally() *KmsCmkNotDeletedUnintentionally {
    return &KmsCmkNotDeletedUnintentionally{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_cmk_not_deleted_unintentionally",
            CheckTitle: "AWS KMS customer managed key is not scheduled for deletion",
            ServiceName: "kms",
            Severity: "critical",
            Description: "**Customer-managed KMS keys** are evaluated for the `PendingDeletion` state, indicating a scheduled deletion during the mandatory waiting period.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsCmkNotDeletedUnintentionally) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsCmkNotDeletedUnintentionally) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveAttestationPcrMismatch - KMS enclave key attestation PCRs match customer-supplied golden values
type KmsKeyEnclaveAttestationPcrMismatch struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveAttestationPcrMismatch() *KmsKeyEnclaveAttestationPcrMismatch {
    return &KmsKeyEnclaveAttestationPcrMismatch{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_attestation_pcr_mismatch",
            CheckTitle: "KMS enclave key attestation PCRs match customer-supplied golden values",
            ServiceName: "kms",
            Severity: "medium",
            Description: "Compares the `kms:RecipientAttestation:PCR<N>` (and equivalent `ImageSha384`) values referenced by an enclave key policy against a customer-provided list of trusted PCR hashes configured under `enclave_golden_pcr_values` in `audit_config`. Detects **image provenance drift**: policies whose attestation conditions still reference PCRs that no longer correspond to a known-good build.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveAttestationPcrMismatch) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveAttestationPcrMismatch) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveAttestationUnknownImage - No enclave with an unknown image identity has called this KMS key
type KmsKeyEnclaveAttestationUnknownImage struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveAttestationUnknownImage() *KmsKeyEnclaveAttestationUnknownImage {
    return &KmsKeyEnclaveAttestationUnknownImage{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_attestation_unknown_image",
            CheckTitle: "No enclave with an unknown image identity has called this KMS key",
            ServiceName: "kms",
            Severity: "medium",
            Description: "Scans CloudTrail attestation activity and flags PCR values missing from `enclave_golden_pcr_values` (only for buckets with a configured golden list). Complements `kms_key_enclave_attestation_pcr_mismatch` by catching real enclave calls with an unrecognized image. MEDIUM by default, overridable to HIGH via `enclave_unknown_image_severity`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveAttestationUnknownImage) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveAttestationUnknownImage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyNotPubliclyAccessible - Cloud KMS key does not grant access to allUsers or allAuthenticatedUsers
type KmsKeyNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewKmsKeyNotPubliclyAccessible() *KmsKeyNotPubliclyAccessible {
    return &KmsKeyNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_not_publicly_accessible",
            CheckTitle: "Cloud KMS key does not grant access to allUsers or allAuthenticatedUsers",
            ServiceName: "kms",
            Severity: "critical",
            Description: "**KMS keys** are assessed for **excessive access** in key policies or grants, including `*` principals and broadly scoped permissions to multiple identities.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveAttestationNoDeploymentBinding - KMS enclave key attestation binds a specific deployment context
type KmsKeyEnclaveAttestationNoDeploymentBinding struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveAttestationNoDeploymentBinding() *KmsKeyEnclaveAttestationNoDeploymentBinding {
    return &KmsKeyEnclaveAttestationNoDeploymentBinding{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_attestation_no_deployment_binding",
            CheckTitle: "KMS enclave key attestation binds a specific deployment context",
            ServiceName: "kms",
            Severity: "informational",
            Description: "Sensitive Allow statements on enclave KMS keys are checked for deployment-context binding: PCR3 (parent IAM role, AWS-recommended), PCR4 (parent instance ID), PCR8 (EIF signing cert), or an account-level condition (aws:PrincipalAccount / SourceAccount / OrgID / ResourceAccount / OrgPaths) paired with a RecipientAttestation binding. PCR0/PCR1/PCR2 travel with the EIF and do not bind deployment.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveAttestationNoDeploymentBinding) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveAttestationNoDeploymentBinding) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsCmkRotationEnabled - KMS customer-managed symmetric CMK has automatic rotation enabled
type KmsCmkRotationEnabled struct {
    metadata models.CheckMetadata
}

func NewKmsCmkRotationEnabled() *KmsCmkRotationEnabled {
    return &KmsCmkRotationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_cmk_rotation_enabled",
            CheckTitle: "KMS customer-managed symmetric CMK has automatic rotation enabled",
            ServiceName: "kms",
            Severity: "high",
            Description: "**Customer-managed KMS symmetric keys** in the `Enabled` state are evaluated to confirm `automatic rotation` of key material is configured",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsCmkRotationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsCmkRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsCmkNotMultiRegion - AWS KMS customer managed key is single-Region
type KmsCmkNotMultiRegion struct {
    metadata models.CheckMetadata
}

func NewKmsCmkNotMultiRegion() *KmsCmkNotMultiRegion {
    return &KmsCmkNotMultiRegion{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_cmk_not_multi_region",
            CheckTitle: "AWS KMS customer managed key is single-Region",
            ServiceName: "kms",
            Severity: "medium",
            Description: "**AWS KMS customer-managed keys** in an `Enabled` state are assessed for the `multi-Region` setting. The finding highlights keys with the `multi-Region` property enabled.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsCmkNotMultiRegion) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsCmkNotMultiRegion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveAttestationNotEnforced - KMS enclave key requires kms:RecipientAttestation conditions on sensitive actions
type KmsKeyEnclaveAttestationNotEnforced struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveAttestationNotEnforced() *KmsKeyEnclaveAttestationNotEnforced {
    return &KmsKeyEnclaveAttestationNotEnforced{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_attestation_not_enforced",
            CheckTitle: "KMS enclave key requires kms:RecipientAttestation conditions on sensitive actions",
            ServiceName: "kms",
            Severity: "high",
            Description: "**Customer-managed KMS keys** used with Nitro Enclaves (identified by `prowler:enclave-key=true` tag, `enclave` in description/tags/aliases, or a policy referencing `kms:RecipientAttestation:*`). Every `Allow` on sensitive actions (`kms:Decrypt`, `DeriveSharedSecret`, `GenerateDataKey*`, `GenerateRandom`, `kms:*`, `*`) must require a `kms:RecipientAttestation:*` condition.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveAttestationNotEnforced) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveAttestationNotEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveDebugAttestationDetected - No Nitro Enclave debug-mode attestation observed against this KMS key
type KmsKeyEnclaveDebugAttestationDetected struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveDebugAttestationDetected() *KmsKeyEnclaveDebugAttestationDetected {
    return &KmsKeyEnclaveDebugAttestationDetected{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_debug_attestation_detected",
            CheckTitle: "No Nitro Enclave debug-mode attestation observed against this KMS key",
            ServiceName: "kms",
            Severity: "high",
            Description: "Detects **Nitro Enclaves** launched with `--debug-mode` via CloudTrail KMS-from-enclave events. Debug enclaves produce attestations with zeroed image/kernel/application PCRs (PCR0/1/2); the check flags every KMS key that received such a call. Configurable via `enclave_debug_lookback_window_hours` (default 2160h / 90d) and `enclave_debug_max_events` (5000).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveDebugAttestationDetected) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveDebugAttestationDetected) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsCmkAreUsed - KMS customer managed key is enabled or scheduled for deletion
type KmsCmkAreUsed struct {
    metadata models.CheckMetadata
}

func NewKmsCmkAreUsed() *KmsCmkAreUsed {
    return &KmsCmkAreUsed{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_cmk_are_used",
            CheckTitle: "KMS customer managed key is enabled or scheduled for deletion",
            ServiceName: "kms",
            Severity: "low",
            Description: "**Customer-managed KMS keys** are assessed by key state. Keys in `Enabled` are considered in use. Keys not `Enabled` and not `PendingDeletion` are identified as unused, while those in `PendingDeletion` are recognized as scheduled for removal.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsCmkAreUsed) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsCmkAreUsed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// KmsKeyEnclaveAttestationBypassablePath - KMS enclave key has no authorization path that bypasses attestation
type KmsKeyEnclaveAttestationBypassablePath struct {
    metadata models.CheckMetadata
}

func NewKmsKeyEnclaveAttestationBypassablePath() *KmsKeyEnclaveAttestationBypassablePath {
    return &KmsKeyEnclaveAttestationBypassablePath{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "kms_key_enclave_attestation_bypassable_path",
            CheckTitle: "KMS enclave key has no authorization path that bypasses attestation",
            ServiceName: "kms",
            Severity: "high",
            Description: "Detects **bypass paths** in enclave KMS key policies: `Allow` statements that grant sensitive KMS actions without a restrictive `kms:RecipientAttestation:*` condition and without a paired `Deny` that neutralizes the gap. Includes the common root-delegation shape (`Principal: root`, `Action: kms:*`) when it is not paired with an attestation Deny.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"kms"},
        },
    }
}

func (c *KmsKeyEnclaveAttestationBypassablePath) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *KmsKeyEnclaveAttestationBypassablePath) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "kms",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

