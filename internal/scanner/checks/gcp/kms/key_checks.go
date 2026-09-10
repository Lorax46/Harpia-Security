package kms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/cloudkms/v1"
)

// === kms_key_not_publicly_accessible ===

type KMSKeyNotPubliclyAccessibleCheck struct {
	metadata models.CheckMetadata
}

func NewKMSKeyNotPubliclyAccessibleCheck() *KMSKeyNotPubliclyAccessibleCheck {
	return &KMSKeyNotPubliclyAccessibleCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "kms_key_not_publicly_accessible",
			CheckTitle:      "Cloud KMS key has no public IAM access",
			ServiceName:     "kms",
			Severity:        "high",
			ResourceType:    "CryptoKey",
			ResourceGroup:   "CloudKMS",
			Description:     "Cloud KMS crypto keys are evaluated for public principals in their IAM bindings, specifically allUsers and allAuthenticatedUsers.",
			Risk:            "Publicly accessible KMS keys allow anyone to encrypt/decrypt data, potentially exposing sensitive information",
			RemediationText: "Remove allUsers and allAuthenticatedUsers from key IAM. Grant access only to specific groups or service accounts with least privilege at the key scope.",
			RemediationURL:  "https://cloud.google.com/kms/docs/iam",
			Categories:      []string{"kms", "iam", "encryption", "access-control"},
		},
	}
}

func (c *KMSKeyNotPubliclyAccessibleCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *KMSKeyNotPubliclyAccessibleCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		KMS(ctx context.Context) (*cloudkms.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa KMS() ou ProjectID()")
	}

	kmsService, err := p.KMS(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente KMS: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// List all key rings in the project
	keyRings, err := listKeyRings(ctx, kmsService, projectID)
	if err != nil {
		return nil, err
	}

	for _, keyRing := range keyRings {
		// List all crypto keys in each key ring
		keys, err := listCryptoKeys(ctx, kmsService, keyRing.Name)
		if err != nil {
			continue
		}

		for _, key := range keys {
			// Get IAM policy for each key
			policy, err := getCryptoKeyIAMPolicy(ctx, kmsService, key.Name)
			if err != nil {
				continue
			}

			// Check for public access
			hasPublicAccess := false
			publicPrincipals := []string{}
			for _, binding := range policy.Bindings {
				for _, member := range binding.Members {
					if member == "allUsers" || member == "allAuthenticatedUsers" {
						hasPublicAccess = true
						publicPrincipals = append(publicPrincipals, member)
					}
				}
			}

			if hasPublicAccess {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud KMS key '%s' has public IAM access: %s", key.Name, strings.Join(publicPrincipals, ", ")),
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			} else {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud KMS key '%s' has no public IAM access", key.Name),
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// === kms_key_rotation_enabled ===

type KMSKeyRotationEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewKMSKeyRotationEnabledCheck() *KMSKeyRotationEnabledCheck {
	return &KMSKeyRotationEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "kms_key_rotation_enabled",
			CheckTitle:      "KMS key has automatic rotation enabled",
			ServiceName:     "kms",
			Severity:        "low",
			ResourceType:    "CryptoKey",
			ResourceGroup:   "CloudKMS",
			Description:     "Google Cloud KMS customer-managed keys have automatic rotation enabled, regardless of the rotation interval.",
			Risk:            "Without automatic rotation, key material remains in use for extended periods, increasing the risk of cryptographic compromise",
			RemediationText: "Enable auto-rotation for customer-managed keys by configuring a rotation period.",
			RemediationURL:  "https://cloud.google.com/kms/docs/key-rotation",
			Categories:      []string{"kms", "encryption", "key-management"},
		},
	}
}

func (c *KMSKeyRotationEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *KMSKeyRotationEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		KMS(ctx context.Context) (*cloudkms.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa KMS() ou ProjectID()")
	}

	kmsService, err := p.KMS(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente KMS: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// List all key rings in the project
	keyRings, err := listKeyRings(ctx, kmsService, projectID)
	if err != nil {
		return nil, err
	}

	for _, keyRing := range keyRings {
		// List all crypto keys in each key ring
		keys, err := listCryptoKeys(ctx, kmsService, keyRing.Name)
		if err != nil {
			continue
		}

		for _, key := range keys {
			// Check if rotation is enabled
			rotationEnabled := key.RotationPeriod != "" || key.NextRotationTime != ""

			if !rotationEnabled {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Cloud KMS key '%s' does not have automatic rotation enabled", key.Name),
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			} else {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud KMS key '%s' has automatic rotation enabled (rotation period: %s)", key.Name, key.RotationPeriod),
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// === kms_key_rotation_max_90_days ===

type KMSKeyRotationMax90DaysCheck struct {
	metadata models.CheckMetadata
}

func NewKMSKeyRotationMax90DaysCheck() *KMSKeyRotationMax90DaysCheck {
	return &KMSKeyRotationMax90DaysCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "kms_key_rotation_max_90_days",
			CheckTitle:      "KMS key is rotated every 90 days or less",
			ServiceName:     "kms",
			Severity:        "low",
			ResourceType:    "CryptoKey",
			ResourceGroup:   "CloudKMS",
			Description:     "Google Cloud KMS customer-managed keys are rotated with an interval of 90 days or less, in line with the CIS Benchmark.",
			Risk:            "Keys rotated less frequently than 90 days increase the window of exposure if a key version is compromised",
			RemediationText: "Enable auto-rotation for customer-managed keys with an interval of 90 days or less.",
			RemediationURL:  "https://cloud.google.com/kms/docs/key-rotation",
			Categories:      []string{"kms", "encryption", "key-management"},
		},
	}
}

func (c *KMSKeyRotationMax90DaysCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *KMSKeyRotationMax90DaysCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		KMS(ctx context.Context) (*cloudkms.Service, error)
		ProjectID() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa KMS() ou ProjectID()")
	}

	kmsService, err := p.KMS(ctx)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar cliente KMS: %w", err)
	}

	projectID := p.ProjectID()
	findings := []models.Finding{}

	// List all key rings in the project
	keyRings, err := listKeyRings(ctx, kmsService, projectID)
	if err != nil {
		return nil, err
	}

	for _, keyRing := range keyRings {
		// List all crypto keys in each key ring
		keys, err := listCryptoKeys(ctx, kmsService, keyRing.Name)
		if err != nil {
			continue
		}

		for _, key := range keys {
			// Check if rotation period is <= 90 days (90 * 24 * 3600 = 7776000 seconds)
			rotationPeriod := key.RotationPeriod
			maxRotationPeriod := "7776000s" // 90 days in seconds

			isWithinLimit := false
			if rotationPeriod != "" {
				isWithinLimit = compareRotationPeriods(rotationPeriod, maxRotationPeriod)
			}

			if !isWithinLimit {
				statusExtended := fmt.Sprintf("Cloud KMS key '%s' does not have rotation period <= 90 days", key.Name)
				if rotationPeriod != "" {
					statusExtended = fmt.Sprintf("Cloud KMS key '%s' has rotation period %s (should be <= 90 days)", key.Name, rotationPeriod)
				}
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: statusExtended,
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			} else {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Cloud KMS key '%s' has rotation period <= 90 days (%s)", key.Name, rotationPeriod),
					ResourceID:     key.Name,
					ResourceARN:    key.Name,
					Provider:       "gcp",
					Service:        "kms",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// Helper functions for KMS checks

// listKeyRings lists all key rings in a project across all locations
func listKeyRings(ctx context.Context, kmsService *cloudkms.Service, projectID string) ([]*cloudkms.KeyRing, error) {
	var keyRings []*cloudkms.KeyRing

	parent := fmt.Sprintf("projects/%s", projectID)
	
	// List key rings across all locations (- means all locations)
	req := kmsService.Projects.Locations.KeyRings.List(parent + "/locations/-")
	if err := req.Pages(ctx, func(page *cloudkms.ListKeyRingsResponse) error {
		keyRings = append(keyRings, page.KeyRings...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar key rings: %w", err)
	}

	return keyRings, nil
}

// listCryptoKeys lists all crypto keys in a key ring
func listCryptoKeys(ctx context.Context, kmsService *cloudkms.Service, keyRingName string) ([]*cloudkms.CryptoKey, error) {
	var keys []*cloudkms.CryptoKey

	req := kmsService.Projects.Locations.KeyRings.CryptoKeys.List(keyRingName)
	if err := req.Pages(ctx, func(page *cloudkms.ListCryptoKeysResponse) error {
		keys = append(keys, page.CryptoKeys...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("falha ao listar crypto keys: %w", err)
	}

	return keys, nil
}

// getCryptoKeyIAMPolicy gets the IAM policy for a crypto key
func getCryptoKeyIAMPolicy(ctx context.Context, kmsService *cloudkms.Service, keyName string) (*cloudkms.Policy, error) {
	policy, err := kmsService.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(keyName).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("falha ao obter IAM policy: %w", err)
	}
	return policy, nil
}

// compareRotationPeriods checks if rotation period is <= max period
// Periods are in format like "7776000s" (seconds)
func compareRotationPeriods(rotationPeriod, maxPeriod string) bool {
	// Parse rotation period seconds
	rotationSeconds := parseRotationPeriodSeconds(rotationPeriod)
	maxSeconds := parseRotationPeriodSeconds(maxPeriod)
	
	return rotationSeconds > 0 && rotationSeconds <= maxSeconds
}

// parseRotationPeriodSeconds parses a rotation period string (e.g., "7776000s") to seconds
func parseRotationPeriodSeconds(period string) int64 {
	if period == "" {
		return 0
	}
	
	// Remove trailing 's' if present
	period = strings.TrimSuffix(period, "s")
	
	var seconds int64
	_, err := fmt.Sscanf(period, "%d", &seconds)
	if err != nil {
		return 0
	}
	return seconds
}