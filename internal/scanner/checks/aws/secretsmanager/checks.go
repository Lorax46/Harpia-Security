package secretsmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type secretsmanagerProvider interface {
	SecretsManager(ctx context.Context) (*secretsmanager.Client, error)
}

// SecretsManagerSecretRotationEnabled - Secrets Manager secret rotation enabled
type SecretsManagerSecretRotationEnabled struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerSecretRotationEnabled() *SecretsManagerSecretRotationEnabled {
	return &SecretsManagerSecretRotationEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_secret_rotation_enabled",
			CheckTitle: "Secrets Manager secret rotation enabled",
			ServiceName: "secretsmanager", Severity: "medium", ResourceType: "Secret",
			Description: "Secrets Manager secrets should have rotation enabled",
			RemediationText: "Enable rotation on Secrets Manager secrets",
			Categories: []string{"secrets"},
		},
	}
}

func (c *SecretsManagerSecretRotationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerSecretRotationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	smClient, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	secrets, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secrets.SecretList {
		secretName := aws.ToString(secret.Name)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("Secret %s does not have rotation enabled.", secretName)

		if secret.RotationEnabled != nil && *secret.RotationEnabled {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("Secret %s has rotation enabled.", secretName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "secretsmanager", ResourceID: secretName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// SecretsManagerSecretUnused - Secrets Manager secret unused
type SecretsManagerSecretUnused struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerSecretUnused() *SecretsManagerSecretUnused {
	return &SecretsManagerSecretUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_secret_unused",
			CheckTitle: "Secrets Manager secret unused",
			ServiceName: "secretsmanager", Severity: "low", ResourceType: "Secret",
			Description: "Secrets Manager secrets should be used",
			RemediationText: "Remove unused secrets",
			Categories: []string{"secrets"},
		},
	}
}

func (c *SecretsManagerSecretUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerSecretUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	smClient, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	secrets, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secrets.SecretList {
		secretName := aws.ToString(secret.Name)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Secret %s is in use.", secretName)

		// Check if the secret has been accessed recently (LastAccessedDate)
		// If LastAccessedDate is nil, the secret has never been accessed
		if secret.LastAccessedDate == nil {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Secret %s has never been accessed (unused).", secretName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "secretsmanager", ResourceID: secretName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// SecretsManagerSecretVersionUnused - Secrets Manager secret version unused
type SecretsManagerSecretVersionUnused struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerSecretVersionUnused() *SecretsManagerSecretVersionUnused {
	return &SecretsManagerSecretVersionUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_secret_version_unused",
			CheckTitle: "Secrets Manager secret version unused",
			ServiceName: "secretsmanager", Severity: "low", ResourceType: "Secret",
			Description: "Secrets Manager secret versions should be used",
			RemediationText: "Remove unused secret versions",
			Categories: []string{"secrets"},
		},
	}
}

func (c *SecretsManagerSecretVersionUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerSecretVersionUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	smClient, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	secrets, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secrets.SecretList {
		secretName := aws.ToString(secret.Name)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Secret %s has no unused versions.", secretName)

		// Check for unused versions by listing secret versions
		// If there are versions that are not in the default stages (AWSCURRENT, AWSPENDING), they are unused
		versions, err := smClient.ListSecretVersionIds(ctx, &secretsmanager.ListSecretVersionIdsInput{
			SecretId: secret.Name,
		})
		if err == nil {
			unusedCount := 0
			for _, version := range versions.Versions {
				if version.VersionStages != nil {
					hasDefaultStage := false
					for _, stage := range version.VersionStages {
						if stage == "AWSCURRENT" || stage == "AWSPENDING" || stage == "AWSPREVIOUS" {
							hasDefaultStage = true
							break
						}
					}
					if !hasDefaultStage {
						unusedCount++
					}
				}
			}
			if unusedCount > 0 {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("Secret %s has %d unused version(s).", secretName, unusedCount)
			}
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "secretsmanager", ResourceID: secretName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// SecretsManagerSecretEncryptedWithCmk - Secrets Manager secret encrypted with CMK
type SecretsManagerSecretEncryptedWithCmk struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerSecretEncryptedWithCmk() *SecretsManagerSecretEncryptedWithCmk {
	return &SecretsManagerSecretEncryptedWithCmk{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_secret_encrypted_with_cmk",
			CheckTitle: "Secrets Manager secret encrypted with CMK",
			ServiceName: "secretsmanager", Severity: "medium", ResourceType: "Secret",
			Description: "Secrets Manager secrets should be encrypted with CMK",
			RemediationText: "Use CMK encryption for Secrets Manager secrets",
			Categories: []string{"secrets", "encryption"},
		},
	}
}

func (c *SecretsManagerSecretEncryptedWithCmk) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerSecretEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	smClient, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	secrets, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secrets.SecretList {
		secretName := aws.ToString(secret.Name)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Secret %s is encrypted with CMK.", secretName)

		if secret.KmsKeyId == nil || aws.ToString(secret.KmsKeyId) == "" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Secret %s is not encrypted with CMK.", secretName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "secretsmanager", ResourceID: secretName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}

// SecretsManagerSecretUnused90Days - Secrets Manager secret unused 90 days
type SecretsManagerSecretUnused90Days struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerSecretUnused90Days() *SecretsManagerSecretUnused90Days {
	return &SecretsManagerSecretUnused90Days{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_secret_unused_90_days",
			CheckTitle: "Secrets Manager secret unused 90 days",
			ServiceName: "secretsmanager", Severity: "medium", ResourceType: "Secret",
			Description: "Secrets Manager secrets should not be unused for 90 days",
			RemediationText: "Remove unused secrets",
			Categories: []string{"secrets"},
		},
	}
}

func (c *SecretsManagerSecretUnused90Days) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerSecretUnused90Days) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	smClient, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	secrets, err := smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	for _, secret := range secrets.SecretList {
		secretName := aws.ToString(secret.Name)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("Secret %s has been accessed within 90 days.", secretName)

		// Check if the secret has been accessed within the last 90 days
		if secret.LastAccessedDate != nil {
			daysSinceAccess := time.Since(*secret.LastAccessedDate).Hours() / 24
			if daysSinceAccess > 90 {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("Secret %s has not been accessed for %.0f days.", secretName, daysSinceAccess)
			}
		} else {
			// Never accessed
			status = models.StatusFail
			statusExtended = fmt.Sprintf("Secret %s has never been accessed.", secretName)
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: statusExtended,
			Provider: "aws", Service: "secretsmanager", ResourceID: secretName,
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now().UTC(),
		})
	}

	return findings, nil
}