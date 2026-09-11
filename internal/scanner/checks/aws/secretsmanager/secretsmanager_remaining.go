package secretsmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsManagerNotPubliclyAccessible - verifica acesso público
type SecretsManagerNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerNotPubliclyAccessible() *SecretsManagerNotPubliclyAccessible {
	return &SecretsManagerNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_not_publicly_accessible",
			CheckTitle: "Ensure secrets are not publicly accessible",
			Description: "Secrets should not have public resource policies",
			Severity: "critical", ServiceName: "secretsmanager", ResourceType: "Secret",
			RemediationText: "Remove public access from secrets",
			Categories: []string{"secretsmanager", "public-access"},
		},
	}
}

func (c *SecretsManagerNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	client, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, secret := range result.SecretList {
		status := models.StatusPass
		msg := fmt.Sprintf("Secret %s is not publicly accessible", aws.ToString(secret.Name))
		policy, err := client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
			SecretId: secret.ARN,
		})
		if err == nil && policy.ResourcePolicy != nil {
			policyStr := aws.ToString(policy.ResourcePolicy)
			if policyStr == "*" || policyStr == "{}" {
				status = models.StatusFail
				msg = fmt.Sprintf("Secret %s may be publicly accessible", aws.ToString(secret.Name))
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(secret.Name), Provider: "aws", Service: "secretsmanager",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// SecretsManagerRestrictiveResourcePolicy - verifica política restritiva
type SecretsManagerRestrictiveResourcePolicy struct {
	metadata models.CheckMetadata
}

func NewSecretsManagerRestrictiveResourcePolicy() *SecretsManagerRestrictiveResourcePolicy {
	return &SecretsManagerRestrictiveResourcePolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "secretsmanager_has_restrictive_resource_policy",
			CheckTitle: "Ensure secrets have restrictive resource policies",
			Description: "Secrets should have restrictive resource policies",
			Severity: "medium", ServiceName: "secretsmanager", ResourceType: "Secret",
			RemediationText: "Add restrictive resource policies to secrets",
			Categories: []string{"secretsmanager", "policy"},
		},
	}
}

func (c *SecretsManagerRestrictiveResourcePolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecretsManagerRestrictiveResourcePolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(secretsmanagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement secretsmanagerProvider")
	}
	client, err := p.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, secret := range result.SecretList {
		status := models.StatusFail
		msg := fmt.Sprintf("Secret %s has no resource policy", aws.ToString(secret.Name))
		_, err := client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
			SecretId: secret.ARN,
		})
		if err == nil {
			status = models.StatusPass
			msg = fmt.Sprintf("Secret %s has resource policy", aws.ToString(secret.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(secret.Name), Provider: "aws", Service: "secretsmanager",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
