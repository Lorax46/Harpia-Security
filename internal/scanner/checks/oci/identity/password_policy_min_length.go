package identity

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// PasswordPolicyMinLengthCheck verifica se a política de senha tem mínimo 14 caracteres
type PasswordPolicyMinLengthCheck struct {
	metadata models.CheckMetadata
}

func NewPasswordPolicyMinLength() *PasswordPolicyMinLengthCheck {
	return &PasswordPolicyMinLengthCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_password_policy_minimum_length_14",
			CheckTitle:      "Ensure IAM password policy requires minimum length of 14 characters",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "Policy",
			ResourceGroup:   "IAM",
			Description:     "The IAM password policy requires a minimum password length of 14 characters",
			Risk:            "Shorter passwords are easier to compromise through brute force attacks",
			RemediationText: "Update the IAM password policy to require a minimum password length of 14 characters",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingpasswordrules.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *PasswordPolicyMinLengthCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *PasswordPolicyMinLengthCheck) Execute(ctx context.Context, client identity.IdentityClient, tenancyId string) ([]models.Finding, error) {
	findings := []models.Finding{}

	request := identity.GetAuthenticationPolicyRequest{
		CompartmentId: &tenancyId,
	}

	response, err := client.GetAuthenticationPolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("falha ao obter política de senha: %w", err)
	}

	policy := response.AuthenticationPolicy
	passwordPolicy := policy.PasswordPolicy

	if passwordPolicy == nil {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "IAM password policy is not configured",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		})
		return findings, nil
	}

	minLength := passwordPolicy.MinimumPasswordLength
	if minLength != nil && *minLength >= 14 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: fmt.Sprintf("Password policy requires minimum length of %d characters", *minLength),
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		})
	} else {
		msg := "Password policy does not require minimum length of 14 characters"
		if minLength != nil {
			msg = fmt.Sprintf("Password policy requires minimum length of %d characters (should be 14)", *minLength)
		}
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: msg,
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		})
	}

	return findings, nil
}
