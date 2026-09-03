package identity

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// MFACheck verifica se MFA está habilitado para usuários console
type MFACheck struct {
	metadata models.CheckMetadata
}

func NewMFACheck() *MFACheck {
	return &MFACheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "identity_user_mfa_enabled_console_access",
			CheckTitle:      "Ensure MFA is enabled for all console users",
			ServiceName:     "identity",
			Severity:        "high",
			ResourceType:    "User",
			ResourceGroup:   "IAM",
			Description:     "Multi-factor authentication (MFA) should be enabled for all users with console access",
			Risk:            "Accounts without MFA are more susceptible to credential compromise",
			RemediationText: "Enable MFA for all users with console access",
			RemediationURL:  "https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/usingmfa.htm",
			Categories:      []string{"iam"},
		},
	}
}

func (c *MFACheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *MFACheck) Execute(ctx context.Context, client identity.IdentityClient, tenancyId string) ([]models.Finding, error) {
	findings := []models.Finding{}

	// Listar todos os usuários
	listReq := identity.ListUsersRequest{
		CompartmentId: &tenancyId,
	}

	users, err := client.ListUsers(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar usuários: %w", err)
	}

	for _, user := range users.Items {
		// Verificar se é MFA habilitado
		if !isMFAEnabled(user) {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusFail,
				StatusExtended: fmt.Sprintf("User %s does not have MFA enabled", *user.Name),
				ResourceID:     *user.Id,
				ResourceARN:    fmt.Sprintf("oci:iam::%s:user/%s", tenancyId, *user.Name),
				Provider:       "oci",
				Service:        "identity",
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "All users have MFA enabled",
			Provider:       "oci",
			Service:        "identity",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		})
	}

	return findings, nil
}

func isMFAEnabled(user identity.User) bool {
	return user.IsMfaActivated != nil && *user.IsMfaActivated
}
