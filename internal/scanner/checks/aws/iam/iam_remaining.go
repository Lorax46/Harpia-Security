package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMRootMfaEnabled - verifica MFA na conta root
type IAMRootMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewIAMRootMfaEnabled() *IAMRootMfaEnabled {
	return &IAMRootMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "iam_root_mfa_enabled",
			CheckTitle: "Ensure MFA is enabled for root account",
			Description: "MFA should be enabled for the root account",
			Severity: "critical", ServiceName: "iam", ResourceType: "RootAccount",
			RemediationText: "Enable MFA for the root account",
			Categories: []string{"iam", "mfa", "root"},
		},
	}
}

func (c *IAMRootMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *IAMRootMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(iamProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement iamProvider")
	}
	client, err := p.IAM(ctx)
	if err != nil {
		return nil, err
	}

	summary, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "MFA is not enabled for root account"
	if summary.SummaryMap != nil {
		if v, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && v == 1 {
			status = models.StatusPass
			msg = "MFA is enabled for root account"
		}
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "root", Provider: "aws", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}
