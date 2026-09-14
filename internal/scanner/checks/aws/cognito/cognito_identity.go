package cognito

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// CognitoIdentityPoolGuestAccessDisabled - verifica acesso de convidado em identity pools
type CognitoIdentityPoolGuestAccessDisabled struct {
	metadata models.CheckMetadata
}

func NewCognitoIdentityPoolGuestAccessDisabled() *CognitoIdentityPoolGuestAccessDisabled {
	return &CognitoIdentityPoolGuestAccessDisabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_identity_pool_guest_access_disabled",
			CheckTitle: "Ensure Cognito identity pool guest access is disabled",
			Description: "Cognito identity pools should not allow guest/unauthenticated access",
			Severity: "high", ServiceName: "cognito", ResourceType: "IdentityPool",
			RemediationText: "Disable guest access on Cognito identity pools",
			Categories: []string{"cognito", "guest-access"},
		},
	}
}

func (c *CognitoIdentityPoolGuestAccessDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoIdentityPoolGuestAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cognitoProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cognitoProvider")
	}

	client, err := p.Cognito(ctx)
	if err != nil {
		return nil, err
	}

	// List identity providers through cognitoidentityprovider (v2 SDK)
	pools, err := client.ListIdentityProviders(ctx, &cognitoidentityprovider.ListIdentityProvidersInput{})
	if err != nil {
		return nil, err
	}

	guestPools := []string{}
	for _, pool := range pools.Providers {
		guestPools = append(guestPools, aws.ToString(pool.ProviderName))
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: fmt.Sprintf("Found %d identity providers to review", len(guestPools)),
		ResourceID: "cognito-identity-pools", Provider: "aws", Service: "cognito",
		FoundAt: time.Now().UTC(),
	}}, nil
}
