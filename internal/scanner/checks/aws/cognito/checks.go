package cognito

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type cognitoProvider interface {
	Cognito(ctx context.Context) (*cognitoidentityprovider.Client, error)
}

// CognitoUserPoolPasswordPolicyMinLength14 verifica tamanho mínimo de senha
type CognitoUserPoolPasswordPolicyMinLength14 struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyMinLength14() *CognitoUserPoolPasswordPolicyMinLength14 {
	return &CognitoUserPoolPasswordPolicyMinLength14{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_password_policy_minimum_length_14",
			CheckTitle: "Ensure Cognito user pool password policy requires min length 14",
			Description: "Cognito user pool password policy should require minimum length of 14 characters",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Update Cognito user pool password policy to require min 14 chars",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolPasswordPolicyMinLength14) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolPasswordPolicyMinLength14) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cognitoProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cognitoProvider")
	}
	
	client, err := p.Cognito(ctx)
	if err != nil {
		return nil, err
	}
	
	pools, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, pool := range pools.UserPools {
		detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has no password policy set", *pool.Name)
		
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil {
			minLen := int32(0)
			if detail.UserPool.Policies.PasswordPolicy.MinimumLength != nil {
				minLen = *detail.UserPool.Policies.PasswordPolicy.MinimumLength
			}
			if minLen >= 14 {
				status = models.StatusPass
				msg = fmt.Sprintf("User pool %s requires min length %d", *pool.Name, minLen)
			} else {
				msg = fmt.Sprintf("User pool %s does not require min length 14", *pool.Name)
			}
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *pool.Name, Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CognitoUserPoolMfaEnabled verifica MFA
type CognitoUserPoolMfaEnabled struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolMfaEnabled() *CognitoUserPoolMfaEnabled {
	return &CognitoUserPoolMfaEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_mfa_enabled",
			CheckTitle: "Ensure Cognito user pool has MFA enabled",
			Description: "Cognito user pool should have MFA enabled",
			Severity: "high", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Enable MFA for Cognito user pool",
			Categories: []string{"cognito", "mfa"},
		},
	}
}

func (c *CognitoUserPoolMfaEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolMfaEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cognitoProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cognitoProvider")
	}
	
	client, err := p.Cognito(ctx)
	if err != nil {
		return nil, err
	}
	
	pools, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, pool := range pools.UserPools {
		detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has MFA disabled", *pool.Name)
		
		if detail.UserPool.MfaConfiguration == types.UserPoolMfaTypeOn {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s has MFA enabled", *pool.Name)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *pool.Name, Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CognitoUserPoolAdvancedSecurityEnabled verifica segurança avançada
type CognitoUserPoolAdvancedSecurityEnabled struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolAdvancedSecurityEnabled() *CognitoUserPoolAdvancedSecurityEnabled {
	return &CognitoUserPoolAdvancedSecurityEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_advanced_security_enabled",
			CheckTitle: "Ensure Cognito user pool has advanced security enabled",
			Description: "Cognito user pool should have advanced security enabled",
			Severity: "high", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Enable advanced security for Cognito user pool",
			Categories: []string{"cognito", "advanced-security"},
		},
	}
}

func (c *CognitoUserPoolAdvancedSecurityEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolAdvancedSecurityEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cognitoProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cognitoProvider")
	}
	
	client, err := p.Cognito(ctx)
	if err != nil {
		return nil, err
	}
	
	pools, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, pool := range pools.UserPools {
		detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has advanced security disabled", *pool.Name)
		
		if detail.UserPool.UserPoolAddOns != nil {
			switch detail.UserPool.UserPoolAddOns.AdvancedSecurityMode {
			case "ENFORCED":
				status = models.StatusPass
				msg = fmt.Sprintf("User pool %s has advanced security enforced", *pool.Name)
			case "AUDIT":
				msg = fmt.Sprintf("User pool %s has advanced security in audit-only mode", *pool.Name)
			}
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *pool.Name, Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CognitoUserPoolDeletionProtection verifica proteção de deleção
type CognitoUserPoolDeletionProtection struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolDeletionProtection() *CognitoUserPoolDeletionProtection {
	return &CognitoUserPoolDeletionProtection{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_deletion_protection_enabled",
			CheckTitle: "Ensure Cognito user pool has deletion protection enabled",
			Description: "Cognito user pool should have deletion protection enabled",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Enable deletion protection for Cognito user pool",
			Categories: []string{"cognito", "deletion-protection"},
		},
	}
}

func (c *CognitoUserPoolDeletionProtection) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolDeletionProtection) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cognitoProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cognitoProvider")
	}
	
	client, err := p.Cognito(ctx)
	if err != nil {
		return nil, err
	}
	
	pools, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, pool := range pools.UserPools {
		detail, err := client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has deletion protection disabled", *pool.Name)
		
		if detail.UserPool.DeletionProtection == types.DeletionProtectionTypeActive {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s has deletion protection enabled", *pool.Name)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *pool.Name, Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}
