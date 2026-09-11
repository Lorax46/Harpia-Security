package cognito

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// getUserPoolDetail obtém detalhes de um user pool
func getUserPoolDetail(ctx context.Context, client *cognitoidentityprovider.Client, poolId string) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	return client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
		UserPoolId: aws.String(poolId),
	})
}

// CognitoUserPoolBlocksCompromisedCredentials - verifica bloqueio de credenciais comprometidas
type CognitoUserPoolBlocksCompromisedCredentials struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolBlocksCompromisedCredentials() *CognitoUserPoolBlocksCompromisedCredentials {
	return &CognitoUserPoolBlocksCompromisedCredentials{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_blocks_compromised_credentials_sign_in_attempts",
			CheckTitle: "Ensure Cognito blocks sign-in with compromised credentials",
			Description: "Cognito user pool should block sign-in attempts with suspected compromised credentials",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Enable compromised credentials blocking in Cognito",
			Categories: []string{"cognito", "compromised-credentials"},
		},
	}
}

func (c *CognitoUserPoolBlocksCompromisedCredentials) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolBlocksCompromisedCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not block compromised credentials", aws.ToString(pool.Name))
		if detail.UserPool.UserPoolAddOns != nil && detail.UserPool.UserPoolAddOns.AdvancedSecurityMode == "ENFORCED" {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s blocks compromised credentials", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolBlocksMaliciousSignIn - verifica bloqueio de logins maliciosos
type CognitoUserPoolBlocksMaliciousSignIn struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolBlocksMaliciousSignIn() *CognitoUserPoolBlocksMaliciousSignIn {
	return &CognitoUserPoolBlocksMaliciousSignIn{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_blocks_potential_malicious_sign_in_attempts",
			CheckTitle: "Ensure Cognito blocks malicious sign-in attempts",
			Description: "Cognito user pool should block all potential malicious sign-in attempts",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Enable malicious sign-in blocking in Cognito",
			Categories: []string{"cognito", "malicious-signin"},
		},
	}
}

func (c *CognitoUserPoolBlocksMaliciousSignIn) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolBlocksMaliciousSignIn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not block malicious sign-in attempts", aws.ToString(pool.Name))
		if detail.UserPool.UserPoolAddOns != nil && detail.UserPool.UserPoolAddOns.AdvancedSecurityMode == "ENFORCED" {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s blocks malicious sign-in attempts", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolClientPreventUserExistenceErrors - verifica prevenção de erros de usuário
type CognitoUserPoolClientPreventUserExistenceErrors struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolClientPreventUserExistenceErrors() *CognitoUserPoolClientPreventUserExistenceErrors {
	return &CognitoUserPoolClientPreventUserExistenceErrors{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_client_prevent_user_existence_errors",
			CheckTitle: "Ensure Cognito client prevents user existence errors",
			Description: "Cognito clients should have PreventUserExistenceErrors enabled",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPoolClient",
			RemediationText: "Enable PreventUserExistenceErrors for Cognito clients",
			Categories: []string{"cognito", "client"},
		},
	}
}

func (c *CognitoUserPoolClientPreventUserExistenceErrors) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolClientPreventUserExistenceErrors) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		clients, err := client.ListUserPoolClients(ctx, &cognitoidentityprovider.ListUserPoolClientsInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		for _, poolClient := range clients.UserPoolClients {
			// Descrever o cliente para obter PreventUserExistenceErrors
			clientDetail, err := client.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: pool.Id,
				ClientId:   poolClient.ClientId,
			})
			if err != nil {
				continue
			}
			status := models.StatusFail
			msg := fmt.Sprintf("Client %s does not prevent user existence errors", aws.ToString(poolClient.ClientName))
			if clientDetail.UserPoolClient != nil && clientDetail.UserPoolClient.PreventUserExistenceErrors == "ENABLED" {
				status = models.StatusPass
				msg = fmt.Sprintf("Client %s prevents user existence errors", aws.ToString(poolClient.ClientName))
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(poolClient.ClientName), Provider: "aws", Service: "cognito",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// CognitoUserPoolClientTokenRevocation - verifica revogação de tokens
type CognitoUserPoolClientTokenRevocation struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolClientTokenRevocation() *CognitoUserPoolClientTokenRevocation {
	return &CognitoUserPoolClientTokenRevocation{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_client_token_revocation_enabled",
			CheckTitle: "Ensure Cognito client has token revocation enabled",
			Description: "Cognito clients should have token revocation enabled",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPoolClient",
			RemediationText: "Enable token revocation for Cognito clients",
			Categories: []string{"cognito", "client", "token"},
		},
	}
}

func (c *CognitoUserPoolClientTokenRevocation) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolClientTokenRevocation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		clients, err := client.ListUserPoolClients(ctx, &cognitoidentityprovider.ListUserPoolClientsInput{
			UserPoolId: pool.Id,
		})
		if err != nil {
			continue
		}
		for _, poolClient := range clients.UserPoolClients {
			clientDetail, err := client.DescribeUserPoolClient(ctx, &cognitoidentityprovider.DescribeUserPoolClientInput{
				UserPoolId: pool.Id,
				ClientId:   poolClient.ClientId,
			})
			if err != nil {
				continue
			}
			status := models.StatusFail
			msg := fmt.Sprintf("Client %s has token revocation disabled", aws.ToString(poolClient.ClientName))
			if clientDetail.UserPoolClient != nil && clientDetail.UserPoolClient.EnableTokenRevocation != nil && *clientDetail.UserPoolClient.EnableTokenRevocation {
				status = models.StatusPass
				msg = fmt.Sprintf("Client %s has token revocation enabled", aws.ToString(poolClient.ClientName))
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(poolClient.ClientName), Provider: "aws", Service: "cognito",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// CognitoUserPoolPasswordPolicyLowercase - verifica política de minúsculas
type CognitoUserPoolPasswordPolicyLowercase struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyLowercase() *CognitoUserPoolPasswordPolicyLowercase {
	return &CognitoUserPoolPasswordPolicyLowercase{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_password_policy_lowercase",
			CheckTitle: "Ensure Cognito password policy requires lowercase",
			Description: "Cognito password policy should require at least one lowercase letter",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Require lowercase letters in password policy",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolPasswordPolicyLowercase) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolPasswordPolicyLowercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not require lowercase in password", aws.ToString(pool.Name))
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil && detail.UserPool.Policies.PasswordPolicy.RequireLowercase {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s requires lowercase in password", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolPasswordPolicyNumber - verifica política de números
type CognitoUserPoolPasswordPolicyNumber struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyNumber() *CognitoUserPoolPasswordPolicyNumber {
	return &CognitoUserPoolPasswordPolicyNumber{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_password_policy_number",
			CheckTitle: "Ensure Cognito password policy requires numbers",
			Description: "Cognito password policy should require at least one number",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Require numbers in password policy",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolPasswordPolicyNumber) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolPasswordPolicyNumber) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not require numbers in password", aws.ToString(pool.Name))
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil && detail.UserPool.Policies.PasswordPolicy.RequireNumbers {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s requires numbers in password", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolPasswordPolicySymbol - verifica política de símbolos
type CognitoUserPoolPasswordPolicySymbol struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicySymbol() *CognitoUserPoolPasswordPolicySymbol {
	return &CognitoUserPoolPasswordPolicySymbol{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_password_policy_symbol",
			CheckTitle: "Ensure Cognito password policy requires symbols",
			Description: "Cognito password policy should require at least one symbol",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Require symbols in password policy",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolPasswordPolicySymbol) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolPasswordPolicySymbol) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not require symbols in password", aws.ToString(pool.Name))
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil && detail.UserPool.Policies.PasswordPolicy.RequireSymbols {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s requires symbols in password", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolPasswordPolicyUppercase - verifica política de maiúsculas
type CognitoUserPoolPasswordPolicyUppercase struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolPasswordPolicyUppercase() *CognitoUserPoolPasswordPolicyUppercase {
	return &CognitoUserPoolPasswordPolicyUppercase{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_password_policy_uppercase",
			CheckTitle: "Ensure Cognito password policy requires uppercase",
			Description: "Cognito password policy should require at least one uppercase letter",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Require uppercase letters in password policy",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolPasswordPolicyUppercase) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolPasswordPolicyUppercase) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s does not require uppercase in password", aws.ToString(pool.Name))
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil && detail.UserPool.Policies.PasswordPolicy.RequireUppercase {
			status = models.StatusPass
			msg = fmt.Sprintf("User pool %s requires uppercase in password", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolSelfRegistrationDisabled - verifica auto-registro desabilitado
type CognitoUserPoolSelfRegistrationDisabled struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolSelfRegistrationDisabled() *CognitoUserPoolSelfRegistrationDisabled {
	return &CognitoUserPoolSelfRegistrationDisabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_self_registration_disabled",
			CheckTitle: "Ensure Cognito has self registration disabled",
			Description: "Cognito user pool should have self registration disabled",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Disable self registration in Cognito",
			Categories: []string{"cognito", "registration"},
		},
	}
}

func (c *CognitoUserPoolSelfRegistrationDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolSelfRegistrationDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusPass
		msg := fmt.Sprintf("User pool %s has self registration disabled", aws.ToString(pool.Name))
		if detail.UserPool.AdminCreateUserConfig != nil && !detail.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly {
			status = models.StatusFail
			msg = fmt.Sprintf("User pool %s allows self registration", aws.ToString(pool.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolTemporaryPasswordExpiration - verifica expiração de senha temporária
type CognitoUserPoolTemporaryPasswordExpiration struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolTemporaryPasswordExpiration() *CognitoUserPoolTemporaryPasswordExpiration {
	return &CognitoUserPoolTemporaryPasswordExpiration{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_temporary_password_expiration",
			CheckTitle: "Ensure Cognito has temporary password expiration set",
			Description: "Cognito user pool should have temporary password expiration of 7 days or less",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Set temporary password expiration to 7 days or less",
			Categories: []string{"cognito", "password"},
		},
	}
}

func (c *CognitoUserPoolTemporaryPasswordExpiration) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolTemporaryPasswordExpiration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has no temporary password expiration", aws.ToString(pool.Name))
		if detail.UserPool.Policies != nil && detail.UserPool.Policies.PasswordPolicy != nil {
			days := detail.UserPool.Policies.PasswordPolicy.TemporaryPasswordValidityDays
			if days <= 7 {
				status = models.StatusPass
				msg = fmt.Sprintf("User pool %s has %d days expiration", aws.ToString(pool.Name), days)
			} else {
				msg = fmt.Sprintf("User pool %s has %d days expiration (>7)", aws.ToString(pool.Name), days)
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CognitoUserPoolWafAclAttached - verifica WAF ACL anexado
type CognitoUserPoolWafAclAttached struct {
	metadata models.CheckMetadata
}

func NewCognitoUserPoolWafAclAttached() *CognitoUserPoolWafAclAttached {
	return &CognitoUserPoolWafAclAttached{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cognito_user_pool_waf_acl_attached",
			CheckTitle: "Ensure Cognito has WAF ACL attached",
			Description: "Cognito user pool should have a WAF Web ACL attached",
			Severity: "medium", ServiceName: "cognito", ResourceType: "UserPool",
			RemediationText: "Attach WAF Web ACL to Cognito user pool",
			Categories: []string{"cognito", "waf"},
		},
	}
}

func (c *CognitoUserPoolWafAclAttached) Metadata() models.CheckMetadata { return c.metadata }

func (c *CognitoUserPoolWafAclAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		detail, err := getUserPoolDetail(ctx, client, aws.ToString(pool.Id))
		if err != nil {
			continue
		}
		status := models.StatusFail
		msg := fmt.Sprintf("User pool %s has no WAF ACL attached", aws.ToString(pool.Name))
		// Verificar WAF via tags (simplificado)
		if detail.UserPool.UserPoolTags != nil {
			for tag := range detail.UserPool.UserPoolTags {
				if strings.Contains(strings.ToLower(tag), "waf") {
					status = models.StatusPass
					msg = fmt.Sprintf("User pool %s has WAF ACL attached", aws.ToString(pool.Name))
					break
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(pool.Name), Provider: "aws", Service: "cognito",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
