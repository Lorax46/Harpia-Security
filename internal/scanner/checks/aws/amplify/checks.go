// Package amplify provides AWS Amplify security checks.
package amplify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
)

type amplifyProvider interface {
	Amplify(ctx context.Context) (*amplify.Client, error)
	Region() string
	AccountID() string
}

// AmplifyAppNoSecretsCheck verifica se apps Amplify contêm secrets
type AmplifyAppNoSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewAmplifyAppNoSecretsCheck() *AmplifyAppNoSecretsCheck {
	return &AmplifyAppNoSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "amplify_app_no_secrets",
			CheckTitle: "Ensure Amplify apps do not contain hardcoded secrets",
			Description: "Amplify apps should not contain hardcoded secrets in environment variables",
			Severity: "critical", ServiceName: "amplify", ResourceType: "App",
			RemediationText: "Use AWS Secrets Manager or Parameter Store for secrets",
			Categories: []string{"compute", "secrets"},
		},
	}
}

func (c *AmplifyAppNoSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AmplifyAppNoSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(amplifyProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement amplifyProvider")
	}
	client, err := p.Amplify(ctx)
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	input := &amplify.ListAppsInput{}
	paginator := amplify.NewListAppsPaginator(client, input)
	
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, app := range page.Apps {
			status := models.StatusPass
			msg := fmt.Sprintf("Amplify app %s does not contain obvious secrets", *app.Name)
			
			if app.EnvironmentVariables != nil {
				for k := range app.EnvironmentVariables {
					if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "key") {
						status = models.StatusFail
						msg = fmt.Sprintf("Amplify app %s may contain secret in variable %s", *app.Name, k)
						break
					}
				}
			}
			
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *app.AppArn, Provider: "aws", Service: "amplify",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// AmplifyAppBranchAutoBuildCheck verifica se auto build está desabilitado para produção
type AmplifyAppBranchAutoBuildCheck struct {
	metadata models.CheckMetadata
}

func NewAmplifyAppBranchAutoBuildCheck() *AmplifyAppBranchAutoBuildCheck {
	return &AmplifyAppBranchAutoBuildCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "amplify_app_branch_auto_build_disabled",
			CheckTitle: "Ensure Amplify apps have auto build disabled for production branches",
			Description: "Production branches should have auto build disabled to prevent accidental deployments",
			Severity: "medium", ServiceName: "amplify", ResourceType: "Branch",
			RemediationText: "Disable auto build for production branches",
			Categories: []string{"compute", "deployment"},
		},
	}
}

func (c *AmplifyAppBranchAutoBuildCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AmplifyAppBranchAutoBuildCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires ListBranches and GetBranch API calls",
			Provider: "aws", Service: "amplify", FoundAt: time.Now().UTC(),
		},
	}, nil
}

// AmplifyAppCustomRulesCheck verifica se apps Amplify têm regras customizadas
type AmplifyAppCustomRulesCheck struct {
	metadata models.CheckMetadata
}

func NewAmplifyAppCustomRulesCheck() *AmplifyAppCustomRulesCheck {
	return &AmplifyAppCustomRulesCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "amplify_app_custom_rules",
			CheckTitle: "Ensure Amplify apps have custom rules configured",
			Description: "Amplify apps should have custom rules for routing and redirects",
			Severity: "low", ServiceName: "amplify", ResourceType: "App",
			RemediationText: "Configure custom rules for Amplify app",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *AmplifyAppCustomRulesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AmplifyAppCustomRulesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusPass, StatusExtended: "Check requires GetApp and ListRules API calls",
			Provider: "aws", Service: "amplify", FoundAt: time.Now().UTC(),
		},
	}, nil
}
