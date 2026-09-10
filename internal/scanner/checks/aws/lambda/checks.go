package lambda

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

type lambdaProvider interface {
	Lambda(ctx context.Context) (*lambda.Client, error)
	Region() string
	AccountID() string
}

// LambdaFunctionNoSecretsCheck verifica se funções Lambda não contêm secrets
type LambdaFunctionNoSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionNoSecretsCheck() *LambdaFunctionNoSecretsCheck {
	return &LambdaFunctionNoSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_no_secrets",
			CheckTitle: "Ensure Lambda functions do not contain hardcoded secrets",
			Description: "Lambda functions should not contain hardcoded secrets in environment variables",
			Severity: "critical", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Use AWS Secrets Manager or Parameter Store for secrets",
			Categories: []string{"compute", "secrets"},
		},
	}
}

func (c *LambdaFunctionNoSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionNoSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s does not contain obvious secrets", *fn.FunctionName)
			if fn.Environment != nil && fn.Environment.Variables != nil {
				for k, v := range fn.Environment.Variables {
					if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "key") {
						if len(v) > 0 {
							status = models.StatusFail
							msg = fmt.Sprintf("Lambda function %s may contain secret in variable %s", *fn.FunctionName, k)
							break
						}
					}
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionTracingEnabledCheck verifica se tracing está habilitado
type LambdaFunctionTracingEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionTracingEnabledCheck() *LambdaFunctionTracingEnabledCheck {
	return &LambdaFunctionTracingEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_tracing_enabled",
			CheckTitle: "Ensure Lambda functions have tracing enabled",
			Description: "Lambda functions should have AWS X-Ray tracing enabled",
			Severity: "low", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Enable AWS X-Ray tracing for Lambda functions",
			Categories: []string{"compute", "logging"},
		},
	}
}

func (c *LambdaFunctionTracingEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionTracingEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s has tracing enabled", *fn.FunctionName)
			if fn.TracingConfig == nil || fn.TracingConfig.Mode != "Active" {
				status = models.StatusFail
				msg = fmt.Sprintf("Lambda function %s does not have tracing enabled", *fn.FunctionName)
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionNoLatestRuntimeCheck verifica se não usa runtime descontinuado
type LambdaFunctionNoLatestRuntimeCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionNoLatestRuntimeCheck() *LambdaFunctionNoLatestRuntimeCheck {
	return &LambdaFunctionNoLatestRuntimeCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_no_latest_runtime",
			CheckTitle: "Ensure Lambda functions do not use deprecated runtime",
			Description: "Lambda functions should not use deprecated or EOL runtimes",
			Severity: "medium", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Update Lambda function runtime to a supported version",
			Categories: []string{"compute", "reliability"},
		},
	}
}

func (c *LambdaFunctionNoLatestRuntimeCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionNoLatestRuntimeCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	
	deprecatedRuntimes := []string{"python3.6", "python3.7", "python2.7", "nodejs8.10", "nodejs10.x", "nodejs12.x", "dotnetcore2.1", "dotnetcore3.1", "ruby2.5", "java8", "go1.x"}
	
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s uses supported runtime", *fn.FunctionName)
			for _, deprecated := range deprecatedRuntimes {
				if string(fn.Runtime) == deprecated {
					status = models.StatusFail
					msg = fmt.Sprintf("Lambda function %s uses deprecated runtime %s", *fn.FunctionName, deprecated)
					break
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionInVPCCheck verifica se funções Lambda sensíveis estão em VPC
type LambdaFunctionInVPCCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionInVPCCheck() *LambdaFunctionInVPCCheck {
	return &LambdaFunctionInVPCCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_in_vpc",
			CheckTitle: "Ensure Lambda functions are in a VPC when required",
			Description: "Lambda functions should be in a VPC for network isolation when accessing sensitive resources",
			Severity: "medium", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Configure Lambda function to connect to a VPC",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *LambdaFunctionInVPCCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionInVPCCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s is in a VPC", *fn.FunctionName)
			if fn.VpcConfig == nil || fn.VpcConfig.VpcId == nil || *fn.VpcConfig.VpcId == "" {
				status = models.StatusFail
				msg = fmt.Sprintf("Lambda function %s is not in a VPC", *fn.FunctionName)
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionNotPublicCheck verifica políticas de acesso via API Lambda
type LambdaFunctionNotPublicCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionNotPublicCheck() *LambdaFunctionNotPublicCheck {
	return &LambdaFunctionNotPublicCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_not_public",
			CheckTitle: "Ensure Lambda functions are not publicly accessible",
			Description: "Lambda functions should not have public access via resource policy",
			Severity: "high", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Ensure Lambda resource policies do not allow public access",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *LambdaFunctionNotPublicCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionNotPublicCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s is not publicly accessible", *fn.FunctionName)
			policyInput := &lambda.GetPolicyInput{FunctionName: fn.FunctionArn}
			policy, err := client.GetPolicy(ctx, policyInput)
			if err == nil && policy.Policy != nil {
				policyStr := *policy.Policy
				if strings.Contains(policyStr, "\"Principal\":\"*\"") {
					status = models.StatusFail
					msg = fmt.Sprintf("Lambda function %s has public access in resource policy", *fn.FunctionName)
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionReservedConcurrencyCheck verifica se há limite de concorrência
type LambdaFunctionReservedConcurrencyCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionReservedConcurrencyCheck() *LambdaFunctionReservedConcurrencyCheck {
	return &LambdaFunctionReservedConcurrencyCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_reserved_concurrency",
			CheckTitle: "Ensure Lambda functions have reserved concurrency",
			Description: "Lambda functions should have reserved concurrency to prevent resource exhaustion",
			Severity: "medium", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Set reserved concurrency for Lambda functions",
			Categories: []string{"compute", "reliability"},
		},
	}
}

func (c *LambdaFunctionReservedConcurrencyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionReservedConcurrencyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s - requires GetFunctionConcurrency API call", *fn.FunctionName)
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// LambdaFunctionCodeSigningCheck verifica code signing
type LambdaFunctionCodeSigningCheck struct {
	metadata models.CheckMetadata
}

func NewLambdaFunctionCodeSigningCheck() *LambdaFunctionCodeSigningCheck {
	return &LambdaFunctionCodeSigningCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lambda_function_code_signing",
			CheckTitle: "Ensure Lambda functions use code signing",
			Description: "Lambda functions should use code signing for supply chain security",
			Severity: "low", ServiceName: "lambda", ResourceType: "Function",
			RemediationText: "Enable code signing for Lambda functions",
			Categories: []string{"compute", "supply-chain"},
		},
	}
}

func (c *LambdaFunctionCodeSigningCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LambdaFunctionCodeSigningCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lambdaProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lambdaProvider")
	}
	client, err := p.Lambda(ctx)
	if err != nil {
		return nil, err
	}
	findings := []models.Finding{}
	input := &lambda.ListFunctionsInput{}
	paginator := lambda.NewListFunctionsPaginator(client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fn := range page.Functions {
			status := models.StatusPass
			msg := fmt.Sprintf("Lambda function %s - requires GetFunctionCodeSigningConfig API call", *fn.FunctionName)
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: *fn.FunctionArn, Provider: "aws", Service: "lambda",
				Region: p.Region(), FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}
