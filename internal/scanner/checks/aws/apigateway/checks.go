package apigateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type apigatewayProvider interface {
	APIGateway(ctx context.Context) (*apigateway.Client, error)
}

// ApigatewayRestapiWafAclAttached - API Gateway REST API has WAF ACL attached
type ApigatewayRestapiWafAclAttached struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiWafAclAttached() *ApigatewayRestapiWafAclAttached {
	return &ApigatewayRestapiWafAclAttached{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_waf_acl_attached",
			CheckTitle:   "API Gateway REST API has WAF ACL attached",
			ServiceName:  "apigateway",
			Severity:     "medium",
			ResourceType: "Stage",
			Description:  "API Gateway REST API stages should have WAF ACL attached for protection against common web exploits",
			RemediationText: "Attach a WAF ACL to your API Gateway stages",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiWafAclAttached) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiWafAclAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			status := models.StatusFail
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s does not have WAF ACL attached.", apiName, apiID, stageName)

			if stage.WebAclArn != nil && aws.ToString(stage.WebAclArn) != "" {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s has WAF ACL attached.", apiName, apiID, stageName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// ApigatewayRestapiPublicWithAuthorizer - Public API Gateway REST API has authorizer
type ApigatewayRestapiPublicWithAuthorizer struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiPublicWithAuthorizer() *ApigatewayRestapiPublicWithAuthorizer {
	return &ApigatewayRestapiPublicWithAuthorizer{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_public_with_authorizer",
			CheckTitle:   "Public API Gateway REST API has authorizer",
			ServiceName:  "apigateway",
			Severity:     "high",
			ResourceType: "RestApi",
			Description:  "Public API Gateway REST APIs should have an authorizer configured",
			RemediationText: "Configure an authorizer on your public API Gateway REST APIs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiPublicWithAuthorizer) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiPublicWithAuthorizer) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		// Check if API is public (endpoint type is not PRIVATE)
		if api.EndpointConfiguration != nil {
			isPublic := false
			for _, endpointType := range api.EndpointConfiguration.Types {
				if endpointType != "PRIVATE" {
					isPublic = true
					break
				}
			}
			if !isPublic {
				continue
			}
		}

		// Check for authorizers
		authorizers, err := apiClient.GetAuthorizers(ctx, &apigateway.GetAuthorizersInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		status := models.StatusFail
		statusExtended := fmt.Sprintf("API Gateway REST API %s with ID %s does not have an authorizer.", apiName, apiID)

		if len(authorizers.Items) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("API Gateway REST API %s with ID %s has a public endpoint with an authorizer.", apiName, apiID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "apigateway",
			ResourceID:     apiID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ApigatewayRestapiLoggingEnabled - API Gateway REST API stage has logging enabled
type ApigatewayRestapiLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiLoggingEnabled() *ApigatewayRestapiLoggingEnabled {
	return &ApigatewayRestapiLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_logging_enabled",
			CheckTitle:   "API Gateway REST API stage has logging enabled",
			ServiceName:  "apigateway",
			Severity:     "medium",
			ResourceType: "Stage",
			Description:  "API Gateway REST API stages should have logging enabled",
			RemediationText: "Enable logging on your API Gateway stages",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			status := models.StatusFail
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s does not have logging enabled.", apiName, apiID, stageName)

			if stage.MethodSettings != nil {
				for _, settings := range stage.MethodSettings {
					if settings.LoggingLevel != nil && aws.ToString(settings.LoggingLevel) != "OFF" {
						status = models.StatusPass
						statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s has logging enabled.", apiName, apiID, stageName)
						break
					}
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// ApigatewayRestapiAuthorizersEnabled - API Gateway REST API has authorizers enabled
type ApigatewayRestapiAuthorizersEnabled struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiAuthorizersEnabled() *ApigatewayRestapiAuthorizersEnabled {
	return &ApigatewayRestapiAuthorizersEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_authorizers_enabled",
			CheckTitle:   "API Gateway REST API has authorizers enabled",
			ServiceName:  "apigateway",
			Severity:     "medium",
			ResourceType: "RestApi",
			Description:  "API Gateway REST APIs should have authorizers enabled",
			RemediationText: "Enable authorizers on your API Gateway REST APIs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiAuthorizersEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiAuthorizersEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		authorizers, err := apiClient.GetAuthorizers(ctx, &apigateway.GetAuthorizersInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		status := models.StatusFail
		statusExtended := fmt.Sprintf("API Gateway REST API %s with ID %s does not have authorizers enabled.", apiName, apiID)

		if len(authorizers.Items) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("API Gateway REST API %s with ID %s has authorizers enabled.", apiName, apiID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "apigateway",
			ResourceID:     apiID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ApigatewayDomainNamePqcTlsEnabled - API Gateway domain name uses TLS 1.2+
type ApigatewayDomainNamePqcTlsEnabled struct {
	metadata models.CheckMetadata
}

func NewApigatewayDomainNamePqcTlsEnabled() *ApigatewayDomainNamePqcTlsEnabled {
	return &ApigatewayDomainNamePqcTlsEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_domain_name_pqc_tls_enabled",
			CheckTitle:   "API Gateway domain name uses TLS 1.2+",
			ServiceName:  "apigateway",
			Severity:     "low",
			ResourceType: "DomainName",
			Description:  "API Gateway domain names should use security policy with TLS 1.2 or higher",
			RemediationText: "Update your API Gateway domain name security policy to TLS_1_2 or higher",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayDomainNamePqcTlsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayDomainNamePqcTlsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	domainNames, err := apiClient.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get domain names: %w", err)
	}

	for _, dn := range domainNames.Items {
		domainName := aws.ToString(dn.DomainName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("API Gateway domain name %s uses security policy %s.", domainName, string(dn.SecurityPolicy))

		if dn.SecurityPolicy == types.SecurityPolicyTls12 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("API Gateway domain name %s uses secure security policy %s.", domainName, string(dn.SecurityPolicy))
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "apigateway",
			ResourceID:     domainName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ApigatewayRestapiClientCertificateEnabled - API Gateway REST API stage has client certificate enabled
type ApigatewayRestapiClientCertificateEnabled struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiClientCertificateEnabled() *ApigatewayRestapiClientCertificateEnabled {
	return &ApigatewayRestapiClientCertificateEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_client_certificate_enabled",
			CheckTitle:   "API Gateway REST API stage has client certificate enabled",
			ServiceName:  "apigateway",
			Severity:     "low",
			ResourceType: "Stage",
			Description:  "API Gateway REST API stages should have client certificate enabled for backend authentication",
			RemediationText: "Enable client certificate on your API Gateway stages for backend authentication",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiClientCertificateEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiClientCertificateEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			clientCertID := aws.ToString(stage.ClientCertificateId)

			status := models.StatusFail
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s does not have client certificate enabled.", apiName, apiID, stageName)

			if clientCertID != "" {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s has client certificate enabled.", apiName, apiID, stageName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// ApigatewayRestapiPublic - API Gateway REST API endpoint is not public
type ApigatewayRestapiPublic struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiPublic() *ApigatewayRestapiPublic {
	return &ApigatewayRestapiPublic{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_public",
			CheckTitle:   "API Gateway REST API endpoint is not public",
			ServiceName:  "apigateway",
			Severity:     "high",
			ResourceType: "RestApi",
			Description:  "API Gateway REST API endpoints should not be public unless required",
			RemediationText: "Change your API Gateway endpoint type to PRIVATE or REGIONAL",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		status := models.StatusPass
		statusExtended := fmt.Sprintf("API Gateway REST API %s with ID %s is not public.", apiName, apiID)

		if api.EndpointConfiguration != nil {
			for _, endpointType := range api.EndpointConfiguration.Types {
				if endpointType == "EDGE" {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("API Gateway REST API %s with ID %s is public (EDGE endpoint).", apiName, apiID)
					break
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "apigateway",
			ResourceID:     apiID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ApigatewayRestapiCacheEncrypted - API Gateway REST API stage has cache encryption enabled
type ApigatewayRestapiCacheEncrypted struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiCacheEncrypted() *ApigatewayRestapiCacheEncrypted {
	return &ApigatewayRestapiCacheEncrypted{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_cache_encrypted",
			CheckTitle:   "API Gateway REST API stage has cache encryption enabled",
			ServiceName:  "apigateway",
			Severity:     "low",
			ResourceType: "Stage",
			Description:  "API Gateway REST API stages should have cache encryption enabled",
			RemediationText: "Enable cache encryption on your API Gateway stages",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiCacheEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiCacheEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s has cache encryption enabled or cache is disabled.", apiName, apiID, stageName)

			// Cache encryption check: if cache cluster is enabled, it should be encrypted
			if stage.CacheClusterEnabled {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s has cache cluster enabled (encryption check unavailable in SDK).", apiName, apiID, stageName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// ApigatewayRestapiTracingEnabled - API Gateway REST API stage has X-Ray tracing enabled
type ApigatewayRestapiTracingEnabled struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiTracingEnabled() *ApigatewayRestapiTracingEnabled {
	return &ApigatewayRestapiTracingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_tracing_enabled",
			CheckTitle:   "API Gateway REST API stage has X-Ray tracing enabled",
			ServiceName:  "apigateway",
			Severity:     "low",
			ResourceType: "Stage",
			Description:  "API Gateway REST API stages should have X-Ray tracing enabled for debugging",
			RemediationText: "Enable X-Ray tracing on your API Gateway stages",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiTracingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiTracingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			status := models.StatusFail
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s does not have X-Ray tracing enabled.", apiName, apiID, stageName)

			if stage.TracingEnabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s has X-Ray tracing enabled.", apiName, apiID, stageName)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

// ApigatewayRestapiNoSecretsInStageVariables - API Gateway stage variables do not contain secrets
type ApigatewayRestapiNoSecretsInStageVariables struct {
	metadata models.CheckMetadata
}

func NewApigatewayRestapiNoSecretsInStageVariables() *ApigatewayRestapiNoSecretsInStageVariables {
	return &ApigatewayRestapiNoSecretsInStageVariables{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "apigateway_restapi_no_secrets_in_stage_variables",
			CheckTitle:   "API Gateway stage variables do not contain secrets",
			ServiceName:  "apigateway",
			Severity:     "high",
			ResourceType: "Stage",
			Description:  "API Gateway stage variables should not contain secrets",
			RemediationText: "Use AWS Secrets Manager or SSM Parameter Store for secrets instead of stage variables",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ApigatewayRestapiNoSecretsInStageVariables) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApigatewayRestapiNoSecretsInStageVariables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(apigatewayProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement apigatewayProvider")
	}
	apiClient, err := p.APIGateway(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	restAPIs, err := apiClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get REST APIs: %w", err)
	}

	for _, api := range restAPIs.Items {
		apiID := aws.ToString(api.Id)
		apiName := aws.ToString(api.Name)

		stages, err := apiClient.GetStages(ctx, &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			continue
		}

		for _, stage := range stages.Item {
			stageName := aws.ToString(stage.StageName)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("API Gateway %s ID %s in stage %s does not have secrets in stage variables.", apiName, apiID, stageName)

			// Check for suspicious variable names
			for key := range stage.Variables {
				if containsSensitivePattern(key) {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("API Gateway %s ID %s in stage %s may have secrets in stage variables: %s", apiName, apiID, stageName, key)
					break
				}
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "apigateway",
				ResourceID:     fmt.Sprintf("%s/%s", apiName, stageName),
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}

func containsSensitivePattern(s string) bool {
	patterns := []string{"password", "secret", "token", "key", "apikey", "api_key"}
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}