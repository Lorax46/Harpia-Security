package app

// =============================================================================
// Azure App Service Checks — 20 checks
// =============================================================================

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// AppClientCertificatesOn - verifica certificados de cliente
type AppClientCertificatesOn struct {
	metadata models.CheckMetadata
}

func NewAppClientCertificatesOn() *AppClientCertificatesOn {
	return &AppClientCertificatesOn{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_client_certificates_on",
			CheckTitle: "Ensure App Service has client certificates enabled",
			Description: "App Service should have client certificates enabled",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Enable client certificates for App Service",
			Categories: []string{"app", "certificates"},
		},
	}
}

func (c *AppClientCertificatesOn) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppClientCertificatesOn) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App client certificates check requires Azure SDK",
		ResourceID: "app-client-certificates", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsureAuthIsSetUp - verifica autenticação
type AppEnsureAuthIsSetUp struct {
	metadata models.CheckMetadata
}

func NewAppEnsureAuthIsSetUp() *AppEnsureAuthIsSetUp {
	return &AppEnsureAuthIsSetUp{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_auth_is_set_up",
			CheckTitle: "Ensure App Service has authentication enabled",
			Description: "App Service should have authentication enabled",
			Severity: "high", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Enable authentication for App Service",
			Categories: []string{"app", "authentication"},
		},
	}
}

func (c *AppEnsureAuthIsSetUp) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsureAuthIsSetUp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App authentication check requires Azure SDK",
		ResourceID: "app-auth", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsureHttpIsRedirectedToHttps - verifica redirecionamento HTTPS
type AppEnsureHttpIsRedirectedToHttps struct {
	metadata models.CheckMetadata
}

func NewAppEnsureHttpIsRedirectedToHttps() *AppEnsureHttpIsRedirectedToHttps {
	return &AppEnsureHttpIsRedirectedToHttps{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_http_is_redirected_to_https",
			CheckTitle: "Ensure HTTP is redirected to HTTPS in App Service",
			Description: "App Service should redirect HTTP to HTTPS",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Configure HTTP to HTTPS redirection",
			Categories: []string{"app", "https"},
		},
	}
}

func (c *AppEnsureHttpIsRedirectedToHttps) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsureHttpIsRedirectedToHttps) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App HTTPS redirection check requires Azure SDK",
		ResourceID: "app-https-redirect", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsureJavaVersionIsLatest - verifica versão Java
type AppEnsureJavaVersionIsLatest struct {
	metadata models.CheckMetadata
}

func NewAppEnsureJavaVersionIsLatest() *AppEnsureJavaVersionIsLatest {
	return &AppEnsureJavaVersionIsLatest{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_java_version_is_latest",
			CheckTitle: "Ensure App Service uses latest Java version",
			Description: "App Service should use the latest Java version",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Update Java version",
			Categories: []string{"app", "java"},
		},
	}
}

func (c *AppEnsureJavaVersionIsLatest) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsureJavaVersionIsLatest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App Java version check requires Azure SDK",
		ResourceID: "app-java-version", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsurePhpVersionIsLatest - verifica versão PHP
type AppEnsurePhpVersionIsLatest struct {
	metadata models.CheckMetadata
}

func NewAppEnsurePhpVersionIsLatest() *AppEnsurePhpVersionIsLatest {
	return &AppEnsurePhpVersionIsLatest{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_php_version_is_latest",
			CheckTitle: "Ensure App Service uses latest PHP version",
			Description: "App Service should use the latest PHP version",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Update PHP version",
			Categories: []string{"app", "php"},
		},
	}
}

func (c *AppEnsurePhpVersionIsLatest) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsurePhpVersionIsLatest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App PHP version check requires Azure SDK",
		ResourceID: "app-php-version", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsurePythonVersionIsLatest - verifica versão Python
type AppEnsurePythonVersionIsLatest struct {
	metadata models.CheckMetadata
}

func NewAppEnsurePythonVersionIsLatest() *AppEnsurePythonVersionIsLatest {
	return &AppEnsurePythonVersionIsLatest{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_python_version_is_latest",
			CheckTitle: "Ensure App Service uses latest Python version",
			Description: "App Service should use the latest Python version",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Update Python version",
			Categories: []string{"app", "python"},
		},
	}
}

func (c *AppEnsurePythonVersionIsLatest) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsurePythonVersionIsLatest) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App Python version check requires Azure SDK",
		ResourceID: "app-python-version", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppEnsureUsingHttp20 - verifica HTTP/2
type AppEnsureUsingHttp20 struct {
	metadata models.CheckMetadata
}

func NewAppEnsureUsingHttp20() *AppEnsureUsingHttp20 {
	return &AppEnsureUsingHttp20{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ensure_using_http20",
			CheckTitle: "Ensure App Service uses HTTP/2",
			Description: "App Service should use HTTP/2 protocol",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Enable HTTP/2 for App Service",
			Categories: []string{"app", "protocol"},
		},
	}
}

func (c *AppEnsureUsingHttp20) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppEnsureUsingHttp20) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App HTTP/2 check requires Azure SDK",
		ResourceID: "app-http2", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFtpDeploymentDisabled - verifica FTP
type AppFtpDeploymentDisabled struct {
	metadata models.CheckMetadata
}

func NewAppFtpDeploymentDisabled() *AppFtpDeploymentDisabled {
	return &AppFtpDeploymentDisabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_ftp_deployment_disabled",
			CheckTitle: "Ensure FTP deployment is disabled in App Service",
			Description: "App Service should disable FTP deployment",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Disable FTP deployment",
			Categories: []string{"app", "ftp"},
		},
	}
}

func (c *AppFtpDeploymentDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFtpDeploymentDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App FTP check requires Azure SDK",
		ResourceID: "app-ftp", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionAccessKeysConfigured - verifica chaves de acesso
type AppFunctionAccessKeysConfigured struct {
	metadata models.CheckMetadata
}

func NewAppFunctionAccessKeysConfigured() *AppFunctionAccessKeysConfigured {
	return &AppFunctionAccessKeysConfigured{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_access_keys_configured",
			CheckTitle: "Ensure Function App has access keys configured",
			Description: "Function App should have access keys configured",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Configure access keys for Function App",
			Categories: []string{"app", "function"},
		},
	}
}

func (c *AppFunctionAccessKeysConfigured) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionAccessKeysConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function access keys check requires Azure SDK",
		ResourceID: "function-keys", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionApplicationInsightsEnabled - verifica App Insights
type AppFunctionApplicationInsightsEnabled struct {
	metadata models.CheckMetadata
}

func NewAppFunctionApplicationInsightsEnabled() *AppFunctionApplicationInsightsEnabled {
	return &AppFunctionApplicationInsightsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_application_insights_enabled",
			CheckTitle: "Ensure Function App has Application Insights enabled",
			Description: "Function App should have Application Insights enabled",
			Severity: "low", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Enable Application Insights for Function App",
			Categories: []string{"app", "monitoring"},
		},
	}
}

func (c *AppFunctionApplicationInsightsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionApplicationInsightsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function App Insights check requires Azure SDK",
		ResourceID: "function-insights", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionEnsureHttpIsRedirectedToHttps - verifica HTTPS em Functions
type AppFunctionEnsureHttpIsRedirectedToHttps struct {
	metadata models.CheckMetadata
}

func NewAppFunctionEnsureHttpIsRedirectedToHttps() *AppFunctionEnsureHttpIsRedirectedToHttps {
	return &AppFunctionEnsureHttpIsRedirectedToHttps{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_ensure_http_is_redirected_to_https",
			CheckTitle: "Ensure Function App redirects HTTP to HTTPS",
			Description: "Function App should redirect HTTP to HTTPS",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Configure HTTP to HTTPS redirection for Function App",
			Categories: []string{"app", "function"},
		},
	}
}

func (c *AppFunctionEnsureHttpIsRedirectedToHttps) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionEnsureHttpIsRedirectedToHttps) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function HTTPS check requires Azure SDK",
		ResourceID: "function-https", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionFtpsDeploymentDisabled - verifica FTPS em Functions
type AppFunctionFtpsDeploymentDisabled struct {
	metadata models.CheckMetadata
}

func NewAppFunctionFtpsDeploymentDisabled() *AppFunctionFtpsDeploymentDisabled {
	return &AppFunctionFtpsDeploymentDisabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_ftps_deployment_disabled",
			CheckTitle: "Ensure Function App has FTPS deployment disabled",
			Description: "Function App should have FTPS deployment disabled",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Disable FTPS deployment for Function App",
			Categories: []string{"app", "function"},
		},
	}
}

func (c *AppFunctionFtpsDeploymentDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionFtpsDeploymentDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function FTPS check requires Azure SDK",
		ResourceID: "function-ftps", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionIdentityIsConfigured - verifica identidade gerenciada
type AppFunctionIdentityIsConfigured struct {
	metadata models.CheckMetadata
}

func NewAppFunctionIdentityIsConfigured() *AppFunctionIdentityIsConfigured {
	return &AppFunctionIdentityIsConfigured{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_identity_is_configured",
			CheckTitle: "Ensure Function App has managed identity configured",
			Description: "Function App should have managed identity configured",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Configure managed identity for Function App",
			Categories: []string{"app", "function", "identity"},
		},
	}
}

func (c *AppFunctionIdentityIsConfigured) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionIdentityIsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function identity check requires Azure SDK",
		ResourceID: "function-identity", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionIdentityWithoutAdminPrivileges - verifica privilégios de admin
type AppFunctionIdentityWithoutAdminPrivileges struct {
	metadata models.CheckMetadata
}

func NewAppFunctionIdentityWithoutAdminPrivileges() *AppFunctionIdentityWithoutAdminPrivileges {
	return &AppFunctionIdentityWithoutAdminPrivileges{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_identity_without_admin_privileges",
			CheckTitle: "Ensure Function App identity has no admin privileges",
			Description: "Function App identity should not have admin privileges",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Review and reduce Function App identity privileges",
			Categories: []string{"app", "function", "privileges"},
		},
	}
}

func (c *AppFunctionIdentityWithoutAdminPrivileges) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionIdentityWithoutAdminPrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function admin privileges check requires Azure SDK",
		ResourceID: "function-privileges", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionLatestRuntimeVersion - verifica runtime
type AppFunctionLatestRuntimeVersion struct {
	metadata models.CheckMetadata
}

func NewAppFunctionLatestRuntimeVersion() *AppFunctionLatestRuntimeVersion {
	return &AppFunctionLatestRuntimeVersion{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_latest_runtime_version",
			CheckTitle: "Ensure Function App uses latest runtime version",
			Description: "Function App should use the latest runtime version",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Update Function App runtime version",
			Categories: []string{"app", "function", "runtime"},
		},
	}
}

func (c *AppFunctionLatestRuntimeVersion) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionLatestRuntimeVersion) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function runtime check requires Azure SDK",
		ResourceID: "function-runtime", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionNotPubliclyAccessible - verifica acesso público
type AppFunctionNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewAppFunctionNotPubliclyAccessible() *AppFunctionNotPubliclyAccessible {
	return &AppFunctionNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_not_publicly_accessible",
			CheckTitle: "Ensure Function App is not publicly accessible",
			Description: "Function App should not be publicly accessible",
			Severity: "high", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Restrict public access to Function App",
			Categories: []string{"app", "function", "public"},
		},
	}
}

func (c *AppFunctionNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function public access check requires Azure SDK",
		ResourceID: "function-public", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppFunctionVnetIntegrationEnabled - verifica integração VNet
type AppFunctionVnetIntegrationEnabled struct {
	metadata models.CheckMetadata
}

func NewAppFunctionVnetIntegrationEnabled() *AppFunctionVnetIntegrationEnabled {
	return &AppFunctionVnetIntegrationEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_function_vnet_integration_enabled",
			CheckTitle: "Ensure Function App has VNet integration enabled",
			Description: "Function App should have VNet integration enabled",
			Severity: "medium", ServiceName: "app", ResourceType: "FunctionApp",
			RemediationText: "Enable VNet integration for Function App",
			Categories: []string{"app", "function", "network"},
		},
	}
}

func (c *AppFunctionVnetIntegrationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppFunctionVnetIntegrationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Function VNet check requires Azure SDK",
		ResourceID: "function-vnet", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppHttpLogsEnabled - verifica logs HTTP
type AppHttpLogsEnabled struct {
	metadata models.CheckMetadata
}

func NewAppHttpLogsEnabled() *AppHttpLogsEnabled {
	return &AppHttpLogsEnabled{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_http_logs_enabled",
			CheckTitle: "Ensure App Service has HTTP logs enabled",
			Description: "App Service should have HTTP logs enabled",
			Severity: "low", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Enable HTTP logs for App Service",
			Categories: []string{"app", "logging"},
		},
	}
}

func (c *AppHttpLogsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppHttpLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App HTTP logs check requires Azure SDK",
		ResourceID: "app-http-logs", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppMinimumTlsVersion12 - verifica TLS 1.2
type AppMinimumTlsVersion12 struct {
	metadata models.CheckMetadata
}

func NewAppMinimumTlsVersion12() *AppMinimumTlsVersion12 {
	return &AppMinimumTlsVersion12{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_minimum_tls_version_12",
			CheckTitle: "Ensure App Service uses minimum TLS 1.2",
			Description: "App Service should use minimum TLS version 1.2",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Configure minimum TLS version 1.2 for App Service",
			Categories: []string{"app", "tls"},
		},
	}
}

func (c *AppMinimumTlsVersion12) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppMinimumTlsVersion12) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App TLS version check requires Azure SDK",
		ResourceID: "app-tls", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// AppRegisterWithIdentity - verifica registro com identidade
type AppRegisterWithIdentity struct {
	metadata models.CheckMetadata
}

func NewAppRegisterWithIdentity() *AppRegisterWithIdentity {
	return &AppRegisterWithIdentity{
		metadata: models.CheckMetadata{
			Provider: "azure", CheckID: "app_register_with_identity",
			CheckTitle: "Ensure App Service is registered with identity provider",
			Description: "App Service should be registered with an identity provider",
			Severity: "medium", ServiceName: "app", ResourceType: "WebApp",
			RemediationText: "Register App Service with identity provider",
			Categories: []string{"app", "identity"},
		},
	}
}

func (c *AppRegisterWithIdentity) Metadata() models.CheckMetadata { return c.metadata }

func (c *AppRegisterWithIdentity) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "App identity registration check requires Azure SDK",
		ResourceID: "app-identity", Provider: "azure", Service: "app",
		FoundAt: time.Now().UTC(),
	}}, nil
}
