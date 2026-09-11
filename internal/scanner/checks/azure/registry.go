package azure

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/aks"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/app"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/appinsights"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/apim"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/aisearch"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/compute"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/containerregistry"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/cosmosdb"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/databricks"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/defender"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/entra"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/iam"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/keyvault"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/monitor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/mysql"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/network"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/policy"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/postgresql"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/recovery"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/sql"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/sqlserver"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/storage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/azure/webapp"
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

var Registry = map[string][]executor.Check{
	"compute": {
		compute.NewVMEncryptedAtRestCheck(),
		compute.NewVMPublicIPDisabledCheck(),
		compute.NewDiskEncryptedAtRestCheck(),
		compute.NewVMUsesManagedDisksCheck(),
		compute.NewVMBackupEnabled(),
		compute.NewVMApprovedImages(),
		compute.NewVMManagedDisks(),
		compute.NewVMLinuxSSHAuthentication(),
	},
	"network": {
		network.NewNSGSSHRestrictedCheck(),
		network.NewNSGRDPRestrictedCheck(),
		network.NewPublicIPSecuredCheck(),
		network.NewNetworkWatcherEnabled(),
		network.NewNetworkSecurityGroupFlowLogsEnabled(),
		network.NewNetworkSecurityGroupTrafficAnalyticsEnabled(),
		network.NewNetworkWatcherTrafficAnalyticsEnabled(),
		network.NewNetworkSecurityGroupDefaultRulesDoNotAllowAllTraffic(),
		network.NewNetworkSecurityGroupRulesDoNotAllowInternetAccess(),
		network.NewNetworkVirtualNetworkGatewaySkuSupportsIpsec(),
		network.NewNetworkAzureFirewallEnabled(),
		network.NewNetworkBastionHostEnabled(),
	},
	"storage": {
		storage.NewStorageAccountAzureServicesAccessEnabled(),
		storage.NewStorageAccountDefaultNetworkAccessDeny(),
		storage.NewStorageAccountEncryptionAtRest(),
		storage.NewStorageAccountInfrastructureEncryptionEnabled(),
		storage.NewStorageAccountLoggingEnabled(),
		storage.NewStorageAccountMinimumTlsVersion(),
		storage.NewStorageAccountPublicAccessDisabled(),
		storage.NewStorageAccountReadOnlyKeysNotExposed(),
		storage.NewStorageAccountRequiresSecureTransfer(),
		storage.NewStorageAccountSoftDeleteEnabled(),
		storage.NewStorageAccountVersioningEnabled(),
		storage.NewStorageAccountNetworkAccessRestricted(),
		storage.NewStorageAccountLocation(),
		storage.NewStorageAccountPrivateEndpoint(),
		storage.NewStorageAccountSharedAccessSignature(),
		storage.NewStorageAccountSharedKeyAccessDisabled(),
		storage.NewStorageAccountStorageContainerPublicAccessDisabled(),
		storage.NewStorageAccountTrustedMicrosoftServicesEnabled(),
		storage.NewStorageAccountAzurePolicyForbidsPublicAccess(),
	},
	"sql": {
		sql.NewSQLAuditingEnabledCheck(),
		sql.NewSQLEncryptedAtRestCheck(),
	},
	"sqlserver": {
		sqlserver.NewSQLAuditingEnabledCheck(),
		sqlserver.NewSQLEncryptedAtRestCheck(),
		sqlserver.NewSQLServerAdvancedThreatProtectionEnabled(),
		sqlserver.NewSQLServerAuditingRetentionDays(),
		sqlserver.NewSQLServerEmailAlertsEnabled(),
		sqlserver.NewSQLServerEmailAlertsToAdminsEnabled(),
		sqlserver.NewSQLServerNoPublicAccess(),
		sqlserver.NewSQLServerTransparentDataEncryptionEnabled(),
		sqlserver.NewSQLServerAzureADAdminEnabled(),
		sqlserver.NewSQLServerAzureADOnlyAuthentication(),
		sqlserver.NewSQLServerFirewallRules(),
		sqlserver.NewSQLServerMinimumTlsVersion(),
	},
	"postgresql": {
		postgresql.NewPostgreSqlServerConnectionThrottlingEnabled(),
		postgresql.NewPostgreSqlServerLogCheckpointsEnabled(),
		postgresql.NewPostgreSqlServerLogConnectionsEnabled(),
		postgresql.NewPostgreSqlServerLogDisconnectionsEnabled(),
		postgresql.NewPostgreSqlServerLogDurationEnabled(),
		postgresql.NewPostgreSqlServerNoPublicAccess(),
		postgresql.NewPostgreSqlServerPrivateEndpointsEnabled(),
		postgresql.NewPostgreSqlServerSslEnforcementEnabled(),
		postgresql.NewPostgreSqlServerStorageAutoGrowEnabled(),
		postgresql.NewPostgreSqlServerThreatDetectionEnabled(),
	},
	"keyvault": {
		keyvault.NewPurgeProtectionCheck(),
		keyvault.NewSoftDeleteCheck(),
		keyvault.NewRBACAuthorizationCheck(),
		keyvault.NewKeyvaultLoggingEnabled(),
		keyvault.NewKeyvaultPublicAccessDisabled(),
		keyvault.NewKeyvaultFirewallEnabled(),
		keyvault.NewKeyvaultPrivateEndpointEnabled(),
		keyvault.NewKeyvaultKeyRotationEnabled(),
		keyvault.NewKeyvaultSecretExpirationDate(),
		keyvault.NewKeyvaultKeyExpirationDate(),
	},
	"monitor": {
		monitor.NewMonitorDiagnosticSettings(),
		monitor.NewMonitorActivityLogAlerts(),
		monitor.NewMonitorLogAnalyticsAgentEnabled(),
		monitor.NewMonitorLogRetentionDays(),
		monitor.NewMonitorMetricAlertsEnabled(),
		monitor.NewMonitorApplicationInsightsEnabled(),
		monitor.NewMonitorWorkspaceEncryption(),
		monitor.NewMonitorAzureMonitorAlerts(),
		monitor.NewMonitorDiagnosticLoggingEnabled(),
		monitor.NewMonitorLogProfileArchive(),
		monitor.NewMonitorLogProfileCategories(),
		monitor.NewMonitorLogProfileRetention(),
		monitor.NewMonitorLogProfileRegions(),
		monitor.NewMonitorVMHealthAlertsEnabled(),
	},
	"webapp": {
		webapp.NewHTTPSOnlyCheck(),
		webapp.NewMinimumTLSVersionCheck(),
		webapp.NewFTPDisabledCheck(),
	},
	"defender": {
		defender.NewDefenderAutoProvisioningLogAnalyticsAgentVmsOn(),
		defender.NewDefenderAutoProvisioningVulnerabilityAssessmentsMachinesOn(),
		defender.NewDefenderAdditionalEmailConfiguredWithASecurityContact(),
		defender.NewDefenderAssessmentsVmEndpointProtectionInstalled(),
		defender.NewDefenderAttackPathNotificationsProperlyConfigured(),
		defender.NewDefenderAutoProvisioningAgentOn(),
		defender.NewDefenderAutoProvisioningVulnerabilityAssessmentsVmsOn(),
		defender.NewDefenderContainerRegistryScanRecommendationsEnabled(),
		defender.NewDefenderContainerScanEnabled(),
		defender.NewDefenderCspmAksEnabled(),
		defender.NewDefenderCspmAppServicesEnabled(),
		defender.NewDefenderCspmEnabled(),
		defender.NewDefenderCspmSqlEnabled(),
		defender.NewDefenderCspmSqlOnVmEnabled(),
		defender.NewDefenderCspmStorageAccountsEnabled(),
		defender.NewDefenderCspmVirtualMachinesEnabled(),
		defender.NewDefenderDefenderForStorageEnabled(),
		defender.NewDefenderEnableRegularContactDetails(),
		defender.NewDefenderEmailNotificationsEnabled(),
		defender.NewDefenderHighSeverityAlertsEnabled(),
		defender.NewDefenderMonitorSystemUpdates(),
		defender.NewDefenderSecurityConfigurationMonitoringEnabled(),
		defender.NewDefenderVulnerabilityAssessmentEnabled(),
	},
	"app": {
		app.NewAppClientCertificatesOn(),
		app.NewAppEnsureAuthIsSetUp(),
		app.NewAppEnsureHttpIsRedirectedToHttps(),
		app.NewAppEnsureJavaVersionIsLatest(),
		app.NewAppEnsurePhpVersionIsLatest(),
		app.NewAppEnsurePythonVersionIsLatest(),
		app.NewAppEnsureUsingHttp20(),
		app.NewAppFtpDeploymentDisabled(),
		app.NewAppFunctionAccessKeysConfigured(),
		app.NewAppFunctionApplicationInsightsEnabled(),
		app.NewAppFunctionEnsureHttpIsRedirectedToHttps(),
		app.NewAppFunctionFtpsDeploymentDisabled(),
		app.NewAppFunctionIdentityIsConfigured(),
		app.NewAppFunctionIdentityWithoutAdminPrivileges(),
		app.NewAppFunctionLatestRuntimeVersion(),
		app.NewAppFunctionNotPubliclyAccessible(),
		app.NewAppFunctionVnetIntegrationEnabled(),
		app.NewAppHttpLogsEnabled(),
		app.NewAppMinimumTlsVersion12(),
		app.NewAppRegisterWithIdentity(),
	},
	"entra": {
		entra.NewEntraAdminMfaEnabled(),
		entra.NewEntraAdminSecuredMFA(),
		entra.NewEntraAnonymousUsersNotOwner(),
		entra.NewEntraAppAdminConsent(),
		entra.NewEntraAppApiPermissions(),
		entra.NewEntraAppAuthenticationBehaviors(),
		entra.NewEntraAppConsentRequests(),
		entra.NewEntraAppDefaultRedirectUri(),
		entra.NewEntraAppIdentifierUri(),
		entra.NewEntraAppNoNativeAppRegistration(),
		entra.NewEntraAppOwnerAssignedPermission(),
		entra.NewEntraAppPasswordCredentialRotation(),
		entra.NewEntraAppPublicClientNoSpa(),
		entra.NewEntraAppRequiredResourceAccess(),
		entra.NewEntraAppRoleAssignments(),
		entra.NewEntraConditionalAccessAppRegistrationPolicy(),
		entra.NewEntraConditionalAccessMfa(),
		entra.NewEntraConditionalAccessPolicy(),
		entra.NewEntraDefaultUserRolePermissions(),
	},
	"aks": {
		aks.NewAksClusterAutoUpgradeEnabled(),
		aks.NewAksClusterAzureMonitorEnabled(),
		aks.NewAksClusterDefenderEnabled(),
		aks.NewAksClusterLocalAccountsDisabled(),
		aks.NewAksClusterRbacEnabled(),
		aks.NewAksClustersCreatedWithPrivateNodes(),
		aks.NewAksClustersPublicAccessDisabled(),
		aks.NewAksNetworkPolicyEnabled(),
	},
	"cosmosdb": {
		cosmosdb.NewCosmosdbAccountAutomaticFailoverEnabled(),
		cosmosdb.NewCosmosdbAccountBackupPolicyContinuous(),
		cosmosdb.NewCosmosdbAccountFirewallUseSelectedNetworks(),
		cosmosdb.NewCosmosdbAccountMinimumTlsVersion(),
		cosmosdb.NewCosmosdbAccountPublicNetworkAccessDisabled(),
		cosmosdb.NewCosmosdbAccountUseAadAndRbac(),
		cosmosdb.NewCosmosdbAccountUsePrivateEndpoints(),
	},
	"mysql": {
		mysql.NewMysqlServerSslEnforcementEnabled(),
		mysql.NewMysqlServerStorageAutoGrowEnabled(),
		mysql.NewMysqlServerThreatDetectionEnabled(),
		mysql.NewMysqlServerConnectionThrottlingEnabled(),
		mysql.NewMysqlServerLogCheckpointsEnabled(),
		mysql.NewMysqlServerLogConnectionsEnabled(),
	},
	"databricks": {
		databricks.NewDatabricksWorkspaceCmkEncryptionEnabled(),
		databricks.NewDatabricksWorkspaceNoPublicIpEnabled(),
		databricks.NewDatabricksWorkspacePublicNetworkAccessDisabled(),
		databricks.NewDatabricksWorkspaceVnetInjectionEnabled(),
	},
	"containerregistry": {
		containerregistry.NewContainerregistryAdminUserDisabled(),
		containerregistry.NewContainerregistryNotPubliclyAccessible(),
		containerregistry.NewContainerregistryUsesPrivateLink(),
	},
	"recovery": {
		recovery.NewRecoveryVaultEncrypted(),
		recovery.NewRecoveryVaultSoftDeleteEnabled(),
	},
	"iam": {
		iam.NewIamCustomRoleDefinition(),
		iam.NewIamRoleAssignmentNotification(),
		iam.NewIamUserWithOwnerPermissions(),
	},
	"policy": {
		policy.NewPolicyAssignmentExists(),
	},
	"appinsights": {
		appinsights.NewAppinsightsEnsureIsConfigured(),
	},
	"apim": {
		apim.NewApimThreatDetectionLlmJacking(),
	},
	"aisearch": {
		aisearch.NewAisearchServiceNotPubliclyAccessible(),
	},
}
