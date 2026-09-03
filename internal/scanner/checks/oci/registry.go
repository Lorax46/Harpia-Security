package oci

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/analytics"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/audit"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/blockstorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/cloudguard"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/compute"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/database"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/events"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/filestorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/identity"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/integration"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/kms"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/network"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/objectstorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

// Registry contém todos os checks OCI disponíveis organizados por serviço
var Registry = map[string][]executor.Check{
	"analytics": {
		analytics.NewAnalyticsInstanceAccessRestricted(),
	},
	"audit": {
		audit.NewAuditLogRetentionPeriod365Days(),
	},
	"blockstorage": {
		blockstorage.NewBlockstorageBlockVolumeEncryptedWithCmk(),
		blockstorage.NewBlockstorageBootVolumeEncryptedWithCmk(),
	},
	"cloudguard": {
		cloudguard.NewCloudguardEnabled(),
	},
	"compute": {
		compute.NewComputeInstanceInTransitEncryptionEnabled(),
		compute.NewComputeInstanceLegacyMetadataEndpointDisabled(),
		compute.NewComputeInstanceSecureBootEnabled(),
	},
	"database": {
		database.NewDatabaseAutonomousDatabaseAccessRestricted(),
	},
	"events": {
		events.NewEventsNotificationTopicAndSubscriptionExists(),
		events.NewEventsRuleCloudguardProblems(),
		events.NewEventsRuleIamGroupChanges(),
		events.NewEventsRuleIamPolicyChanges(),
		events.NewEventsRuleIdentityProviderChanges(),
		events.NewEventsRuleIdpGroupMappingChanges(),
		events.NewEventsRuleLocalUserAuthentication(),
		events.NewEventsRuleNetworkGatewayChanges(),
		events.NewEventsRuleNetworkSecurityGroupChanges(),
		events.NewEventsRuleRouteTableChanges(),
		events.NewEventsRuleSecurityListChanges(),
		events.NewEventsRuleUserChanges(),
		events.NewEventsRuleVcnChanges(),
	},
	"filestorage": {
		filestorage.NewFilestorageFileSystemEncryptedWithCmk(),
	},
	"identity": {
		identity.NewIdentityIamAdminsCannotUpdateTenancyAdmins(),
		identity.NewIdentityInstancePrincipalUsed(),
		identity.NewIdentityNoResourcesInRootCompartment(),
		identity.NewIdentityNonRootCompartmentExists(),
		identity.NewIdentityPasswordPolicyExpiresWithin365Days(),
		identity.NewIdentityPasswordPolicyMinimumLength14(),
		identity.NewIdentityPasswordPolicyPreventsReuse(),
		identity.NewIdentityServiceLevelAdminsExist(),
		identity.NewIdentityStorageServiceLevelAdminsScoped(),
		identity.NewIdentityTenancyAdminPermissionsLimited(),
		identity.NewIdentityTenancyAdminUsersNoApiKeys(),
		identity.NewIdentityUserApiKeysRotated90Days(),
		identity.NewIdentityUserAuthTokensRotated90Days(),
		identity.NewIdentityUserCustomerSecretKeysRotated90Days(),
		identity.NewIdentityUserDbPasswordsRotated90Days(),
		identity.NewIdentityUserMfaEnabledConsoleAccess(),
		identity.NewIdentityUserValidEmailAddress(),
	},
	"integration": {
		integration.NewIntegrationInstanceAccessRestricted(),
	},
	"kms": {
		kms.NewKmsKeyRotationEnabled(),
	},
	"network": {
		network.NewNetworkDefaultSecurityListRestrictsTraffic(),
		network.NewNetworkSecurityGroupIngressFromInternetToRdpPort(),
		network.NewNetworkSecurityGroupIngressFromInternetToSshPort(),
		network.NewNetworkSecurityListIngressFromInternetToRdpPort(),
		network.NewNetworkSecurityListIngressFromInternetToSshPort(),
		network.NewNetworkVcnSubnetFlowLogsEnabled(),
	},
	"objectstorage": {
		objectstorage.NewObjectstorageBucketEncryptedWithCmk(),
		objectstorage.NewObjectstorageBucketLoggingEnabled(),
		objectstorage.NewObjectstorageBucketNotPubliclyAccessible(),
		objectstorage.NewObjectstorageBucketVersioningEnabled(),
	},
}
