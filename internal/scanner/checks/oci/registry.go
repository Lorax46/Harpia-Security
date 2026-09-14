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

// Registry contém todos os checks OCI implementados
var Registry = map[string][]executor.Check{
	"analytics": {
		analytics.NewInstanceAccessRestrictedCheck(),
	},
	"audit": {
		audit.NewLogRetentionCheck(),
	},
	"blockstorage": {
		blockstorage.NewBlockVolumeEncryptedWithCmkCheck(),
		blockstorage.NewBootVolumeEncryptedWithCmkCheck(),
	},
	"cloudguard": {
		cloudguard.NewCloudguardEnabledCheck(),
	},
	"compute": {
		compute.NewInstanceInTransitEncryptionCheck(),
	},
	"events": {
		events.NewNotificationTopicAndSubscriptionExistsCheck(),
		events.NewRuleCloudguardProblemsCheck(),
		events.NewRuleIamPolicyChangesCheck(),
		events.NewRuleIamGroupChangesCheck(),
		events.NewRuleUserChangesCheck(),
		events.NewRuleNetworkSecurityGroupChangesCheck(),
		events.NewRuleVcnChangesCheck(),
		events.NewRuleRouteTableChangesCheck(),
		events.NewRuleSecurityListChangesCheck(),
		events.NewRuleNetworkGatewayChangesCheck(),
		events.NewRuleIdentityProviderChangesCheck(),
		events.NewRuleIdpGroupMappingChangesCheck(),
		events.NewRuleLocalUserAuthenticationCheck(),
	},
	"identity": {
		identity.NewPasswordPolicyMinLength(),
		identity.NewMFACheck(),
		identity.NewUserAPIKeysRotated90Days(),
		identity.NewTenancyAdminUsersNoApiKeys(),
		identity.NewNoResourcesInRootCompartment(),
		identity.NewComputeInstanceLegacyMetadataEndpointDisabled(),
		identity.NewComputeInstanceSecureBootEnabled(),
		identity.NewIdentityIamAdminsCannotUpdateTenancyAdmins(),
		identity.NewIdentityInstancePrincipalUsed(),
		identity.NewIdentityNonRootCompartmentExists(),
		identity.NewIdentityPasswordPolicyExpiresWithin365Days(),
		identity.NewIdentityPasswordPolicyPreventsReuse(),
		identity.NewIdentityServiceLevelAdminsExist(),
		identity.NewIdentityStorageServiceLevelAdminsScoped(),
		identity.NewIdentityTenancyAdminPermissionsLimited(),
		identity.NewIdentityUserAuthTokensRotated90Days(),
		identity.NewIdentityUserCustomerSecretKeysRotated90Days(),
		identity.NewIdentityUserDbPasswordsRotated90Days(),
		identity.NewIdentityUserValidEmailAddress(),
	},
	"network": {
		network.NewDefaultSecurityListRestrictsTrafficCheck(),
		network.NewSecurityGroupIngressFromInternetToRdpPortCheck(),
		network.NewSecurityGroupIngressFromInternetToSshPortCheck(),
		network.NewSecurityListIngressFromInternetToRdpPortCheck(),
		network.NewSecurityListIngressFromInternetToSshPortCheck(),
		network.NewVcnSubnetFlowLogsEnabledCheck(),
	},
	"objectstorage": {
		objectstorage.NewBucketEncryptedWithCmkCheck(),
		objectstorage.NewBucketLoggingEnabledCheck(),
		objectstorage.NewBucketNotPubliclyAccessibleCheck(),
		objectstorage.NewBucketVersioningEnabledCheck(),
	},
	"database": {
		database.NewDatabaseAutonomousDatabaseAccessRestricted(),
	},
	"filestorage": {
		filestorage.NewFilestorageFileSystemEncryptedWithCmk(),
	},
	"integration": {
		integration.NewIntegrationInstanceAccessRestricted(),
	},
	"kms": {
		kms.NewKmsKeyRotationEnabled(),
	},
}
