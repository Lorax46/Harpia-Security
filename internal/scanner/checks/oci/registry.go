package oci

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/analytics"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/audit"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/blockstorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/cloudguard"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/compute"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/events"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci/identity"
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
}
