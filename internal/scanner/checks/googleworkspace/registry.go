package googleworkspace

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/additionalservices"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/calendar"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/chat"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/directory"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/drive"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/gmail"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/groups"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/marketplace"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/rules"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/security"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/googleworkspace/sites"
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

// Registry contains all Google Workspace security checks organized by service.
// Total: 87 checks across 11 services.
var Registry = map[string][]executor.Check{
	"security": {
		security.NewTwoSVEnforcedCheck(),
		security.NewTwoSVHardwareKeysAdminsCheck(),
		security.NewAdvancedProtectionConfiguredCheck(),
		security.NewAppAccessRestrictedCheck(),
		security.NewDLPDriveRulesConfiguredCheck(),
		security.NewInternalAppsTrustedCheck(),
		security.NewLessSecureAppsDisabledCheck(),
		security.NewLoginChallengesConfiguredCheck(),
		security.NewPasswordPolicyStrongCheck(),
		security.NewSessionDurationLimitedCheck(),
		security.NewSuperAdminRecoveryDisabledCheck(),
		security.NewUserRecoveryEnabledCheck(),
		security.NewTwoSVEnrollmentAllowedCheck(),
		security.NewTwoSVGracePeriodCheck(),
		security.NewPasswordPolicyMinLengthCheck(),
		security.NewPasswordPolicyMaxAgeCheck(),
		security.NewPasswordPolicyReuseCountCheck(),
		security.NewPasswordPolicyComplexityCheck(),
		security.NewSessionDurationWebCheck(),
		security.NewSessionDurationMobileCheck(),
		security.NewSessionDurationAPICheck(),
		security.NewSuperAdminMFAEnforcedCheck(),
		security.NewAdminMFAEnforcedCheck(),
		security.NewUserMFAEnforcedCheck(),
		security.NewDLPGmailRulesConfiguredCheck(),
		security.NewDLPChatRulesConfiguredCheck(),
		security.NewDLPRulesReviewersCheck(),
		security.NewDLPRulesNotificationsCheck(),
		security.NewDLPRulesIncidentsCheck(),
		security.NewDLPRulesAlertsCheck(),
		security.NewDLPRulesActionsCheck(),
		security.NewDLPRulesConditionsCheck(),
	},
	"gmail": {
		gmail.NewAnomalousAttachmentProtectionEnabledCheck(),
		gmail.NewAutoForwardingDisabledCheck(),
		gmail.NewComprehensiveMailStorageEnabledCheck(),
		gmail.NewDomainSpoofingProtectionEnabledCheck(),
		gmail.NewEmployeeNameSpoofingProtectionEnabledCheck(),
		gmail.NewEncryptedAttachmentProtectionEnabledCheck(),
		gmail.NewEnhancedPreDeliveryScanningEnabledCheck(),
		gmail.NewExternalImageScanningEnabledCheck(),
		gmail.NewGroupsSpoofingProtectionEnabledCheck(),
		gmail.NewInboundDomainSpoofingProtectionEnabledCheck(),
		gmail.NewMailDelegationDisabledCheck(),
		gmail.NewPerUserOutboundGatewayDisabledCheck(),
		gmail.NewPopImapAccessDisabledCheck(),
		gmail.NewScriptAttachmentProtectionEnabledCheck(),
		gmail.NewShortenerScanningEnabledCheck(),
		gmail.NewUnauthenticatedEmailProtectionEnabledCheck(),
		gmail.NewUntrustedLinkWarningsEnabledCheck(),
		gmail.NewWorkspaceEnabledCheck(),
	},
	"calendar": {
		calendar.NewExternalInvitationsWarningCheck(),
		calendar.NewExternalSharingPrimaryCalendarCheck(),
		calendar.NewExternalSharingSecondaryCalendarCheck(),
	},
	"chat": {
		chat.NewAppsInstallationDisabledCheck(),
		chat.NewExternalFileSharingDisabledCheck(),
		chat.NewExternalMessagingRestrictedCheck(),
		chat.NewExternalSpacesRestrictedCheck(),
		chat.NewIncomingWebhooksDisabledCheck(),
		chat.NewInternalFileSharingDisabledCheck(),
	},
	"drive": {
		drive.NewDriveSharedDriveMembersOnlyAccessCheck(),
		drive.NewDriveDesktopAccessDisabledCheck(),
		drive.NewDriveSharingAllowlistedDomainsCheck(),
		drive.NewDriveAccessCheckerRecipientsOnlyCheck(),
		drive.NewDriveWorkspaceEnabledCheck(),
		drive.NewDriveSharedDriveManagersCannotOverrideCheck(),
		drive.NewDriveExternalSharingWarnUsersCheck(),
		drive.NewDrivePublishingFilesDisabledCheck(),
		drive.NewDriveInternalUsersDistributeContentCheck(),
		drive.NewDriveSharedDriveDisableDownloadPrintCopyCheck(),
		drive.NewDriveSharedDriveCreationAllowedCheck(),
		drive.NewDriveWarnSharingWithAllowlistedDomainsCheck(),
	},
	"groups": {
		groups.NewGroupsCreationRestrictedCheck(),
		groups.NewGroupsExternalAccessRestrictedCheck(),
		groups.NewGroupsViewConversationsRestrictedCheck(),
	},
	"directory": {
		directory.NewDirectorySuperAdminCountCheck(),
		directory.NewDirectorySuperAdminOnlyAdminRolesCheck(),
	},
	"rules": {
		rules.NewRulesAdminPrivilegeGrantedAlertConfiguredCheck(),
		rules.NewRulesGmailEmployeeSpoofingAlertConfiguredCheck(),
		rules.NewRulesGovernmentBackedAttacksAlertConfiguredCheck(),
		rules.NewRulesLeakedPasswordAlertConfiguredCheck(),
		rules.NewRulesPasswordChangedAlertConfiguredCheck(),
		rules.NewRulesSuspiciousActivitySuspensionAlertConfiguredCheck(),
		rules.NewRulesSuspiciousLoginAlertConfiguredCheck(),
		rules.NewRulesSuspiciousProgrammaticLoginAlertConfiguredCheck(),
	},
	"marketplace": {
		marketplace.NewMarketplaceAppsAccessRestrictedCheck(),
	},
	"sites": {
		sites.NewSitesServiceDisabledCheck(),
	},
	"additionalservices": {
		additionalservices.NewAdditionalservicesExternalGroupsDisabledCheck(),
	},
}
