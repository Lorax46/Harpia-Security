package github

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/github/githubactions"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/github/organization"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/github/repository"
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

// Registry contains all GitHub checks organized by service
var Registry = map[string][]executor.Check{
	"repository": {
		// Main repository checks (21)
		repository.NewRepositoryDefaultBranchProtectionEnabledCheck(),
		repository.NewRepositoryDefaultBranchProtectionAppliesToAdminsCheck(),
		repository.NewRepositoryDefaultBranchRequiresSignedCommitsCheck(),
		repository.NewRepositoryDefaultBranchRequiresLinearHistoryCheck(),
		repository.NewRepositoryDefaultBranchDisallowsForcePushCheck(),
		repository.NewRepositoryDefaultBranchDeletionDisabledCheck(),
		repository.NewRepositoryDefaultBranchDismissesStaleReviewsCheck(),
		repository.NewRepositoryDefaultBranchRequiresConversationResolutionCheck(),
		repository.NewRepositoryDefaultBranchRequiresMultipleApprovalsCheck(),
		repository.NewRepositoryDefaultBranchRequiresCodeownersReviewCheck(),
		repository.NewRepositoryDefaultBranchStatusChecksRequiredCheck(),
		repository.NewRepositoryBranchDeleteOnMergeEnabledCheck(),
		repository.NewRepositorySecretScanningEnabledCheck(),
		repository.NewRepositoryDependencyScanningEnabledCheck(),
		repository.NewRepositoryHasCodeownersFileCheck(),
		repository.NewRepositoryPublicHasSecuritymdFileCheck(),
		repository.NewRepositoryDefaultWorkflowPermissionsReadOnlyCheck(),
		repository.NewRepositoryImmutableReleasesEnabledCheck(),
		repository.NewRepositoryInactiveNotArchivedCheck(),
		repository.NewRepositoryDefaultBranchRequiresPullRequestCheck(),
		repository.NewRepositorySecurityMdFileExistsCheck(),
		// Extra repository checks (8)
		repository.NewRepositoryPublicRepositoryHasNoSecretsInEnvironmentCheck(),
		repository.NewRepositoryTagsImmutableCheck(),
		repository.NewRepositorySigningRequiredCheck(),
		repository.NewRepositoryPushProtectionEnabledCheck(),
		repository.NewRepositoryCodeScanningDefaultConfigCheck(),
		repository.NewRepositorySecurityAndAnalysisEnabledCheck(),
		repository.NewRepositoryForkingDisabledCheck(),
		repository.NewRepositoryIssuesEnabledCheck(),
	},
	"organization": {
		organization.NewOrganizationMembersMfaRequiredCheck(),
		organization.NewOrganizationDefaultRepositoryPermissionStrictCheck(),
		organization.NewOrganizationDefaultWorkflowPermissionsReadOnlyCheck(),
		organization.NewOrganizationActionsPullRequestApprovalDisabledCheck(),
		organization.NewOrganizationRepositoryCreationLimitedCheck(),
		organization.NewOrganizationRepositoryDeletionLimitedCheck(),
		organization.NewOrganizationVerifiedBadgeCheck(),
		organization.NewOrganizationTwoFactorRequiredCheck(),
		organization.NewOrganizationAdministratorsWithoutExternalIdentityCheck(),
	},
	"githubactions": {
		githubactions.NewGithubactionsWorkflowSecurityScanCheck(),
		githubactions.NewGithubactionsActionsNotPublicCheck(),
		githubactions.NewGithubactionsOidcPermissionsBoundCheck(),
	},
}
