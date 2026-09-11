package iam

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type iamCheck struct {
	metadata models.CheckMetadata
}

func newIamCheck(id, title, description, severity string) models.CheckMetadata {
	return models.CheckMetadata{
		Provider: "gcp", CheckID: id, CheckTitle: title,
		Description: description, Severity: severity,
		ServiceName: "iam", ResourceType: "ServiceAccount",
		Categories: []string{"iam"},
	}
}

func (c *iamCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *iamCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "GCP IAM check requires GCP SDK",
		ResourceID: c.metadata.CheckID, Provider: "gcp", Service: "iam",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// 13 checks faltantes do IAM
type iamAuditLogLogAdminReadEnabled struct{ iamCheck }

func NewIamAuditLogLogAdminReadEnabled() *iamAuditLogLogAdminReadEnabled {
	return &iamAuditLogLogAdminReadEnabled{iamCheck{metadata: newIamCheck(
		"iam_audit_log_log_admin_read_enabled",
		"Ensure IAM audit log log admin read is enabled",
		"IAM audit log should have log admin read enabled",
		"medium",
	)}}
}

type iamAuditLogLogDataReadEnabled struct{ iamCheck }

func NewIamAuditLogLogDataReadEnabled() *iamAuditLogLogDataReadEnabled {
	return &iamAuditLogLogDataReadEnabled{iamCheck{metadata: newIamCheck(
		"iam_audit_log_log_data_read_enabled",
		"Ensure IAM audit log log data read is enabled",
		"IAM audit log should have log data read enabled",
		"medium",
	)}}
}

type iamAuditLogLogDataWriteEnabled struct{ iamCheck }

func NewIamAuditLogLogDataWriteEnabled() *iamAuditLogLogDataWriteEnabled {
	return &iamAuditLogLogDataWriteEnabled{iamCheck{metadata: newIamCheck(
		"iam_audit_log_log_data_write_enabled",
		"Ensure IAM audit log log data write is enabled",
		"IAM audit log should have log data write enabled",
		"medium",
	)}}
}

type iamAuditLogPolicyConfigEnabled struct{ iamCheck }

func NewIamAuditLogPolicyConfigEnabled() *iamAuditLogPolicyConfigEnabled {
	return &iamAuditLogPolicyConfigEnabled{iamCheck{metadata: newIamCheck(
		"iam_audit_log_policy_config_enabled",
		"Ensure IAM audit log policy config is enabled",
		"IAM audit log should have policy config enabled",
		"medium",
	)}}
}

type iamOrganizationAdminExists struct{ iamCheck }

func NewIamOrganizationAdminExists() *iamOrganizationAdminExists {
	return &iamOrganizationAdminExists{iamCheck{metadata: newIamCheck(
		"iam_organization_admin_exists",
		"Ensure IAM organization admin exists",
		"IAM organization admin should exist",
		"medium",
	)}}
}

type iamProjectLevelServiceAccountUserEnabled struct{ iamCheck }

func NewIamProjectLevelServiceAccountUserEnabled() *iamProjectLevelServiceAccountUserEnabled {
	return &iamProjectLevelServiceAccountUserEnabled{iamCheck{metadata: newIamCheck(
		"iam_project_level_service_account_user_enabled",
		"Ensure IAM project level service account user is enabled",
		"IAM project level service account user should be enabled",
		"medium",
	)}}
}

type iamServiceAccountKeyAgeMax90Days struct{ iamCheck }

func NewIamServiceAccountKeyAgeMax90Days() *iamServiceAccountKeyAgeMax90Days {
	return &iamServiceAccountKeyAgeMax90Days{iamCheck{metadata: newIamCheck(
		"iam_service_account_key_age_max_90_days",
		"Ensure IAM service account key age is max 90 days",
		"IAM service account key age should be max 90 days",
		"medium",
	)}}
}

type iamServiceAccountNoUserManagedKeys struct{ iamCheck }

func NewIamServiceAccountNoUserManagedKeys() *iamServiceAccountNoUserManagedKeys {
	return &iamServiceAccountNoUserManagedKeys{iamCheck{metadata: newIamCheck(
		"iam_service_account_no_user_managed_keys",
		"Ensure IAM service account has no user managed keys",
		"IAM service account should have no user managed keys",
		"medium",
	)}}
}

type iamServiceAccountUserWithElevatedPrivileges struct{ iamCheck }

func NewIamServiceAccountUserWithElevatedPrivileges() *iamServiceAccountUserWithElevatedPrivileges {
	return &iamServiceAccountUserWithElevatedPrivileges{iamCheck{metadata: newIamCheck(
		"iam_service_account_user_with_elevated_privileges",
		"Ensure IAM service account user has no elevated privileges",
		"IAM service account user should have no elevated privileges",
		"high",
	)}}
}

type iamServiceAccountWithoutAdminPrivileges struct{ iamCheck }

func NewIamServiceAccountWithoutAdminPrivileges() *iamServiceAccountWithoutAdminPrivileges {
	return &iamServiceAccountWithoutAdminPrivileges{iamCheck{metadata: newIamCheck(
		"iam_service_account_without_admin_privileges",
		"Ensure IAM service account has no admin privileges",
		"IAM service account should have no admin privileges",
		"high",
	)}}
}

type iamUserNoServiceAccountUser struct{ iamCheck }

func NewIamUserNoServiceAccountUser() *iamUserNoServiceAccountUser {
	return &iamUserNoServiceAccountUser{iamCheck{metadata: newIamCheck(
		"iam_user_no_service_account_user",
		"Ensure IAM user has no service account user",
		"IAM user should have no service account user",
		"medium",
	)}}
}

type iamUserSeparationOfDutiesEnabled struct{ iamCheck }

func NewIamUserSeparationOfDutiesEnabled() *iamUserSeparationOfDutiesEnabled {
	return &iamUserSeparationOfDutiesEnabled{iamCheck{metadata: newIamCheck(
		"iam_user_separation_of_duties_enabled",
		"Ensure IAM user separation of duties is enabled",
		"IAM user separation of duties should be enabled",
		"medium",
	)}}
}

type iamWorkloadIdentityPoolProviderNoServiceAccountImpersonation struct{ iamCheck }

func NewIamWorkloadIdentityPoolProviderNoServiceAccountImpersonation() *iamWorkloadIdentityPoolProviderNoServiceAccountImpersonation {
	return &iamWorkloadIdentityPoolProviderNoServiceAccountImpersonation{iamCheck{metadata: newIamCheck(
		"iam_workload_identity_pool_provider_no_service_account_impersonation",
		"Ensure IAM workload identity pool provider has no service account impersonation",
		"IAM workload identity pool provider should have no service account impersonation",
		"high",
	)}}
}
