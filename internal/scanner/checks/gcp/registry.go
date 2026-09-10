package gcp

import (
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/accesscontextmanager"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/artifactregistry"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/bigquery"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/bigtable"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/cloudbuild"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/cloudfunctions"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/cloudscheduler"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/cloudsql"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/cloudstorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/compute"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/container"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/dataproc"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/dns"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/filestorage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/gcr"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/iam"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/kms"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/logging"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/resourcemanager"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/spanner"
	"github.com/Lorax46/Harpia-Security/internal/scanner/checks/gcp/storage"
	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
)

// Registry contém todos os checks GCP implementados
var Registry = map[string][]executor.Check{
	"accesscontextmanager": {
		accesscontextmanager.NewAccessLevelCheck(),
		accesscontextmanager.NewAccessLevelCheck(),
		accesscontextmanager.NewServicePerimeterCheck(),
		accesscontextmanager.NewServicePerimeterCheck(),
		accesscontextmanager.NewGcpUserAccessCheck(),
	},
	"artifactregistry": {
		artifactregistry.NewRepositoryCheck(),
		artifactregistry.NewRepositoryIamCheck(),
		artifactregistry.NewRepositoryEncryptionCheck(),
		artifactregistry.NewRepositoryCheck(),
		artifactregistry.NewRepositoryIamCheck(),
	},
	"bigquery": {
		bigquery.NewDatasetPublicAccessCheck(),
		bigquery.NewDatasetCmekEncryptionCheck(),
		bigquery.NewDatasetLabelsCheck(),
		bigquery.NewTableCmekEncryptionCheck(),
		bigquery.NewDatasetIamPolicyCheck(),
	},
	"bigtable": {
		bigtable.NewInstanceCheck(),
		bigtable.NewInstanceIamCheck(),
		bigtable.NewInstanceLoggingCheck(),
		bigtable.NewInstanceCheck(),
		bigtable.NewInstanceBackupCheck(),
	},
	"cloudbuild": {
		cloudbuild.NewBuildCheck(),
		cloudbuild.NewBuildArtifactCheck(),
		cloudbuild.NewBuildLoggingCheck(),
		cloudbuild.NewBuildTriggerCheck(),
		cloudbuild.NewBuildIamCheck(),
	},
	"cloudfunctions": {
		cloudfunctions.NewCloudFunctionPublicAccessCheck(),
		cloudfunctions.NewCloudFunctionEncryptionCheck(),
		cloudfunctions.NewCloudFunctionLoggingCheck(),
		cloudfunctions.NewCloudFunctionVpcConnectorCheck(),
		cloudfunctions.NewCloudFunctionServiceAccountCheck(),
	},
	"cloudscheduler": {
		cloudscheduler.NewJobCheck(),
		cloudscheduler.NewJobRetryCheck(),
		cloudscheduler.NewJobLoggingCheck(),
		cloudscheduler.NewJobRetryCheck(),
		cloudscheduler.NewJobTargetCheck(),
	},
	"cloudsql": {
		cloudsql.NewCloudSQLInstanceAutomatedBackupsCheck(),
		cloudsql.NewCloudSQLInstanceCmekEncryptionCheck(),
		cloudsql.NewCloudSQLInstanceHighAvailabilityCheck(),
		cloudsql.NewCloudSQLInstanceMysqlLocalInfileFlagCheck(),
		cloudsql.NewCloudSQLInstanceMysqlSkipShowDatabaseFlagCheck(),
		cloudsql.NewCloudSQLInstanceNetworkEgressControlledCheck(),
		cloudsql.NewCloudSQLInstanceNoIPForwardingCheck(),
		cloudsql.NewCloudSQLInstanceNoPublicIPCheck(),
		cloudsql.NewCloudSQLInstancePasswordMinLengthFlagCheck(),
		cloudsql.NewCloudSQLInstancePasswordRequireComplexityFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresCheckPasswordFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresConnectionsLimitFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresDbRoleFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresEncryptedConnectionsFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogCheckpointsFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogConnectionsFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogDisconnectionsFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogDurationFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogLockWaitsFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogMinDurationStatementFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogMinErrorStatementFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresLogMinMessagesFlagCheck(),
		cloudsql.NewCloudSQLInstancePostgresStatementTimeoutFlagCheck(),
		cloudsql.NewCloudSQLInstanceSSLConnectionsRequiredCheck(),
	},
	"cloudstorage": {
		cloudstorage.NewBucketIamCheck(),
		cloudstorage.NewBucketLoggingCheck(),
		cloudstorage.NewBucketEncryptionCheck(),
		cloudstorage.NewBucketVersioningCheck(),
		cloudstorage.NewBucketEncryptionCheck(),
	},
	"compute": {
		compute.NewFirewallRdpAccessFromTheInternetAllowedCheck(),
		compute.NewFirewallSshAccessFromTheInternetAllowedCheck(),
		compute.NewInstanceNoPublicIpCheck(),
		compute.NewInstanceShieldedVmEnabledCheck(),
		compute.NewInstanceNoSerialPortsCheck(),
		compute.NewInstanceBlockProjectWideSshKeysDisabledCheck(),
		compute.NewProjectLevelOsLoginEnabledCheck(),
		compute.NewInstanceIpForwardingDisabledCheck(),
		compute.NewInstanceDiskEncryptionCmekCheck(),
		compute.NewInstanceDefaultServiceAccountDisabledCheck(),
		compute.NewInstanceConfidentialComputingEnabledCheck(),
		compute.NewInstanceDeletionProtectionEnabledCheck(),
		compute.NewInstanceDisplayDisabledCheck(),
		compute.NewSshKeysAtProjectLevelCheck(),
		compute.NewInstancePreemptibleDisabledCheck(),
		compute.NewInstanceAutomaticRestartEnabledCheck(),
		compute.NewInstanceStorageDiskNoDefaultEncryptionCheck(),
		compute.NewImageNotPubliclySharedCheck(),
		compute.NewNetworkGlobalRoutingModeCheck(),
		compute.NewNetworkNoDefaultSubnetsCheck(),
		compute.NewNetworkNoUnusedFirewallRulesCheck(),
		compute.NewNetworkNoUnusedRoutesCheck(),
		compute.NewNetworkNoVpcPeeringWithDefaultNetworkCheck(),
		compute.NewSubnetFlowLogsEnabledCheck(),
		compute.NewSubnetNoIpRangeConflictsCheck(),
		compute.NewSubnetNoUnusedIpRangesCheck(),
		compute.NewTargetHttpsProxySslPolicyNoWeakCheck(),
		compute.NewTargetHttpsProxySslPolicyTls12Check(),
		compute.NewTargetSslProxyNoWeakCipherCheck(),
		compute.NewProjectLevelSerialPortLoggingEnabledCheck(),
	},
	"container": {
		container.NewGKEClusterPrivateNodesCheck(),
		container.NewGKEClusterNetworkPolicyCheck(),
		container.NewGKEClusterPodSecurityPolicyCheck(),
		container.NewGKEClusterMasterAuthCheck(),
		container.NewGKEClusterLoggingCheck(),
	},
	"dataproc": {
		dataproc.NewDataprocClusterEncryptionCheck(),
		dataproc.NewDataprocClusterPublicAccessCheck(),
		dataproc.NewDataprocClusterLoggingCheck(),
		dataproc.NewDataprocClusterNetworkCheck(),
		dataproc.NewDataprocClusterAutoscalingCheck(),
	},
	"dns": {
		dns.NewDNSZonePublicAccessCheck(),
		dns.NewDNSZoneDnssecCheck(),
		dns.NewDNSZoneDsRecordCheck(),
		dns.NewDNSManagedZonePrivateCheck(),
		dns.NewDNSZoneLoggingCheck(),
	},
	"filestorage": {
		filestorage.NewInstanceNetworkCheck(),
		filestorage.NewInstanceEncryptedCheck(),
		filestorage.NewInstanceLoggingCheck(),
		filestorage.NewInstanceNetworkCheck(),
		filestorage.NewInstanceBackupCheck(),
	},
	"gcr": {
		gcr.NewRegistryLoggingCheck(),
		gcr.NewRegistryEncryptionCheck(),
		gcr.NewImageVulnerabilityScanCheck(),
		gcr.NewImageBuildCheck(),
		gcr.NewRegistryIamCheck(),
	},
	"iam": {
		iam.NewServiceAccountKeyRotationCheck(),
		iam.NewServiceAccountKeyRotationCheck(),
		iam.NewServiceAccountManagedKeyCheck(),
		iam.NewServiceAccountKeyRotationCheck(),
		iam.NewServiceAccountManagedKeyCheck(),
		iam.NewServiceAccountKeyRotationCheck(),
		iam.NewServiceAccountManagedKeyCheck(),
		iam.NewWorkloadIdentityCheck(),
		iam.NewServiceAccountKeyRotationCheck(),
		iam.NewServiceAccountManagedKeyCheck(),
		iam.NewWorkloadIdentityCheck(),
		iam.NewWorkloadIdentityCheck(),
	},
	"kms": {
		kms.NewKMSKeyNotPubliclyAccessibleCheck(),
		kms.NewKMSKeyRotationEnabledCheck(),
		kms.NewKMSKeyRotationMax90DaysCheck(),
	},
	"logging": {
		logging.NewLoggingLogMetricFilterAndAlertForAuditConfigurationChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForBucketPermissionChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForComputeConfigurationChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForCustomRoleChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForProjectOwnershipChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForSQLInstanceConfigurationChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForVpcFirewallRuleChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForVpcNetworkChangesCheck(),
		logging.NewLoggingLogMetricFilterAndAlertForVpcRouteChangesCheck(),
		logging.NewLoggingProjectLevelLogSinkEnabledCheck(),
	},
	"resourcemanager": {
		resourcemanager.NewProjectIamCheck(),
		resourcemanager.NewProjectLoggingCheck(),
		resourcemanager.NewProjectMonitoringCheck(),
		resourcemanager.NewProjectIamCheck(),
		resourcemanager.NewProjectLoggingCheck(),
	},
	"spanner": {
		spanner.NewSpannerInstanceEncryptionCheck(),
		spanner.NewSpannerInstancePublicAccessCheck(),
		spanner.NewSpannerInstanceLoggingCheck(),
		spanner.NewSpannerInstanceAutoscalingCheck(),
		spanner.NewSpannerDatabaseEncryptionCheck(),
	},
	"storage": {
		storage.NewBucketPublicAccessCheck(),
		storage.NewBucketEncryptionCheck(),
		storage.NewBucketVersioningCheck(),
		storage.NewBucketLoggingCheck(),
		storage.NewBucketUniformAccessCheck(),
	},
}