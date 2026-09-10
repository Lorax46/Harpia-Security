package aws

import (
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/executor"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/accessanalyzer"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/account"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/acm"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/acmpca"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/amplify"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/apigateway"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/apigatewayv2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/appstream"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/appsync"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/athena"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/autoscaling"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/awslambda"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/backup"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/batch"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/bedrock"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/cloudformation"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/cloudfront"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/cloudtrail"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/cloudwatch"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/codeartifact"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/codebuild"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/codecommit"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/codepipeline"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/cognito"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/config"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/datapipeline"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/datasync"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/directconnect"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/directoryservice"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/dlm"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/dms"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/documentdb"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/drs"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/dynamodb"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ec2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ecr"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ecs"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/efs"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/eks"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/elasticache"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/elasticbeanstalk"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/elb"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/elbv2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/emr"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/eventbridge"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/firehose"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/fms"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/fsx"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/glacier"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/glue"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/guardduty"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/iam"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/inspector2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/kafka"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/kinesis"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/kms"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/lambda"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/lightsail"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/macie"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/memorydb"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/mq"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/neptune"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/networkfirewall"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/opensearch"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/organizations"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/rds"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/redshift"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/resourceexplorer2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/rolesanywhere"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/route53"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/s3"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/sagemaker"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/secretsmanager"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/securityhub"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/servicecatalog"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ses"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/shield"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/sns"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/sqs"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ssm"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/ssmincidents"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/stepfunctions"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/storagegateway"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/sts"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/transfer"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/trustedadvisor"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/vpc"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/waf"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/wafv2"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/wellarchitected"
    "github.com/Lorax46/TOTVS-Horus/internal/scanner/checks/aws/workspaces"

)

// Registry contém todos os checks AWS implementados
var Registry = map[string][]executor.Check{
    "accessanalyzer": {
        accessanalyzer.NewAccessanalyzerEnabledWithoutFindings(),
        accessanalyzer.NewAccessanalyzerEnabled(),
    },
    "account": {
        account.NewAccountSecurityContactInformationIsRegistered(),
        account.NewAccountMaintainDifferentContactDetailsToSecurityBillingAndOperations(),
        account.NewAccountSecurityQuestionsAreRegisteredInTheAwsAccount(),
        account.NewAccountMaintainCurrentContactDetails(),
    },
    "acm": {
        acm.NewAcmCertificateExpirationCheck(),
        acm.NewAcmCertificateRenewal(),
        acm.NewAcmCertificateStatus(),
    },
    "acmpca": {
        acmpca.NewACMPCACertificateAuthorityKeyAlgorithmCheck(),
        acmpca.NewACMPCACertificateAuthorityRevocationCheck(),
    },
    "amplify": {
        amplify.NewAmplifyAppNoSecretsCheck(),
        amplify.NewAmplifyAppBranchAutoBuildCheck(),
        amplify.NewAmplifyAppCustomRulesCheck(),
    },
    "apigateway": {
        apigateway.NewApigatewayRestapiWafAclAttached(),
        apigateway.NewApigatewayRestapiPublicWithAuthorizer(),
        apigateway.NewApigatewayRestapiLoggingEnabled(),
        apigateway.NewApigatewayRestapiAuthorizersEnabled(),
        apigateway.NewApigatewayDomainNamePqcTlsEnabled(),
        apigateway.NewApigatewayRestapiClientCertificateEnabled(),
        apigateway.NewApigatewayRestapiPublic(),
        apigateway.NewApigatewayRestapiCacheEncrypted(),
        apigateway.NewApigatewayRestapiTracingEnabled(),
        apigateway.NewApigatewayRestapiNoSecretsInStageVariables(),
    },
    "apigatewayv2": {
        apigatewayv2.NewApigatewayv2ApiAccessLoggingEnabled(),
        apigatewayv2.NewApigatewayv2ApiAuthorizersEnabled(),
    },
    "appstream": {
        appstream.NewAppstreamFleetDefaultInternetAccessDisabled(),
        appstream.NewAppstreamFleetInternetAccess(),
        appstream.NewAppstreamFleetMaxSessionDuration(),
        appstream.NewAppstreamFleetUserSessionPolicies(),
    },
    "appsync": {
        appsync.NewAppsyncGraphqlApiLoggingEnabled(),
        appsync.NewAppsyncGraphqlApiAuth(),
    },
    "athena": {
        athena.NewAthenaWorkgroupEncryption(),
        athena.NewAthenaWorkgroupLoggingEnabled(),
        athena.NewAthenaWorkgroupResultEncryption(),
    },
    "autoscaling": {
        autoscaling.NewAutoscalingGroupHealthCheckEnabled(),
        autoscaling.NewAutoscalingGroupLaunchConfigurationAttached(),
        autoscaling.NewAutoscalingGroupMultipleAz(),
        autoscaling.NewAutoscalingGroupScalingNotifications(),
        autoscaling.NewAutoscalingGroupTagTracking(),
        autoscaling.NewAutoscalingGroupWithSuspendedProcesses(),
        autoscaling.NewAutoscalingLaunchConfigPublicIpDisabled(),
        autoscaling.NewAutoscalingLaunchConfigMetadataOptions(),
    },
    "awslambda": {
        awslambda.NewAwslambdaFunctionInsideVpc(),
        awslambda.NewAwslambdaFunctionNotPubliclyAccessible(),
        awslambda.NewAwslambdaFunctionUrlCorsPolicy(),
        awslambda.NewAwslambdaFunctionVpcMultiAz(),
        awslambda.NewAwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled(),
        awslambda.NewAwslambdaFunctionNoSecretsInCode(),
        awslambda.NewAwslambdaFunctionUsingSupportedRuntimes(),
        awslambda.NewAwslambdaFunctionUrlPublic(),
        awslambda.NewAwslambdaFunctionUsingCrossAccountLayers(),
        awslambda.NewAwslambdaLayerNoSecretsInContent(),
        awslambda.NewAwslambdaFunctionNoSecretsInVariables(),
        awslambda.NewAwslambdaFunctionEnvVarsNotEncryptedWithCmk(),
        awslambda.NewAwslambdaFunctionNoDeadLetterQueue(),
    },
    "backup": {
        backup.NewBackupPlansExist(),
        backup.NewBackupVaultsExist(),
        backup.NewBackupVaultsEncrypted(),
        backup.NewBackupReportplansExist(),
        backup.NewBackupRecoveryPointEncrypted(),
    },
    "batch": {
        batch.NewBatchJobDefinitionNoSecrets(),
    },
    "bedrock": {
        bedrock.NewBedrockApiKeyNoLongTermCredentials(),
        bedrock.NewBedrockAgentRoleLeastPrivilege(),
        bedrock.NewBedrockGuardrailSensitiveInformationFilterEnabled(),
        bedrock.NewBedrockGuardrailContextualGroundingFilterEnabled(),
        bedrock.NewBedrockModelInvocationLoggingEnabled(),
        bedrock.NewBedrockAgentGuardrailEnabled(),
        bedrock.NewBedrockModelInvocationLogsEncryptionEnabled(),
        bedrock.NewBedrockAgentRoleNotSharedAcrossAgents(),
        bedrock.NewBedrockPromptManagementExists(),
        bedrock.NewBedrockGuardrailPromptAttackFilterEnabled(),
        bedrock.NewBedrockFullAccessPolicyAttached(),
        bedrock.NewBedrockGuardrailsConfigured(),
        bedrock.NewBedrockPromptEncryptedWithCmk(),
        bedrock.NewBedrockCustomModelEncryptedWithCmk(),
        bedrock.NewBedrockKnowledgeBaseEncryptedWithCmk(),
        bedrock.NewBedrockVpcEndpointsConfigured(),
        bedrock.NewBedrockApiKeyNoAdministrativePrivileges(),
    },
    "cloudformation": {
        cloudformation.NewCloudformationStackEncryption(),
        cloudformation.NewCloudformationStackNotification(),
        cloudformation.NewCloudformationStackTerminationProtection(),
    },
    "cloudfront": {
        cloudfront.NewCloudfrontDistributionsGeoRestrictionsEnabled(),
        cloudfront.NewCloudfrontDistributionsHttpsEnabled(),
        cloudfront.NewCloudfrontDistributionsUsingDeprecatedSslProtocols(),
        cloudfront.NewCloudfrontDistributionsUsingWaf(),
        cloudfront.NewCloudfrontDistributionsCustomSslCertificate(),
        cloudfront.NewCloudfrontDistributionsDefaultRootObject(),
        cloudfront.NewCloudfrontDistributionsLoggingEnabled(),
        cloudfront.NewCloudfrontDistributionsPqcTlsEnabled(),
        cloudfront.NewCloudfrontDistributionsOriginTrafficEncrypted(),
        cloudfront.NewCloudfrontDistributionsMultipleOriginFailoverConfigured(),
        cloudfront.NewCloudfrontDistributionsFieldLevelEncryptionEnabled(),
        cloudfront.NewCloudfrontDistributionsS3OriginAccessControl(),
        cloudfront.NewCloudfrontDistributionsHttpsSniEnabled(),
        cloudfront.NewCloudfrontDistributionsS3OriginNonExistentBucket(),
    },
    "cloudtrail": {
        cloudtrail.NewLoggingCheck(),
        cloudtrail.NewMultiRegionCheck(),
        cloudtrail.NewLogFileValidationCheck(),
        cloudtrail.NewEncryptionCheck(),
        cloudtrail.NewCloudWatchLogsCheck(),
        cloudtrail.NewThreatDetectionPrivilegeEscalation(),
        cloudtrail.NewS3DataeventsReadEnabled(),
        cloudtrail.NewLogsS3BucketIsNotPubliclyAccessible(),
        cloudtrail.NewCloudwatchLoggingEnabled(),
        cloudtrail.NewInsightsExist(),
        cloudtrail.NewThreatDetectionLlmJacking(),
        cloudtrail.NewLogsS3BucketAccessLoggingEnabled(),
        cloudtrail.NewThreatDetectionEnumeration(),
        cloudtrail.NewLogFileValidationEnabled(),
        cloudtrail.NewBucketRequiresMfaDelete(),
        cloudtrail.NewS3DataeventsWriteEnabled(),
        cloudtrail.NewBedrockLoggingEnabled(),
        cloudtrail.NewMultiRegionEnabledLoggingManagementEvents(),
        cloudtrail.NewKmsEncryptionEnabled(),
        cloudtrail.NewMultiRegionEnabled(),
    },
    "cloudwatch": {
        cloudwatch.NewCloudwatchLogGroupKmsEncryptionEnabled(),
        cloudwatch.NewCloudwatchLogGroupRetentionPolicy(),
        cloudwatch.NewCloudwatchCrossAccountSharingDisabled(),
        cloudwatch.NewCloudwatchAlarmActionsEnabled(),
        cloudwatch.NewCloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled(),
    },
    "codeartifact": {
        codeartifact.NewCodeartifactPackagesExternalPublicPublishingDisabled(),
    },
    "codebuild": {
        codebuild.NewCodebuildProjectLoggingEnabled(),
        codebuild.NewCodebuildProjectNoSecretsInVariables(),
        codebuild.NewCodebuildProjectNotPubliclyAccessible(),
        codebuild.NewCodebuildProjectOlder90Days(),
        codebuild.NewCodebuildProjectS3LogsEncrypted(),
        codebuild.NewCodebuildProjectSourceRepoUrlNoSensitiveCredentials(),
        codebuild.NewCodebuildProjectUserControlledBuildspec(),
        codebuild.NewCodebuildProjectUsesAllowedGithubOrganizations(),
        codebuild.NewCodebuildProjectWebhookFiltersUseAnchoredPatterns(),
        codebuild.NewCodebuildReportGroupExportEncrypted(),
    },
    "codecommit": {
        codecommit.NewCodecommitRepositoryNoSecrets(),
    },
    "codepipeline": {
        codepipeline.NewCodepipelineProjectRepoPrivate(),
    },
    "cognito": {
        cognito.NewCognitoUserPoolPasswordPolicyMinLength14(),
        cognito.NewCognitoUserPoolMfaEnabled(),
        cognito.NewCognitoUserPoolAdvancedSecurityEnabled(),
        cognito.NewCognitoUserPoolDeletionProtection(),
    },
    "config": {
        config.NewConfigConfigurationRecorderEnabled(),
        config.NewConfigConfigurationRecorderAllResourceTypes(),
        config.NewConfigDeliveryChannelEnabled(),
    },
    "datapipeline": {
        datapipeline.NewDatapipelinePipelineNoSecretsInDefinition(),
    },
    "datasync": {
        datasync.NewDatasyncTaskLoggingEnabled(),
    },
    "directconnect": {
        directconnect.NewDirectconnectConnectionRedundancy(),
        directconnect.NewDirectconnectVirtualInterfaceRedundancy(),
    },
    "directoryservice": {
        directoryservice.NewDirectoryserviceDirectorySnapshotsLimit(),
        directoryservice.NewDirectoryserviceSupportedMfaRadiusEnabled(),
        directoryservice.NewDirectoryserviceRadiusServerSecurityProtocol(),
        directoryservice.NewDirectoryserviceDirectoryLogForwardingEnabled(),
        directoryservice.NewDirectoryserviceDirectoryMonitorNotifications(),
        directoryservice.NewDirectoryserviceLdapCertificateExpiration(),
    },
    "dlm": {
        dlm.NewDlmEbsSnapshotLifecyclePolicyExists(),
    },
    "dms": {
        dms.NewDmsEndpointSslEnabled(),
        dms.NewDmsEndpointNeptuneIamAuthorizationEnabled(),
        dms.NewDmsEndpointRedisInTransitEncryptionEnabled(),
        dms.NewDmsEndpointMongodbAuthenticationEnabled(),
        dms.NewDmsInstanceMinorVersionUpgradeEnabled(),
        dms.NewDmsInstanceMultiAzEnabled(),
        dms.NewDmsInstanceNoPublicAccess(),
        dms.NewDmsReplicationTaskSourceLoggingEnabled(),
        dms.NewDmsReplicationTaskTargetLoggingEnabled(),
    },
    "documentdb": {
        documentdb.NewDocdbClusterEncryptionAtRest(),
        documentdb.NewDocdbClusterLoggingEnabled(),
        documentdb.NewDocdbClusterPublicAccess(),
        documentdb.NewDocdbClusterRetentionPolicy(),
        documentdb.NewDocdbClusterSnapshotEncryption(),
        documentdb.NewDocdbClusterTlsEnabled(),
    },
    "drs": {
        drs.NewDrsJobExist(),
    },
    "dynamodb": {
        dynamodb.NewDynamodbTableAutoscalingEnabled(),
        dynamodb.NewDynamodbTablesKmsCmkEncryptionEnabled(),
        dynamodb.NewDynamodbTableDeletionProtectionEnabled(),
        dynamodb.NewDynamodbAcceleratorClusterInTransitEncryptionEnabled(),
        dynamodb.NewDynamodbTablesPitrEnabled(),
        dynamodb.NewDynamodbTableProtectedByBackupPlan(),
        dynamodb.NewDynamodbAcceleratorClusterEncryptionEnabled(),
        dynamodb.NewDynamodbTableCrossAccountAccess(),
        dynamodb.NewDynamodbAcceleratorClusterMultiAz(),
    },
    "ec2": {
        ec2.NewEc2PublicAddressCheck(),
        ec2.NewEc2FlowLogsEnabledCheck(),
        ec2.NewEc2SecurityGroupAllPortsOpenCheck(),
    },
    "ecr": {
        ecr.NewEcrRepositoriesNotPubliclyAccessible(),
        ecr.NewEcrRegistryEnhancedScanningEnabled(),
        ecr.NewEcrRepositoriesTagImmutability(),
        ecr.NewEcrRepositoriesLifecyclePolicyEnabled(),
        ecr.NewEcrRepositoriesScanVulnerabilitiesInLatestImage(),
        ecr.NewEcrRegistryScanImagesOnPushEnabled(),
        ecr.NewEcrRepositoriesScanImagesOnPushEnabled(),
        ecr.NewEcrRepositoryImageNoSecrets(),
    },
    "ecs": {
        ecs.NewEcsClusterContainerInsightsEnabled(),
        ecs.NewEcsServiceFargateLatestPlatformVersion(),
        ecs.NewEcsServiceNoAssignPublicIp(),
        ecs.NewEcsTaskDefinitionsContainersReadonlyAccess(),
        ecs.NewEcsTaskDefinitionsHostNamespaceNotShared(),
        ecs.NewEcsTaskDefinitionsHostNetworkingModeUsers(),
        ecs.NewEcsTaskDefinitionsLoggingBlockMode(),
        ecs.NewEcsTaskDefinitionsLoggingEnabled(),
        ecs.NewEcsTaskDefinitionsNoEnvironmentSecrets(),
        ecs.NewEcsTaskDefinitionsNoPrivilegedContainers(),
        ecs.NewEcsTaskSetNoAssignPublicIp(),
    },
    "efs": {
        efs.NewEfsHaveBackupEnabled(),
        efs.NewEfsAccessPointEnforceUserIdentity(),
        efs.NewEfsMountTargetNotPubliclyAccessible(),
        efs.NewEfsMultiAzEnabled(),
        efs.NewEfsEncryptionAtRestEnabled(),
        efs.NewEfsAccessPointEnforceRootDirectory(),
        efs.NewEfsNotPubliclyAccessible(),
    },
    "eks": {
        eks.NewEksClusterNotPubliclyAccessible(),
        eks.NewEksClusterPrivateNodesEnabled(),
        eks.NewEksClusterDeletionProtectionEnabled(),
        eks.NewEksControlPlaneLoggingAllTypesEnabled(),
        eks.NewEksClusterKmsCmkEncryptionInSecretsEnabled(),
        eks.NewEksClusterUsesASupportedVersion(),
        eks.NewEksClusterVpcCniNetworkPolicyEnforced(),
        eks.NewEksClusterNetworkPolicyEnabled(),
    },
    "elasticache": {
        elasticache.NewElasticacheRedisReplicationGroupAuthEnabled(),
        elasticache.NewElasticacheClusterUsesPublicSubnet(),
        elasticache.NewElasticacheRedisClusterAutoMinorVersionUpgrades(),
        elasticache.NewElasticacheRedisClusterBackupEnabled(),
        elasticache.NewElasticacheRedisClusterMultiAzEnabled(),
        elasticache.NewElasticacheRedisClusterRestEncryptionEnabled(),
        elasticache.NewElasticacheRedisClusterAutomaticFailoverEnabled(),
        elasticache.NewElasticacheRedisClusterInTransitEncryptionEnabled(),
    },
    "elasticbeanstalk": {
        elasticbeanstalk.NewElasticbeanstalkEnvironmentManagedUpdatesEnabled(),
        elasticbeanstalk.NewElasticbeanstalkEnvironmentEnhancedHealthReporting(),
        elasticbeanstalk.NewElasticbeanstalkEnvironmentNoSecretsInConfiguration(),
        elasticbeanstalk.NewElasticbeanstalkEnvironmentCloudwatchLoggingEnabled(),
    },
    "elb": {
        elb.NewElbConnectionDrainingEnabled(),
        elb.NewElbCrossZoneLoadBalancingEnabled(),
        elb.NewElbDesyncMitigationMode(),
        elb.NewElbInsecureSslCiphers(),
        elb.NewElbInternetFacing(),
        elb.NewElbIsInMultipleAz(),
        elb.NewElbLoggingEnabled(),
        elb.NewElbSslListeners(),
        elb.NewElbSslListenersUseAcmCertificate(),
    },
    "elbv2": {
        elbv2.NewElbv2ListenersUnderneath(),
        elbv2.NewElbv2LoggingEnabled(),
        elbv2.NewElbv2CrossZoneLoadBalancingEnabled(),
        elbv2.NewElbv2WafAclAttached(),
        elbv2.NewElbv2DesyncMitigationMode(),
        elbv2.NewElbv2IsInMultipleAz(),
        elbv2.NewElbv2NlbTlsTerminationEnabled(),
        elbv2.NewElbv2InsecureSslCiphers(),
        elbv2.NewElbv2ListenerPqcTlsEnabled(),
        elbv2.NewElbv2AlbDropInvalidHeaderFieldsEnabled(),
        elbv2.NewElbv2InternetFacing(),
        elbv2.NewElbv2SslListeners(),
        elbv2.NewElbv2DeletionProtection(),
    },
    "emr": {
        emr.NewEmrClusterAccountPublicBlockEnabled(),
        emr.NewEmrClusterPubliclyAccessible(),
        emr.NewEmrClusterMasterNodesNoPublicIp(),
    },
    "eventbridge": {
        eventbridge.NewEventbridgeBusEncrypted(),
        eventbridge.NewEventbridgeBusPublicAccess(),
        eventbridge.NewEventbridgeRuleEncrypted(),
        eventbridge.NewEventbridgeSchemaRegistryEncrypted(),
    },
    "firehose": {
        firehose.NewFirehoseStreamEncryptedAtRest(),
    },
    "fms": {
        fms.NewFmsPolicyCompliant(),
    },
    "fsx": {
        fsx.NewFsxFileSystemEncrypted(),
        fsx.NewFsxFileSystemInVpc(),
        fsx.NewFileSystemBackupEnabled(),
    },
    "glacier": {
        glacier.NewGlacierVaultEncryptionCheck(),
        glacier.NewGlacierVaultNoPublicAccessCheck(),
        glacier.NewGlacierVaultLoggingCheck(),
    },
    "glue": {
        glue.NewGlueDataCatalogsMetadataEncryptionEnabled(),
        glue.NewGlueDataCatalogsConnectionPasswordsEncryptionEnabled(),
        glue.NewGlueDataCatalogsNotPubliclyAccessible(),
        glue.NewGlueDatabaseConnectionsSSLEnabled(),
        glue.NewGlueCatalogConnectionNoSecrets(),
        glue.NewGlueDevelopmentEndpointsCloudwatchLogsEncryptionEnabled(),
        glue.NewGlueDevelopmentEndpointsJobBookmarkEncryptionEnabled(),
        glue.NewGlueDevelopmentEndpointsS3EncryptionEnabled(),
        glue.NewGlueEtlJobsAmazonS3EncryptionEnabled(),
        glue.NewGlueEtlJobsCloudwatchLogsEncryptionEnabled(),
        glue.NewGlueEtlJobsJobBookmarkEncryptionEnabled(),
        glue.NewGlueEtlJobsLoggingEnabled(),
        glue.NewGlueEtlJobsNoSecretsInArguments(),
        glue.NewGlueMlTransformEncryptedAtRest(),
    },
    "guardduty": {
        guardduty.NewGuarddutyEc2MalwareProtectionEnabled(),
        guardduty.NewGuarddutyEksRuntimeMonitoringEnabled(),
        guardduty.NewGuarddutyDelegatedAdminEnabledAllRegions(),
        guardduty.NewGuarddutyLambdaProtectionEnabled(),
        guardduty.NewGuarddutyIsEnabled(),
        guardduty.NewGuarddutyEksAuditLogEnabled(),
        guardduty.NewGuarddutyRdsProtectionEnabled(),
        guardduty.NewGuarddutyRuntimeMonitoringEnabled(),
        guardduty.NewGuarddutyNoHighSeverityFindings(),
        guardduty.NewGuarddutyS3ProtectionEnabled(),
        guardduty.NewGuarddutyAiProtectionEnabled(),
        guardduty.NewGuarddutyCentrallyManaged(),
    },
    "iam": {
        iam.NewIamPasswordPolicyMinLength14Check(),
        iam.NewIamUserMfaEnabledConsoleAccessCheck(),
        iam.NewIamNoRootAccessKeyCheck(),
        iam.NewIamPasswordPolicyExpiresCheck(),
    },
    "inspector2": {
        inspector2.NewInspector2IsEnabled(),
        inspector2.NewInspector2ActiveFindingsExist(),
    },
    "kafka": {
        kafka.NewKafkaClusterEncryptionAtRest(),
        kafka.NewKafkaClusterEncryptionInTransit(),
        kafka.NewKafkaClusterInVpc(),
        kafka.NewKafkaClusterLoggingEnabled(),
        kafka.NewKafkaClusterMonitoringEnabled(),
        kafka.NewKafkaClusterPublicAccess(),
        kafka.NewKafkaClusterUnencryptedAtRest(),
        kafka.NewKafkaClusterUnencryptedInTransit(),
    },
    "kinesis": {
        kinesis.NewKinesisStreamEncryptedAtRest(),
        kinesis.NewKinesisStreamDataRetentionPeriod(),
    },
    "kms": {
        kms.NewKmsCmkNotDeletedUnintentionally(),
        kms.NewKmsKeyNotPubliclyAccessible(),
        kms.NewKmsCmkRotationEnabled(),
        kms.NewKmsCmkNotMultiRegion(),
        kms.NewKmsCmkAreUsed(),
        kms.NewKmsKeyEnclaveAttestationBypassablePath(),
        kms.NewKmsKeyEnclaveAttestationNoDeploymentBinding(),
        kms.NewKmsKeyEnclaveAttestationNotEnforced(),
        kms.NewKmsKeyEnclaveAttestationPcrMismatch(),
        kms.NewKmsKeyEnclaveAttestationUnknownImage(),
        kms.NewKmsKeyEnclaveDebugAttestationDetected(),
    },
    "lambda": {
        lambda.NewLambdaFunctionNoSecretsCheck(),
        lambda.NewLambdaFunctionTracingEnabledCheck(),
        lambda.NewLambdaFunctionNoLatestRuntimeCheck(),
        lambda.NewLambdaFunctionInVPCCheck(),
        lambda.NewLambdaFunctionNotPublicCheck(),
        lambda.NewLambdaFunctionReservedConcurrencyCheck(),
        lambda.NewLambdaFunctionCodeSigningCheck(),
    },
    "lightsail": {
        lightsail.NewLightsailInstanceAutomaticSnapshots(),
        lightsail.NewLightsailInstancePublicAccess(),
        lightsail.NewLightsailStaticIpUnused(),
        lightsail.NewLightsailLoadBalancerTlsPolicy(),
    },
    "macie": {
        macie.NewMacieAutomatedSensitiveDataDiscoveryEnabled(),
        macie.NewMacieIsEnabled(),
    },
    "memorydb": {
        memorydb.NewMemorydbClusterAutoMinorVersionUpgrades(),
        memorydb.NewMemorydbClusterInTransitEncryptionEnabled(),
    },
    "mq": {
        mq.NewMqBrokerClusterDeploymentMode(),
        mq.NewMqBrokerNotPubliclyAccessible(),
        mq.NewMqBrokerLoggingEnabled(),
        mq.NewMqBrokerActiveDeploymentMode(),
        mq.NewMqBrokerAutoMinorVersionUpgrades(),
    },
    "neptune": {
        neptune.NewNeptuneClusterMultiAz(),
        neptune.NewNeptuneClusterCopyTagsToSnapshots(),
        neptune.NewNeptuneClusterUsesPublicSubnet(),
        neptune.NewNeptuneClusterIamAuthenticationEnabled(),
        neptune.NewNeptuneClusterStorageEncrypted(),
        neptune.NewNeptuneClusterBackupEnabled(),
        neptune.NewNeptuneClusterPublicSnapshot(),
        neptune.NewNeptuneClusterIntegrationCloudwatchLogs(),
        neptune.NewNeptuneClusterDeletionProtection(),
        neptune.NewNeptuneClusterSnapshotEncrypted(),
    },
    "networkfirewall": {
        networkfirewall.NewNetworkfirewallPolicyDefaultActionFragmentedPackets(),
        networkfirewall.NewNetworkfirewallLoggingEnabled(),
        networkfirewall.NewNetworkfirewallPolicyDefaultActionFullPackets(),
        networkfirewall.NewNetworkfirewallInAllVpc(),
        networkfirewall.NewNetworkfirewallPolicyRuleGroupAssociated(),
        networkfirewall.NewNetworkfirewallMultiAz(),
        networkfirewall.NewNetworkfirewallDeletionProtection(),
    },
    "opensearch": {
        opensearch.NewOpensearchServiceDomainsAuditLoggingEnabled(),
        opensearch.NewOpensearchServiceDomainsEncryptionAtRestEnabled(),
        opensearch.NewOpensearchServiceDomainsCloudwatchLoggingEnabled(),
        opensearch.NewOpensearchServiceDomainsHttpsCommunicationsEnforced(),
        opensearch.NewOpensearchServiceDomainsNodeToNodeEncryptionEnabled(),
        opensearch.NewOpensearchServiceDomainsNotPubliclyAccessible(),
        opensearch.NewOpensearchServiceDomainsAccessControlEnabled(),
        opensearch.NewOpensearchServiceDomainsFaultTolerantDataNodes(),
        opensearch.NewOpensearchServiceDomainsFaultTolerantMasterNodes(),
        opensearch.NewOpensearchServiceDomainsInternalUserDatabaseEnabled(),
        opensearch.NewOpensearchServiceDomainsUpdatedToTheLatestServiceSoftwareVersion(),
        opensearch.NewOpensearchServiceDomainsUseCognitoAuthenticationForKibana(),
    },
    "organizations": {
        organizations.NewOrganizationsTagsPoliciesEnabledAndAttached(),
        organizations.NewOrganizationsDelegatedAdministrators(),
        organizations.NewOrganizationsAccountPartOfOrganizations(),
        organizations.NewOrganizationsOptOutAiServicesPolicy(),
        organizations.NewOrganizationsScpCheckDenyRegions(),
    },
    "rds": {
        rds.NewRdsClusterBacktrackEnabled(),
        rds.NewRdsClusterCopyTagsToSnapshots(),
        rds.NewRdsClusterDefaultAdmin(),
        rds.NewRdsClusterDeletionProtection(),
        rds.NewRdsClusterIamAuthenticationEnabled(),
        rds.NewRdsClusterIntegrationCloudwatchLogs(),
        rds.NewRdsClusterMinorVersionUpgradeEnabled(),
        rds.NewRdsClusterMultiAz(),
        rds.NewRdsClusterNonDefaultPort(),
        rds.NewRdsClusterStorageEncrypted(),
        rds.NewRdsInstanceBackupEnabled(),
        rds.NewRdsInstanceCopyTagsToSnapshots(),
        rds.NewRdsInstanceDefaultAdmin(),
        rds.NewRdsInstanceDeletionProtection(),
        rds.NewRdsInstanceEnhancedMonitoringEnabled(),
        rds.NewRdsInstanceIamAuthenticationEnabled(),
        rds.NewRdsInstanceInsideVpc(),
        rds.NewRdsInstanceIntegrationCloudwatchLogs(),
        rds.NewRdsInstanceMinorVersionUpgradeEnabled(),
        rds.NewRdsInstanceMultiAz(),
        rds.NewRdsInstanceNoPublicAccess(),
        rds.NewRdsInstanceNonDefaultPort(),
        rds.NewRdsInstanceStorageEncrypted(),
        rds.NewRdsInstanceTransportEncrypted(),
        rds.NewRdsSnapshotsEncrypted(),
        rds.NewRdsSnapshotsPublicAccess(),
        rds.NewRdsClusterCriticalEventSubscription(),
        rds.NewRdsClusterProtectedByBackupPlan(),
        rds.NewRdsInstanceCertificateExpiration(),
        rds.NewRdsInstanceCriticalEventSubscription(),
        rds.NewRdsInstanceDeprecatedEngineVersion(),
        rds.NewRdsInstanceEventSubscriptionParameterGroups(),
        rds.NewRdsInstanceEventSubscriptionSecurityGroups(),
        rds.NewRdsInstanceExtendedSupport(),
        rds.NewRdsInstanceProtectedByBackupPlan(),
    },
    "redshift": {
        redshift.NewRedshiftClusterAuditLogging(),
        redshift.NewRedshiftClusterAutomatedSnapshot(),
        redshift.NewRedshiftClusterAutomaticUpgrades(),
        redshift.NewRedshiftClusterEncryptedAtRest(),
        redshift.NewRedshiftClusterEnhancedVpcRouting(),
        redshift.NewRedshiftClusterInTransitEncryptionEnabled(),
        redshift.NewRedshiftClusterMultiAzEnabled(),
        redshift.NewRedshiftClusterNonDefaultDatabaseName(),
        redshift.NewRedshiftClusterNonDefaultUsername(),
        redshift.NewRedshiftClusterPublicAccess(),
    },
    "resourceexplorer2": {
        resourceexplorer2.NewResourceExplorer2IndexCheck(),
    },
    "rolesanywhere": {
        rolesanywhere.NewRolesanywhereTrustAnchorPqcPki(),
        rolesanywhere.NewRolesanywhereProfileRestrictsSessionPermissions(),
    },
    "route53": {
        route53.NewRoute53DanglingIpSubdomainTakeover(),
        route53.NewRoute53DomainsTransferlockEnabled(),
        route53.NewRoute53PublicHostedZonesCloudwatchLoggingEnabled(),
        route53.NewRoute53DomainsPrivacyProtectionEnabled(),
    },
    "s3": {
        s3.NewPublicAccessCheck(),
        s3.NewEncryptionCheck(),
        s3.NewVersioningCheck(),
        s3.NewLoggingCheck(),
        s3.NewBlockPublicAccessCheck(),
        s3.NewBucketObjectLock(),
        s3.NewBucketLevelPublicAccessBlock(),
        s3.NewBucketLifecycleEnabled(),
        s3.NewBucketObjectVersioning(),
        s3.NewBucketNoMfaDelete(),
        s3.NewBucketServerAccessLoggingEnabled(),
        s3.NewBucketEventNotificationsEnabled(),
        s3.NewBucketPublicWriteAcl(),
        s3.NewAccountLevelPublicAccessBlocks(),
        s3.NewAccessPointPublicAccessBlock(),
        s3.NewBucketAclProhibited(),
        s3.NewBucketCrossRegionReplication(),
        s3.NewBucketDefaultEncryption(),
        s3.NewBucketCrossAccountAccess(),
        s3.NewBucketObjectPublic(),
        s3.NewBucketSecureTransportPolicy(),
        s3.NewMultiRegionAccessPointPublicAccessBlock(),
        s3.NewBucketPolicyPublicWriteAccess(),
        s3.NewBucketPublicListAcl(),
        s3.NewBucketShadowResourceVulnerability(),
        s3.NewBucketKmsEncryption(),
    },
    "sagemaker": {
        sagemaker.NewSagemakerNotebookInstanceNoSecrets(),
        sagemaker.NewSagemakerTrainingJobsVolumeAndOutputEncryptionEnabled(),
        sagemaker.NewSagemakerTrainingJobsNetworkIsolationEnabled(),
        sagemaker.NewSagemakerTrainingJobsIntercontainerEncryptionEnabled(),
        sagemaker.NewSagemakerEndpointConfigKmsEncryptionEnabled(),
        sagemaker.NewSagemakerNotebookInstanceWithoutDirectInternetAccessConfigured(),
        sagemaker.NewSagemakerNotebookInstanceRootAccessDisabled(),
        sagemaker.NewSagemakerDomainSsoConfigured(),
        sagemaker.NewSagemakerEndpointConfigProdVariantInstances(),
        sagemaker.NewSagemakerModelsNetworkIsolationEnabled(),
        sagemaker.NewSagemakerTrainingJobsVpcSettingsConfigured(),
        sagemaker.NewSagemakerNotebookInstanceVpcSettingsConfigured(),
        sagemaker.NewSagemakerModelsMonitorEnabled(),
        sagemaker.NewSagemakerModelsVpcSettingsConfigured(),
        sagemaker.NewSagemakerClarifyExists(),
        sagemaker.NewSagemakerModelsRegistryInUse(),
        sagemaker.NewSagemakerNotebookInstanceEncryptionEnabled(),
    },
    "secretsmanager": {
        secretsmanager.NewSecretsManagerSecretRotationEnabled(),
        secretsmanager.NewSecretsManagerSecretUnused(),
        secretsmanager.NewSecretsManagerSecretVersionUnused(),
        secretsmanager.NewSecretsManagerSecretEncryptedWithCmk(),
        secretsmanager.NewSecretsManagerSecretUnused90Days(),
    },
    "securityhub": {
        securityhub.NewSecurityhubDelegatedAdminEnabledAllRegions(),
        securityhub.NewSecurityhubEnabled(),
    },
    "servicecatalog": {
        servicecatalog.NewServiceCatalogProductCheck(),
    },
    "ses": {
        ses.NewSesIdentityNotPubliclyAccessible(),
        ses.NewSesIdentityDkimEnabled(),
    },
    "shield": {
        shield.NewShieldAdvancedProtectionInCloudfrontDistributions(),
        shield.NewShieldAdvancedProtectionInInternetFacingLoadBalancers(),
        shield.NewShieldAdvancedProtectionInClassicLoadBalancers(),
        shield.NewShieldAdvancedProtectionInRoute53HostedZones(),
        shield.NewShieldAdvancedProtectionInAssociatedElasticIps(),
        shield.NewShieldAdvancedProtectionInGlobalAccelerators(),
    },
    "sns": {
        sns.NewSnsTopicsNotPubliclyAccessible(),
        sns.NewSnsTopicsKmsEncryptionAtRestEnabled(),
        sns.NewSnsSubscriptionNotUsingHttpEndpoints(),
    },
    "sqs": {
        sqs.NewSqsQueuesServerSideEncryptionEnabled(),
        sqs.NewSqsQueuesNotPubliclyAccessible(),
    },
    "ssm": {
        ssm.NewSsmDocumentEncrypted(),
        ssm.NewSsmSessionManagerEncrypted(),
        ssm.NewSsmAgentLatestVersion(),
    },
    "ssmincidents": {
        ssmincidents.NewSsmIncidentsReplicationSetActiveCheck(),
    },
    "stepfunctions": {
        stepfunctions.NewStepfunctionsStateMachineLoggingEnabled(),
        stepfunctions.NewStepfunctionsStateMachineTracingEnabled(),
        stepfunctions.NewStepfunctionsStateMachineEncrypted(),
    },
    "storagegateway": {
        storagegateway.NewStoragegatewayFileshareEncryptionEnabled(),
        storagegateway.NewStoragegatewayGatewayFaultTolerant(),
    },
    "sts": {
        sts.NewStsEndpointsInUseCheck(),
        sts.NewStsGlobalEndpointDeprecationCheck(),
        sts.NewStsAccessKeysRotatedCheck(),
        sts.NewStsNoRootAccessKeysCheck(),
    },
    "transfer": {
        transfer.NewTransferServerPqcSshKexEnabled(),
        transfer.NewTransferServerInTransitEncryptionEnabled(),
    },
    "trustedadvisor": {
        trustedadvisor.NewTrustedadvisorErrorsAndWarnings(),
        trustedadvisor.NewTrustedadvisorPremiumSupportPlanSubscribed(),
    },
    "vpc": {
        vpc.NewVpcPeeringRoutingTablesWithLeastPrivilege(),
        vpc.NewVpcSubnetSeparatePrivatePublic(),
        vpc.NewVpcVpnConnectionTunnelsUp(),
        vpc.NewVpcEndpointConnectionsTrustBoundaries(),
        vpc.NewVpcSubnetDifferentAz(),
        vpc.NewVpcEndpointMultiAzEnabled(),
        vpc.NewVpcDifferentRegions(),
        vpc.NewVpcFlowLogsEnabled(),
        vpc.NewVpcEndpointForEc2Enabled(),
        vpc.NewVpcSubnetNoPublicIpByDefault(),
        vpc.NewVpcEndpointServicesAllowedPrincipalsTrustBoundaries(),
    },
    "waf": {
        waf.NewWafGlobalWebaclWithRules(),
        waf.NewWafRegionalWebaclLoggingEnabled(),
        waf.NewWafRegionalRulegroupNotEmpty(),
        waf.NewWafRegionalRuleWithConditions(),
        waf.NewWafGlobalRuleWithConditions(),
        waf.NewWafGlobalWebaclLoggingEnabled(),
        waf.NewWafGlobalRulegroupNotEmpty(),
        waf.NewWafRegionalWebaclWithRules(),
    },
    "wafv2": {
        wafv2.NewWafv2WebaclWithRules(),
        wafv2.NewWafv2WebaclLoggingEnabled(),
        wafv2.NewWafv2WebaclRuleLoggingEnabled(),
    },
    "wellarchitected": {
        wellarchitected.NewWellArchitectedWorkloadCheck(),
    },
    "workspaces": {
        workspaces.NewWorkspacesVpc2private1publicSubnetsNat(),
        workspaces.NewWorkspacesVolumeEncryptionEnabled(),
    },
}
