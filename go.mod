module github.com/Lorax46/TOTVS-Horus

go 1.25.0

require (
	github.com/aws/aws-sdk-go-v2 v1.45.1
	github.com/aws/aws-sdk-go-v2/config v1.33.2
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.54.0
	github.com/aws/aws-sdk-go-v2/service/account v1.39.0
	github.com/aws/aws-sdk-go-v2/service/acm v1.48.0
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.54.0
	github.com/aws/aws-sdk-go-v2/service/amplify v1.46.0
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.45.0
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.40.0
	github.com/aws/aws-sdk-go-v2/service/appstream v1.68.1
	github.com/aws/aws-sdk-go-v2/service/appsync v1.59.0
	github.com/aws/aws-sdk-go-v2/service/athena v1.64.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.76.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.63.0
	github.com/aws/aws-sdk-go-v2/service/batch v1.73.0
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.70.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.79.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.71.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.62.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.70.0
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.44.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.76.0
	github.com/aws/aws-sdk-go-v2/service/codecommit v1.41.0
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.53.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.72.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.72.0
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.69.0
	github.com/aws/aws-sdk-go-v2/service/datapipeline v1.36.0
	github.com/aws/aws-sdk-go-v2/service/datasync v1.65.0
	github.com/aws/aws-sdk-go-v2/service/directconnect v1.48.0
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.45.0
	github.com/aws/aws-sdk-go-v2/service/dlm v1.43.0
	github.com/aws/aws-sdk-go-v2/service/docdb v1.54.0
	github.com/aws/aws-sdk-go-v2/service/drs v1.48.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.66.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.328.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.63.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.95.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.47.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.97.0
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.59.0
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.40.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.39.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.61.1
	github.com/aws/aws-sdk-go-v2/service/emr v1.68.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.52.0
	github.com/aws/aws-sdk-go-v2/service/firehose v1.49.0
	github.com/aws/aws-sdk-go-v2/service/fms v1.51.0
	github.com/aws/aws-sdk-go-v2/service/fsx v1.72.0
	github.com/aws/aws-sdk-go-v2/service/glacier v1.39.0
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.42.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.156.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.89.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.62.0
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.57.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.62.0
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.52.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.58.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.106.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.63.0
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.57.0
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.40.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.42.0
	github.com/aws/aws-sdk-go-v2/service/neptune v1.51.0
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.70.0
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.78.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.58.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.127.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.69.0
	github.com/aws/aws-sdk-go-v2/service/resourceexplorer2 v1.31.0
	github.com/aws/aws-sdk-go-v2/service/rolesanywhere v1.29.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.68.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.110.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.273.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.47.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.79.0
	github.com/aws/aws-sdk-go-v2/service/servicecatalog v1.45.0
	github.com/aws/aws-sdk-go-v2/service/ses v1.40.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.48.1
	github.com/aws/aws-sdk-go-v2/service/shield v1.41.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.45.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.50.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.76.0
	github.com/aws/aws-sdk-go-v2/service/ssmincidents v1.45.0
	github.com/aws/aws-sdk-go-v2/service/storagegateway v1.50.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.48.0
	github.com/aws/aws-sdk-go-v2/service/transfer v1.80.0
	github.com/aws/aws-sdk-go-v2/service/trustedadvisor v1.21.0
	github.com/aws/aws-sdk-go-v2/service/waf v1.36.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.81.0
	github.com/aws/aws-sdk-go-v2/service/wellarchitected v1.47.0
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.78.0
	github.com/oracle/oci-go-sdk/v65 v65.124.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.41.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/gofrs/flock v0.10.0 // indirect
	github.com/sony/gobreaker/v2 v2.4.0 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
