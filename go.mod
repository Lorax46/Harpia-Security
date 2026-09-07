module github.com/Lorax46/TOTVS-Horus

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2 v1.46.0
	github.com/aws/aws-sdk-go-v2/config v1.33.2
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.328.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.62.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.110.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.48.0
	github.com/oracle/oci-go-sdk/v65 v65.124.1
	golang.org/x/oauth2 v0.36.0
	google.golang.org/api v0.297.0
)

require (
	cloud.google.com/go/auth v0.23.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.55.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/amplify v1.47.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.46.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/batch v1.74.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.71.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.72.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.62.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.70.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.86.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.45.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.77.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/codecommit v1.42.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.54.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.73.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/configservice v1.72.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.70.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/datapipeline v1.37.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/datasync v1.66.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/dlm v1.44.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/drs v1.49.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.67.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.64.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecs v1.96.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/efs v1.48.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/eks v1.71.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.60.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.41.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.40.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.62.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/emr v1.61.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/firehose v1.50.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/fms v1.52.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/glacier v1.40.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/glue v1.157.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.91.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.58.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/lambda v1.107.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/neptune v1.52.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.79.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/rds v1.127.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/redshift v1.70.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.274.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/servicecatalog v1.46.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssmincidents v1.46.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.41.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/wellarchitected v1.48.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gofrs/flock v0.10.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.20 // indirect
	github.com/googleapis/gax-go/v2 v2.24.0 // indirect
	github.com/sony/gobreaker/v2 v2.4.0 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
