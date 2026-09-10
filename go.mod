module github.com/Lorax46/Harpia-Security

go 1.26.0

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4 v4.2.1
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault v1.5.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor v0.13.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4 v4.3.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.8.1
	github.com/aws/aws-sdk-go-v2 v1.47.0
	github.com/aws/aws-sdk-go-v2/config v1.33.2
	github.com/aws/aws-sdk-go-v2/service/acm v1.50.0
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.55.0
	github.com/aws/aws-sdk-go-v2/service/amplify v1.48.0
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.46.0
	github.com/aws/aws-sdk-go-v2/service/appstream v1.70.0
	github.com/aws/aws-sdk-go-v2/service/appsync v1.61.0
	github.com/aws/aws-sdk-go-v2/service/athena v1.66.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.78.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.65.0
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.71.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.81.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.72.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.62.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.70.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.86.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.77.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.73.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.72.0
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.70.0
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.46.0
	github.com/aws/aws-sdk-go-v2/service/docdb v1.55.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.67.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.328.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.64.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.96.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.48.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.71.0
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.60.0
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.41.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.40.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.62.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.61.0
	github.com/aws/aws-sdk-go-v2/service/fsx v1.74.0
	github.com/aws/aws-sdk-go-v2/service/glacier v1.40.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.157.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.91.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.62.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.63.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.58.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.107.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.65.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.43.0
	github.com/aws/aws-sdk-go-v2/service/neptune v1.52.0
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.71.0
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.79.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.60.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.127.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.70.0
	github.com/aws/aws-sdk-go-v2/service/resourceexplorer2 v1.32.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.69.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.110.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.274.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.48.0
	github.com/aws/aws-sdk-go-v2/service/servicecatalog v1.46.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.50.0
	github.com/aws/aws-sdk-go-v2/service/shield v1.42.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.78.0
	github.com/aws/aws-sdk-go-v2/service/ssmincidents v1.46.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.48.0
	github.com/aws/aws-sdk-go-v2/service/waf v1.38.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.82.0
	github.com/aws/aws-sdk-go-v2/service/wellarchitected v1.48.0
	github.com/gin-gonic/gin v1.12.0
	github.com/google/uuid v1.6.0
	github.com/oracle/oci-go-sdk/v65 v65.124.1
	golang.org/x/oauth2 v0.36.0
	google.golang.org/api v0.297.0
	gorm.io/driver/postgres v1.6.2
	gorm.io/gorm v1.31.2
)

require (
	cloud.google.com/go/auth v0.23.2 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.22.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.7.2 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.19.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.36.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.41.0 // indirect
	github.com/aws/smithy-go v1.28.1 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gofrs/flock v0.10.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.20 // indirect
	github.com/googleapis/gax-go/v2 v2.24.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/sony/gobreaker/v2 v2.4.0 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
