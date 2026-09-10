package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
)

// Provider representa um cliente AWS autenticado
type Provider struct {
	region    string
	accessKey string
	secretKey string
	cfg       aws.Config
}

// NewProvider cria um novo provider AWS
func NewProvider(ctx context.Context, region, accessKey, secretKey string) (*Provider, error) {
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
				}, nil
			}),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("falha ao carregar config AWS: %w", err)
	}

	return &Provider{
		region:    region,
		accessKey: accessKey,
		secretKey: secretKey,
		cfg:       cfg,
	}, nil
}

// ACM retorna o cliente ACM
func (p *Provider) ACM(ctx context.Context) (*acm.Client, error) {
	return acm.NewFromConfig(p.cfg), nil
}

// Amplify retorna o cliente Amplify
func (p *Provider) Amplify(ctx context.Context) (*amplify.Client, error) {
	return amplify.NewFromConfig(p.cfg), nil
}

// APIGateway retorna o cliente API Gateway
func (p *Provider) APIGateway(ctx context.Context) (*apigateway.Client, error) {
	return apigateway.NewFromConfig(p.cfg), nil
}

// AppStream retorna o cliente AppStream
func (p *Provider) AppStream(ctx context.Context) (*appstream.Client, error) {
	return appstream.NewFromConfig(p.cfg), nil
}

// AppSync retorna o cliente AppSync
func (p *Provider) AppSync(ctx context.Context) (*appsync.Client, error) {
	return appsync.NewFromConfig(p.cfg), nil
}

// Athena retorna o cliente Athena
func (p *Provider) Athena(ctx context.Context) (*athena.Client, error) {
	return athena.NewFromConfig(p.cfg), nil
}

// AutoScaling retorna o cliente Auto Scaling
func (p *Provider) AutoScaling(ctx context.Context) (*autoscaling.Client, error) {
	return autoscaling.NewFromConfig(p.cfg), nil
}

// Backup retorna o cliente Backup
func (p *Provider) Backup(ctx context.Context) (*backup.Client, error) {
	return backup.NewFromConfig(p.cfg), nil
}

// Bedrock retorna o cliente Bedrock
func (p *Provider) Bedrock(ctx context.Context) (*bedrock.Client, error) {
	return bedrock.NewFromConfig(p.cfg), nil
}

// CloudFormation retorna o cliente CloudFormation
func (p *Provider) CloudFormation(ctx context.Context) (*cloudformation.Client, error) {
	return cloudformation.NewFromConfig(p.cfg), nil
}

// CloudFront retorna o cliente CloudFront
func (p *Provider) CloudFront(ctx context.Context) (*cloudfront.Client, error) {
	return cloudfront.NewFromConfig(p.cfg), nil
}

// CloudTrail retorna o cliente CloudTrail
func (p *Provider) CloudTrail(ctx context.Context) (*cloudtrail.Client, error) {
	return cloudtrail.NewFromConfig(p.cfg), nil
}

// CloudWatch retorna o cliente CloudWatch
func (p *Provider) CloudWatch(ctx context.Context) (*cloudwatch.Client, error) {
	return cloudwatch.NewFromConfig(p.cfg), nil
}

// CloudWatchLogs retorna o cliente CloudWatch Logs
func (p *Provider) CloudWatchLogs(ctx context.Context) (*cloudwatchlogs.Client, error) {
	return cloudwatchlogs.NewFromConfig(p.cfg), nil
}

// CodeBuild retorna o cliente CodeBuild
func (p *Provider) CodeBuild(ctx context.Context) (*codebuild.Client, error) {
	return codebuild.NewFromConfig(p.cfg), nil
}

// CognitoIDP retorna o cliente Cognito Identity Provider
func (p *Provider) CognitoIDP(ctx context.Context) (*cognitoidentityprovider.Client, error) {
	return cognitoidentityprovider.NewFromConfig(p.cfg), nil
}

// ConfigService retorna o cliente Config
func (p *Provider) ConfigService(ctx context.Context) (*configservice.Client, error) {
	return configservice.NewFromConfig(p.cfg), nil
}

// DirectoryService retorna o cliente Directory Service
func (p *Provider) DirectoryService(ctx context.Context) (*directoryservice.Client, error) {
	return directoryservice.NewFromConfig(p.cfg), nil
}

// DynamoDB retorna o cliente DynamoDB
func (p *Provider) DynamoDB(ctx context.Context) (*dynamodb.Client, error) {
	return dynamodb.NewFromConfig(p.cfg), nil
}

// EC2 retorna o cliente EC2
func (p *Provider) EC2(ctx context.Context) (*ec2.Client, error) {
	return ec2.NewFromConfig(p.cfg), nil
}

// ECR retorna o cliente ECR
func (p *Provider) ECR(ctx context.Context) (*ecr.Client, error) {
	return ecr.NewFromConfig(p.cfg), nil
}

// ECS retorna o cliente ECS
func (p *Provider) ECS(ctx context.Context) (*ecs.Client, error) {
	return ecs.NewFromConfig(p.cfg), nil
}

// EFS retorna o cliente EFS
func (p *Provider) EFS(ctx context.Context) (*efs.Client, error) {
	return efs.NewFromConfig(p.cfg), nil
}

// EKS retorna o cliente EKS
func (p *Provider) EKS(ctx context.Context) (*eks.Client, error) {
	return eks.NewFromConfig(p.cfg), nil
}

// ElastiCache retorna o cliente ElastiCache
func (p *Provider) ElastiCache(ctx context.Context) (*elasticache.Client, error) {
	return elasticache.NewFromConfig(p.cfg), nil
}

// ElasticBeanstalk retorna o cliente Elastic Beanstalk
func (p *Provider) ElasticBeanstalk(ctx context.Context) (*elasticbeanstalk.Client, error) {
	return elasticbeanstalk.NewFromConfig(p.cfg), nil
}

// ELB retorna o cliente ELB (Classic)
func (p *Provider) ELB(ctx context.Context) (*elasticloadbalancing.Client, error) {
	return elasticloadbalancing.NewFromConfig(p.cfg), nil
}

// ELBv2 retorna o cliente ELBv2
func (p *Provider) ELBv2(ctx context.Context) (*elasticloadbalancingv2.Client, error) {
	return elasticloadbalancingv2.NewFromConfig(p.cfg), nil
}

// EMR retorna o cliente EMR
func (p *Provider) EMR(ctx context.Context) (*emr.Client, error) {
	return emr.NewFromConfig(p.cfg), nil
}

// FSx retorna o cliente FSx
func (p *Provider) FSx(ctx context.Context) (*fsx.Client, error) {
	return fsx.NewFromConfig(p.cfg), nil
}

// Glue retorna o cliente Glue
func (p *Provider) Glue(ctx context.Context) (*glue.Client, error) {
	return glue.NewFromConfig(p.cfg), nil
}

// GuardDuty retorna o cliente GuardDuty
func (p *Provider) GuardDuty(ctx context.Context) (*guardduty.Client, error) {
	return guardduty.NewFromConfig(p.cfg), nil
}

// IAM retorna o cliente IAM
func (p *Provider) IAM(ctx context.Context) (*iam.Client, error) {
	return iam.NewFromConfig(p.cfg), nil
}

// KMS retorna o cliente KMS
func (p *Provider) KMS(ctx context.Context) (*kms.Client, error) {
	return kms.NewFromConfig(p.cfg), nil
}

// Lambda retorna o cliente Lambda
func (p *Provider) Lambda(ctx context.Context) (*lambda.Client, error) {
	return lambda.NewFromConfig(p.cfg), nil
}

// Lightsail retorna o cliente Lightsail
func (p *Provider) Lightsail(ctx context.Context) (*lightsail.Client, error) {
	return lightsail.NewFromConfig(p.cfg), nil
}

// MQ retorna o cliente MQ
func (p *Provider) MQ(ctx context.Context) (*mq.Client, error) {
	return mq.NewFromConfig(p.cfg), nil
}

// Neptune retorna o cliente Neptune
func (p *Provider) Neptune(ctx context.Context) (*neptune.Client, error) {
	return neptune.NewFromConfig(p.cfg), nil
}

// NetworkFirewall retorna o cliente Network Firewall
func (p *Provider) NetworkFirewall(ctx context.Context) (*networkfirewall.Client, error) {
	return networkfirewall.NewFromConfig(p.cfg), nil
}

// OpenSearch retorna o cliente OpenSearch
func (p *Provider) OpenSearch(ctx context.Context) (*opensearch.Client, error) {
	return opensearch.NewFromConfig(p.cfg), nil
}

// Organizations retorna o cliente Organizations
func (p *Provider) Organizations(ctx context.Context) (*organizations.Client, error) {
	return organizations.NewFromConfig(p.cfg), nil
}

// RDS retorna o cliente RDS
func (p *Provider) RDS(ctx context.Context) (*rds.Client, error) {
	return rds.NewFromConfig(p.cfg), nil
}

// Redshift retorna o cliente Redshift
func (p *Provider) Redshift(ctx context.Context) (*redshift.Client, error) {
	return redshift.NewFromConfig(p.cfg), nil
}

// ResourceExplorer2 retorna o cliente Resource Explorer
func (p *Provider) ResourceExplorer2(ctx context.Context) (*resourceexplorer2.Client, error) {
	return resourceexplorer2.NewFromConfig(p.cfg), nil
}

// Route53 retorna o cliente Route53
func (p *Provider) Route53(ctx context.Context) (*route53.Client, error) {
	return route53.NewFromConfig(p.cfg), nil
}

// S3 retorna o cliente S3
func (p *Provider) S3(ctx context.Context) (*s3.Client, error) {
	return s3.NewFromConfig(p.cfg), nil
}

// SageMaker retorna o cliente SageMaker
func (p *Provider) SageMaker(ctx context.Context) (*sagemaker.Client, error) {
	return sagemaker.NewFromConfig(p.cfg), nil
}

// SecretsManager retorna o cliente Secrets Manager
func (p *Provider) SecretsManager(ctx context.Context) (*secretsmanager.Client, error) {
	return secretsmanager.NewFromConfig(p.cfg), nil
}

// ServiceCatalog retorna o cliente Service Catalog
func (p *Provider) ServiceCatalog(ctx context.Context) (*servicecatalog.Client, error) {
	return servicecatalog.NewFromConfig(p.cfg), nil
}

// StepFunctions retorna o cliente Step Functions
func (p *Provider) StepFunctions(ctx context.Context) (*sfn.Client, error) {
	return sfn.NewFromConfig(p.cfg), nil
}

// Shield retorna o cliente Shield
func (p *Provider) Shield(ctx context.Context) (*shield.Client, error) {
	return shield.NewFromConfig(p.cfg), nil
}

// SSM retorna o cliente SSM
func (p *Provider) SSM(ctx context.Context) (*ssm.Client, error) {
	return ssm.NewFromConfig(p.cfg), nil
}

// STS retorna o cliente STS
func (p *Provider) STS(ctx context.Context) (*sts.Client, error) {
	return sts.NewFromConfig(p.cfg), nil
}

// WAF retorna o cliente WAF
func (p *Provider) WAF(ctx context.Context) (*waf.Client, error) {
	return waf.NewFromConfig(p.cfg), nil
}

// WAFv2 retorna o cliente WAFv2
func (p *Provider) WAFv2(ctx context.Context) (*wafv2.Client, error) {
	return wafv2.NewFromConfig(p.cfg), nil
}

// DMS retorna o cliente DMS
func (p *Provider) DMS(ctx context.Context) (*databasemigrationservice.Client, error) {
	return databasemigrationservice.NewFromConfig(p.cfg), nil
}

// Region retorna a região configurada
func (p *Provider) Region() string {
	return p.region
}

// AccountId retorna o ID da conta AWS
func (p *Provider) AccountId() string {
	client, _ := p.STS(context.Background())
	if client == nil {
		return ""
	}
	identity, err := client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return ""
	}
	return *identity.Account
}
