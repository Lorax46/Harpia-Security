package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/aws"
)

// AWSCollector implementa a interface Collector para AWS.
type AWSCollector struct {
	provider *aws.Provider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewAWSCollector cria um novo coletor AWS.
func NewAWSCollector(provider *aws.Provider) *AWSCollector {
	return &AWSCollector{
		provider: provider,
		cache:    make(map[string]*InventoryResult),
	}
}

// Collect coleta recursos do tipo especificado.
func (c *AWSCollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "aws",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	case "aws_iam_user":
		result.Resources, err = c.collectIAMUsers(ctx)
	case "aws_iam_role":
		result.Resources, err = c.collectIAMRoles(ctx)
	case "aws_iam_group":
		result.Resources, err = c.collectIAMGroups(ctx)
	case "aws_iam_policy":
		result.Resources, err = c.collectIAMPolicies(ctx)
	case "aws_ec2_instance":
		result.Resources, err = c.collectEC2Instances(ctx)
	case "aws_ec2_vpc":
		result.Resources, err = c.collectVPCs(ctx)
	case "aws_ec2_subnet":
		result.Resources, err = c.collectSubnets(ctx)
	case "aws_ec2_security_group":
		result.Resources, err = c.collectSecurityGroups(ctx)
	case "aws_s3_bucket":
		result.Resources, err = c.collectS3Buckets(ctx)
	case "aws_elbv2_load_balancer":
		result.Resources, err = c.collectLoadBalancers(ctx)
	case "aws_lambda_function":
		result.Resources, err = c.collectLambdaFunctions(ctx)
	case "aws_rds_db_instance":
		result.Resources, err = c.collectRDSInstances(ctx)
	case "aws_dynamodb_table":
		result.Resources, err = c.collectDynamoDBTables(ctx)
	case "aws_ecs_cluster":
		result.Resources, err = c.collectECSClusters(ctx)
	case "aws_eks_cluster":
		result.Resources, err = c.collectEKSClusters(ctx)
	case "aws_cloudfront_distribution":
		result.Resources, err = c.collectCloudFrontDistributions(ctx)
	case "aws_route53_zone":
		result.Resources, err = c.collectRoute53Zones(ctx)
	case "aws_kms_key":
		result.Resources, err = c.collectKMSKeys(ctx)
	case "aws_secretsmanager_secret":
		result.Resources, err = c.collectSecretsManagerSecrets(ctx)
	case "aws_sns_topic":
		result.Resources, err = c.collectSNSTopics(ctx)
	case "aws_sqs_queue":
		result.Resources, err = c.collectSQSQueues(ctx)
	case "aws_cloudtrail_trail":
		result.Resources, err = c.collectCloudTrailTrails(ctx)
	case "aws_organizations_account":
		result.Resources, err = c.collectAccounts(ctx)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	if err != nil {
		return nil, err
	}

	result.Total = len(result.Resources)
	c.mu.Lock()
	c.cache[resourceType] = result
	c.mu.Unlock()
	return result, nil
}

// ListResourceTypes lista todos os tipos de recursos suportados.
func (c *AWSCollector) ListResourceTypes() []ResourceType {
	var resourceTypes []ResourceType
	for _, rt := range steampipeResourceTypes {
		if rt.Provider == "aws" {
			resourceTypes = append(resourceTypes, rt)
		}
	}
	return resourceTypes
}

func (c *AWSCollector) collectIAMUsers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}

	users, err := client.ListUsers(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, user := range users.Users {
		resources = append(resources, Resource{
			ID:         safePtr(user.UserId),
			Name:       safePtr(user.UserName),
			Type:       "aws_iam_user",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectIAMRoles(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListRoles(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, role := range output.Roles {
		resources = append(resources, Resource{
			ID:         safePtr(role.RoleId),
			Name:       safePtr(role.RoleName),
			Type:       "aws_iam_role",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectIAMGroups(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListGroups(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, group := range output.Groups {
		resources = append(resources, Resource{
			ID:         safePtr(group.GroupId),
			Name:       safePtr(group.GroupName),
			Type:       "aws_iam_group",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectIAMPolicies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListPolicies(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, policy := range output.Policies {
		resources = append(resources, Resource{
			ID:         safePtr(policy.Arn),
			Name:       safePtr(policy.PolicyName),
			Type:       "aws_iam_policy",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectEC2Instances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.EC2(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeInstances(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			resources = append(resources, Resource{
				ID:         safePtr(instance.InstanceId),
				Name:       safePtr(instance.InstanceId),
				Type:       "aws_ec2_instance",
				Provider:   "aws",
				Region:     "us-east-1",
				Discovered: time.Now(),
				Tags:       ec2TagsToMap(instance.Tags),
			})
		}
	}
	return resources, nil
}

func (c *AWSCollector) collectVPCs(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.EC2(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeVpcs(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, vpc := range output.Vpcs {
		resources = append(resources, Resource{
			ID:         safePtr(vpc.VpcId),
			Name:       vpcName(vpc),
			Type:       "aws_ec2_vpc",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
			Tags:       ec2TagsToMap(vpc.Tags),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectSubnets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.EC2(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeSubnets(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, subnet := range output.Subnets {
		resources = append(resources, Resource{
			ID:         safePtr(subnet.SubnetId),
			Name:       subnetName(subnet),
			Type:       "aws_ec2_subnet",
			Provider:   "aws",
			Region:     safePtr(subnet.AvailabilityZone),
			Discovered: time.Now(),
			Tags:       ec2TagsToMap(subnet.Tags),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectSecurityGroups(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.EC2(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeSecurityGroups(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, sg := range output.SecurityGroups {
		resources = append(resources, Resource{
			ID:         safePtr(sg.GroupId),
			Name:       safePtr(sg.GroupName),
			Type:       "aws_ec2_security_group",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
			Tags:       ec2TagsToMap(sg.Tags),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectS3Buckets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.S3(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListBuckets(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, bucket := range output.Buckets {
		resources = append(resources, Resource{
			ID:         safePtr(bucket.Name),
			Name:       safePtr(bucket.Name),
			Type:       "aws_s3_bucket",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectLoadBalancers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.ELBv2(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeLoadBalancers(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, lb := range output.LoadBalancers {
		resources = append(resources, Resource{
			ID:         safePtr(lb.LoadBalancerArn),
			Name:       safePtr(lb.LoadBalancerName),
			Type:       "aws_elbv2_load_balancer",
			Provider:   "aws",
			Region:     safePtr(lb.AvailabilityZones[0].ZoneName),
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectLambdaFunctions(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Lambda(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListFunctions(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, fn := range output.Functions {
		resources = append(resources, Resource{
			ID:         safePtr(fn.FunctionArn),
			Name:       safePtr(fn.FunctionName),
			Type:       "aws_lambda_function",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectRDSInstances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.RDS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeDBInstances(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, db := range output.DBInstances {
		resources = append(resources, Resource{
			ID:         safePtr(db.DBInstanceArn),
			Name:       safePtr(db.DBInstanceIdentifier),
			Type:       "aws_rds_db_instance",
			Provider:   "aws",
			Region:     safePtr(db.AvailabilityZone),
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectDynamoDBTables(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.DynamoDB(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListTables(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, table := range output.TableNames {
		resources = append(resources, Resource{
			ID:         table,
			Name:       table,
			Type:       "aws_dynamodb_table",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectECSClusters(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.ECS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListClusters(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cluster := range output.ClusterArns {
		resources = append(resources, Resource{
			ID:         cluster,
			Name:       clusterArnToName(cluster),
			Type:       "aws_ecs_cluster",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectEKSClusters(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.EKS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListClusters(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cluster := range output.Clusters {
		resources = append(resources, Resource{
			ID:         cluster,
			Name:       cluster,
			Type:       "aws_eks_cluster",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectCloudFrontDistributions(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.CloudFront(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListDistributions(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, dist := range output.DistributionList.Items {
		resources = append(resources, Resource{
			ID:         safePtr(dist.ARN),
			Name:       safePtr(dist.DomainName),
			Type:       "aws_cloudfront_distribution",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectRoute53Zones(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Route53(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListHostedZones(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, zone := range output.HostedZones {
		resources = append(resources, Resource{
			ID:         safePtr(zone.Id),
			Name:       safePtr(zone.Name),
			Type:       "aws_route53_zone",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectKMSKeys(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.KMS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListKeys(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, key := range output.Keys {
		resources = append(resources, Resource{
			ID:         safePtr(key.KeyArn),
			Name:       safePtr(key.KeyId),
			Type:       "aws_kms_key",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectSecretsManagerSecrets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SecretsManager(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListSecrets(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, secret := range output.SecretList {
		resources = append(resources, Resource{
			ID:         safePtr(secret.ARN),
			Name:       safePtr(secret.Name),
			Type:       "aws_secretsmanager_secret",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectSNSTopics(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SNS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListTopics(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, topic := range output.Topics {
		resources = append(resources, Resource{
			ID:         safePtr(topic.TopicArn),
			Name:       safePtr(topic.TopicArn),
			Type:       "aws_sns_topic",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectSQSQueues(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQS(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListQueues(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, queue := range output.QueueUrls {
		resources = append(resources, Resource{
			ID:         queue,
			Name:       queue,
			Type:       "aws_sqs_queue",
			Provider:   "aws",
			Region:     "us-east-1",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectCloudTrailTrails(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.DescribeTrails(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, trail := range output.TrailList {
		resources = append(resources, Resource{
			ID:         safePtr(trail.TrailARN),
			Name:       safePtr(trail.Name),
			Type:       "aws_cloudtrail_trail",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func (c *AWSCollector) collectAccounts(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Organizations(ctx)
	if err != nil {
		return nil, err
	}

	output, err := client.ListAccounts(ctx, nil)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, account := range output.Accounts {
		resources = append(resources, Resource{
			ID:         safePtr(account.Id),
			Name:       safePtr(account.Name),
			Type:       "aws_organizations_account",
			Provider:   "aws",
			Region:     "global",
			Discovered: time.Now(),
		})
	}
	return resources, nil
}

func safePtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ec2TagsToMap(tags []types.Tag) map[string]string {
	result := make(map[string]string)
	for _, tag := range tags {
		if tag.Key != nil && tag.Value != nil {
			result[*tag.Key] = *tag.Value
		}
	}
	return result
}

func subnetName(subnet types.Subnet) string {
	if subnet.SubnetId != nil {
		return *subnet.SubnetId
	}
	return ""
}

func vpcName(vpc types.Vpc) string {
	if vpc.VpcId != nil {
		return *vpc.VpcId
	}
	return ""
}

func clusterArnToName(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return arn
}
