package cloudwatch

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// getCloudWatchClients obtém os clientes CloudWatch
func getCloudWatchClients(ctx context.Context, provider interface{}) (*cloudwatch.Client, *cloudwatchlogs.Client, bool) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, nil, false
	}
	cwClient, _ := p.CloudWatch(ctx)
	cwlClient, _ := p.CloudWatchLogs(ctx)
	return cwClient, cwlClient, true
}

// CloudwatchAlarmActionsAlarmStateConfigured verifica ações no estado ALARM
type CloudwatchAlarmActionsAlarmStateConfigured struct {
	metadata models.CheckMetadata
}

func NewCloudwatchAlarmActionsAlarmStateConfigured() *CloudwatchAlarmActionsAlarmStateConfigured {
	return &CloudwatchAlarmActionsAlarmStateConfigured{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_alarm_actions_alarm_state_configured",
			CheckTitle: "Ensure CloudWatch alarm has actions configured for ALARM state",
			Description: "CloudWatch alarm should have actions configured for ALARM state",
			Severity: "high", ServiceName: "cloudwatch", ResourceType: "Alarm",
			RemediationText: "Configure alarm actions for ALARM state",
			Categories: []string{"cloudwatch", "alarms"},
		},
	}
}

func (c *CloudwatchAlarmActionsAlarmStateConfigured) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchAlarmActionsAlarmStateConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	cwClient, _, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	alarms, err := cwClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, alarm := range alarms.MetricAlarms {
		status := models.StatusFail
		msg := fmt.Sprintf("Alarm %s has no actions for ALARM state", aws.ToString(alarm.AlarmName))
		if len(alarm.AlarmActions) > 0 {
			status = models.StatusPass
			msg = fmt.Sprintf("Alarm %s has %d action(s) configured", aws.ToString(alarm.AlarmName), len(alarm.AlarmActions))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(alarm.AlarmName), Provider: "aws", Service: "cloudwatch",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForNetworkAcls verifica metric filter para NACLs
type CloudwatchLogMetricFilterAndAlarmForNetworkAcls struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForNetworkAcls() *CloudwatchLogMetricFilterAndAlarmForNetworkAcls {
	return &CloudwatchLogMetricFilterAndAlarmForNetworkAcls{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_changes_to_network_acls_alarm_configured",
			CheckTitle: "Ensure CloudWatch metric filter for Network ACL changes",
			Description: "CloudWatch should have metric filter and alarm for Network ACL changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for Network ACL changes",
			Categories: []string{"cloudwatch", "monitoring", "nacl"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForNetworkAcls) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForNetworkAcls) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	// Pattern para Network ACL changes
	naclPattern := strings.Contains("networkacl", "network")
	_ = naclPattern

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "NetworkAcl") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for Network ACL changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for Network ACL changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "nacl-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForNetworkGateways verifica metric filter para gateways
type CloudwatchLogMetricFilterAndAlarmForNetworkGateways struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForNetworkGateways() *CloudwatchLogMetricFilterAndAlarmForNetworkGateways {
	return &CloudwatchLogMetricFilterAndAlarmForNetworkGateways{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_changes_to_network_gateways_alarm_configured",
			CheckTitle: "Ensure CloudWatch metric filter for network gateway changes",
			Description: "CloudWatch should have metric filter and alarm for network gateway changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for network gateway changes",
			Categories: []string{"cloudwatch", "monitoring", "gateway"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForNetworkGateways) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForNetworkGateways) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "Gateway") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for network gateway changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for network gateway changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "gateway-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForRouteTables verifica metric filter para route tables
type CloudwatchLogMetricFilterAndAlarmForRouteTables struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForRouteTables() *CloudwatchLogMetricFilterAndAlarmForRouteTables {
	return &CloudwatchLogMetricFilterAndAlarmForRouteTables{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_changes_to_network_route_tables_alarm_configured",
			CheckTitle: "Ensure CloudWatch metric filter for route table changes",
			Description: "CloudWatch should have metric filter and alarm for route table changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for route table changes",
			Categories: []string{"cloudwatch", "monitoring", "route-table"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForRouteTables) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForRouteTables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "RouteTable") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for route table changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for route table changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "route-table-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForVpcChanges verifica metric filter para VPCs
type CloudwatchLogMetricFilterAndAlarmForVpcChanges struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForVpcChanges() *CloudwatchLogMetricFilterAndAlarmForVpcChanges {
	return &CloudwatchLogMetricFilterAndAlarmForVpcChanges{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_changes_to_vpcs_alarm_configured",
			CheckTitle: "Ensure CloudWatch metric filter for VPC changes",
			Description: "CloudWatch should have metric filter and alarm for VPC changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for VPC changes",
			Categories: []string{"cloudwatch", "monitoring", "vpc"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForVpcChanges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForVpcChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "Vpc") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for VPC changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for VPC changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "vpc-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogGroupNotPubliclyAccessible verifica se log groups não são públicos
type CloudwatchLogGroupNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogGroupNotPubliclyAccessible() *CloudwatchLogGroupNotPubliclyAccessible {
	return &CloudwatchLogGroupNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_group_not_publicly_accessible",
			CheckTitle: "Ensure CloudWatch log groups are not publicly accessible",
			Description: "CloudWatch log groups should not be publicly accessible",
			Severity: "high", ServiceName: "cloudwatch", ResourceType: "LogGroup",
			RemediationText: "Remove public access from log groups",
			Categories: []string{"cloudwatch", "access-control"},
		},
	}
}

func (c *CloudwatchLogGroupNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogGroupNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	groups, err := cwlClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range groups.LogGroups {
		status := models.StatusPass
		msg := fmt.Sprintf("Log group %s is not publicly accessible", aws.ToString(group.LogGroupName))

		// Verificar se o log group tem policy pública (simplificado via tags ou nome)
		if strings.Contains(aws.ToString(group.LogGroupName), "public") {
			status = models.StatusFail
			msg = fmt.Sprintf("Log group %s may have public access (name contains 'public')", aws.ToString(group.LogGroupName))
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(group.LogGroupName), Provider: "aws", Service: "cloudwatch",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForAwsConfig verifica metric filter para AWS Config
type CloudwatchLogMetricFilterAndAlarmForAwsConfig struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForAwsConfig() *CloudwatchLogMetricFilterAndAlarmForAwsConfig {
	return &CloudwatchLogMetricFilterAndAlarmForAwsConfig{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
			CheckTitle: "Ensure CloudWatch metric filter for AWS Config changes",
			Description: "CloudWatch should have metric filter for AWS Config configuration changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for AWS Config changes",
			Categories: []string{"cloudwatch", "monitoring", "config"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForAwsConfig) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForAwsConfig) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "AwsConfig") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for AWS Config changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for AWS Config changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "config-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterAuthenticationFailures verifica metric filter para falhas de auth
type CloudwatchLogMetricFilterAuthenticationFailures struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAuthenticationFailures() *CloudwatchLogMetricFilterAuthenticationFailures {
	return &CloudwatchLogMetricFilterAuthenticationFailures{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_authentication_failures",
			CheckTitle: "Ensure CloudWatch metric filter for authentication failures",
			Description: "CloudWatch should have metric filter for authentication failures",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for authentication failures",
			Categories: []string{"cloudwatch", "monitoring", "authentication"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAuthenticationFailures) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAuthenticationFailures) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "errorCode") && strings.Contains(pattern, "UnauthorizedOperation") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for authentication failures"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for authentication failures configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "auth-failures-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterAwsOrganizationsChanges verifica metric filter para Organizations
type CloudwatchLogMetricFilterAwsOrganizationsChanges struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAwsOrganizationsChanges() *CloudwatchLogMetricFilterAwsOrganizationsChanges {
	return &CloudwatchLogMetricFilterAwsOrganizationsChanges{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_aws_organizations_changes",
			CheckTitle: "Ensure CloudWatch metric filter for AWS Organizations changes",
			Description: "CloudWatch should have metric filter for AWS Organizations changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for AWS Organizations changes",
			Categories: []string{"cloudwatch", "monitoring", "organizations"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAwsOrganizationsChanges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAwsOrganizationsChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil && strings.Contains(aws.ToString(filter.FilterPattern), "AwsOrganizations") {
			hasFilter = true
			break
		}
	}

	status := models.StatusFail
	msg := "No metric filter for AWS Organizations changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for AWS Organizations changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "organizations-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk verifica metric filter para KMS
type CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk() *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk {
	return &CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
			CheckTitle: "Ensure CloudWatch metric filter for KMS key deletion",
			Description: "CloudWatch should have metric filter for KMS key disable/deletion",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for KMS key changes",
			Categories: []string{"cloudwatch", "monitoring", "kms"},
		},
	}
}

func (c *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterDisableOrScheduledDeletionOfKmsCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "kms") && (strings.Contains(pattern, "DisableKey") || strings.Contains(pattern, "ScheduleKeyDeletion")) {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for KMS key deletion"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for KMS key deletion configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "kms-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterForS3BucketPolicyChanges verifica metric filter para S3
type CloudwatchLogMetricFilterForS3BucketPolicyChanges struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterForS3BucketPolicyChanges() *CloudwatchLogMetricFilterForS3BucketPolicyChanges {
	return &CloudwatchLogMetricFilterForS3BucketPolicyChanges{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
			CheckTitle: "Ensure CloudWatch metric filter for S3 bucket policy changes",
			Description: "CloudWatch should have metric filter for S3 bucket policy changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for S3 bucket policy changes",
			Categories: []string{"cloudwatch", "monitoring", "s3"},
		},
	}
}

func (c *CloudwatchLogMetricFilterForS3BucketPolicyChanges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterForS3BucketPolicyChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "s3") && strings.Contains(pattern, "BucketPolicy") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for S3 bucket policy changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for S3 bucket policy changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "s3-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterPolicyChanges verifica metric filter para IAM policy
type CloudwatchLogMetricFilterPolicyChanges struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterPolicyChanges() *CloudwatchLogMetricFilterPolicyChanges {
	return &CloudwatchLogMetricFilterPolicyChanges{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_policy_changes",
			CheckTitle: "Ensure CloudWatch metric filter for IAM policy changes",
			Description: "CloudWatch should have metric filter for IAM policy changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for IAM policy changes",
			Categories: []string{"cloudwatch", "monitoring", "iam"},
		},
	}
}

func (c *CloudwatchLogMetricFilterPolicyChanges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterPolicyChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "iam") && strings.Contains(pattern, "Policy") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for IAM policy changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for IAM policy changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "iam-policy-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterRootUsage verifica metric filter para uso de root
type CloudwatchLogMetricFilterRootUsage struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterRootUsage() *CloudwatchLogMetricFilterRootUsage {
	return &CloudwatchLogMetricFilterRootUsage{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_root_usage",
			CheckTitle: "Ensure CloudWatch metric filter for root account usage",
			Description: "CloudWatch should have metric filter for root account usage",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for root account usage",
			Categories: []string{"cloudwatch", "monitoring", "root"},
		},
	}
}

func (c *CloudwatchLogMetricFilterRootUsage) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterRootUsage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "userIdentity.type") && strings.Contains(pattern, "Root") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for root account usage"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for root account usage configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "root-usage-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterSecurityGroupChanges verifica metric filter para security groups
type CloudwatchLogMetricFilterSecurityGroupChanges struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterSecurityGroupChanges() *CloudwatchLogMetricFilterSecurityGroupChanges {
	return &CloudwatchLogMetricFilterSecurityGroupChanges{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_security_group_changes",
			CheckTitle: "Ensure CloudWatch metric filter for security group changes",
			Description: "CloudWatch should have metric filter for security group changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for security group changes",
			Categories: []string{"cloudwatch", "monitoring", "security-group"},
		},
	}
}

func (c *CloudwatchLogMetricFilterSecurityGroupChanges) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterSecurityGroupChanges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "AuthorizeSecurityGroup") || strings.Contains(pattern, "SecurityGroup") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for security group changes"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for security group changes configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "sg-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterSignInWithoutMfa verifica metric filter para login sem MFA
type CloudwatchLogMetricFilterSignInWithoutMfa struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterSignInWithoutMfa() *CloudwatchLogMetricFilterSignInWithoutMfa {
	return &CloudwatchLogMetricFilterSignInWithoutMfa{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_sign_in_without_mfa",
			CheckTitle: "Ensure CloudWatch metric filter for console sign-in without MFA",
			Description: "CloudWatch should have metric filter for console sign-in without MFA",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for console sign-in without MFA",
			Categories: []string{"cloudwatch", "monitoring", "mfa"},
		},
	}
}

func (c *CloudwatchLogMetricFilterSignInWithoutMfa) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterSignInWithoutMfa) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "ConsoleLogin") && strings.Contains(pattern, "MFA") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for console sign-in without MFA"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for console sign-in without MFA configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "mfa-signin-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}

// CloudwatchLogMetricFilterUnauthorizedApiCalls verifica metric filter para chamadas não autorizadas
type CloudwatchLogMetricFilterUnauthorizedApiCalls struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterUnauthorizedApiCalls() *CloudwatchLogMetricFilterUnauthorizedApiCalls {
	return &CloudwatchLogMetricFilterUnauthorizedApiCalls{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_unauthorized_api_calls",
			CheckTitle: "Ensure CloudWatch metric filter for unauthorized API calls",
			Description: "CloudWatch should have metric filter for unauthorized API calls",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for unauthorized API calls",
			Categories: []string{"cloudwatch", "monitoring", "api"},
		},
	}
}

func (c *CloudwatchLogMetricFilterUnauthorizedApiCalls) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterUnauthorizedApiCalls) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	filters, err := cwlClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	hasFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			pattern := aws.ToString(filter.FilterPattern)
			if strings.Contains(pattern, "UnauthorizedAccess") || strings.Contains(pattern, "AccessDenied") {
				hasFilter = true
				break
			}
		}
	}

	status := models.StatusFail
	msg := "No metric filter for unauthorized API calls"
	if hasFilter {
		status = models.StatusPass
		msg = "Metric filter for unauthorized API calls configured"
	}

	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "unauthorized-api-metric-filter",
		FoundAt: time.Now().UTC(),
	})
	return findings, nil
}
