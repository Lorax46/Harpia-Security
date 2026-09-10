package cloudwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

type cloudwatchProvider interface {
	CloudWatch(ctx context.Context) (*cloudwatch.Client, error)
	CloudWatchLogs(ctx context.Context) (*cloudwatchlogs.Client, error)
}

// CloudwatchLogGroupKmsEncryptionEnabled verifica criptografia
type CloudwatchLogGroupKmsEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogGroupKmsEncryptionEnabled() *CloudwatchLogGroupKmsEncryptionEnabled {
	return &CloudwatchLogGroupKmsEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_group_kms_encryption_enabled",
			CheckTitle: "Ensure CloudWatch log groups are encrypted",
			Description: "CloudWatch log groups should be encrypted with KMS",
			Severity: "high", ServiceName: "cloudwatch", ResourceType: "LogGroup",
			RemediationText: "Enable KMS encryption for CloudWatch log groups",
			Categories: []string{"logging", "encryption"},
		},
	}
}

func (c *CloudwatchLogGroupKmsEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogGroupKmsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}
	
	client, err := p.CloudWatchLogs(ctx)
	if err != nil {
		return nil, err
	}
	
	groups, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, group := range groups.LogGroups {
		status := models.StatusFail
		msg := fmt.Sprintf("Log group %s is not encrypted", *group.LogGroupName)
		
		if group.KmsKeyId != nil && *group.KmsKeyId != "" {
			status = models.StatusPass
			msg = fmt.Sprintf("Log group %s is encrypted", *group.LogGroupName)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *group.LogGroupName, Provider: "aws", Service: "cloudwatch",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CloudwatchLogGroupRetentionPolicy verifica retenção
type CloudwatchLogGroupRetentionPolicy struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogGroupRetentionPolicy() *CloudwatchLogGroupRetentionPolicy {
	return &CloudwatchLogGroupRetentionPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_group_retention_policy_specific_days_enabled",
			CheckTitle: "Ensure CloudWatch log groups have retention policy",
			Description: "CloudWatch log groups should have retention policy set",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "LogGroup",
			RemediationText: "Set retention policy for CloudWatch log groups",
			Categories: []string{"logging", "retention"},
		},
	}
}

func (c *CloudwatchLogGroupRetentionPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogGroupRetentionPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}
	
	client, err := p.CloudWatchLogs(ctx)
	if err != nil {
		return nil, err
	}
	
	groups, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	for _, group := range groups.LogGroups {
		status := models.StatusFail
		msg := fmt.Sprintf("Log group %s has no retention policy", *group.LogGroupName)
		
		if group.RetentionInDays != nil {
			status = models.StatusPass
			msg = fmt.Sprintf("Log group %s has retention of %d days", *group.LogGroupName, *group.RetentionInDays)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *group.LogGroupName, Provider: "aws", Service: "cloudwatch",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CloudwatchCrossAccountSharingDisabled verifica compartilhamento
type CloudwatchCrossAccountSharingDisabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchCrossAccountSharingDisabled() *CloudwatchCrossAccountSharingDisabled {
	return &CloudwatchCrossAccountSharingDisabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_cross_account_sharing_disabled",
			CheckTitle: "Ensure CloudWatch cross-account sharing is disabled",
			Description: "CloudWatch cross-account sharing should be disabled",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "Account",
			RemediationText: "Disable CloudWatch cross-account sharing",
			Categories: []string{"logging", "cross-account"},
		},
	}
}

func (c *CloudwatchCrossAccountSharingDisabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchCrossAccountSharingDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}
	
	client, err := p.CloudWatch(ctx)
	if err != nil {
		return nil, err
	}
	
	alarms, err := client.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	
	hasCrossAccount := false
	for _, alarm := range alarms.MetricAlarms {
		if alarm.ActionsEnabled != nil && *alarm.ActionsEnabled {
			for _, action := range alarm.AlarmActions {
				if action != "" {
					hasCrossAccount = true
					break
				}
			}
		}
	}
	
	status := models.StatusPass
	msg := "CloudWatch cross-account sharing is disabled"
	
	if hasCrossAccount {
		status = models.StatusFail
		msg = "CloudWatch has cross-account alarm actions configured"
	}
	
	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "cloudwatch",
		FoundAt: time.Now().UTC(),
	})
	
	return findings, nil
}

// CloudwatchAlarmActionsEnabled verifica ações de alarme
type CloudwatchAlarmActionsEnabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchAlarmActionsEnabled() *CloudwatchAlarmActionsEnabled {
	return &CloudwatchAlarmActionsEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_alarm_actions_enabled",
			CheckTitle: "Ensure CloudWatch alarm actions are enabled",
			Description: "CloudWatch alarm actions should be enabled",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "Alarm",
			RemediationText: "Enable CloudWatch alarm actions",
			Categories: []string{"logging", "alarms"},
		},
	}
}

func (c *CloudwatchAlarmActionsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchAlarmActionsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}
	
	client, err := p.CloudWatch(ctx)
	if err != nil {
		return nil, err
	}
	
	alarms, err := client.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	
	for _, alarm := range alarms.MetricAlarms {
		status := models.StatusFail
		msg := fmt.Sprintf("Alarm %s has actions disabled", *alarm.AlarmName)
		
		if alarm.ActionsEnabled != nil && *alarm.ActionsEnabled {
			status = models.StatusPass
			msg = fmt.Sprintf("Alarm %s has actions enabled", *alarm.AlarmName)
		}
		
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: *alarm.AlarmName, Provider: "aws", Service: "cloudwatch",
			FoundAt: time.Now().UTC(),
		})
	}
	
	return findings, nil
}

// CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled verifica metric filter
type CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled() *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled {
	return &CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
			CheckTitle: "Ensure CloudWatch log metric filter for CloudTrail configuration changes",
			Description: "CloudWatch should have metric filter for CloudTrail configuration changes",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "MetricFilter",
			RemediationText: "Create metric filter for CloudTrail configuration changes",
			Categories: []string{"logging", "monitoring"},
		},
	}
}

func (c *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogMetricFilterAndAlarmForCloudtrailConfigurationChangesEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudwatchProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}
	
	client, err := p.CloudWatchLogs(ctx)
	if err != nil {
		return nil, err
	}
	
	filters, err := client.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{})
	if err != nil {
		return nil, err
	}
	
	findings := []models.Finding{}
	
	hasMetricFilter := false
	for _, filter := range filters.MetricFilters {
		if filter.FilterPattern != nil {
			hasMetricFilter = true
			break
		}
	}
	
	status := models.StatusFail
	msg := "No metric filter for CloudTrail configuration changes"
	
	if hasMetricFilter {
		status = models.StatusPass
		msg = "Metric filter configured"
	}
	
	findings = append(findings, models.Finding{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "cloudwatch", ResourceID: "metric-filter",
		FoundAt: time.Now().UTC(),
	})
	
	return findings, nil
}
