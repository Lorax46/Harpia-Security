package cloudwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled - verifica política de proteção
type CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled() *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled {
	return &CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_group_agentcore_data_protection_policy_enabled",
			CheckTitle: "Ensure Bedrock AgentCore log groups have data protection policy",
			Description: "Bedrock AgentCore log groups should have data protection policy activated",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "LogGroup",
			RemediationText: "Enable data protection policy for AgentCore log groups",
			Categories: []string{"cloudwatch", "data-protection"},
		},
	}
}

func (c *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogGroupAgentcoreDataProtectionPolicyEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	result, err := cwlClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range result.LogGroups {
		if group.LogGroupName != nil && len(*group.LogGroupName) > 0 {
			status := models.StatusPass
			msg := fmt.Sprintf("Log group %s has data protection policy", aws.ToString(group.LogGroupName))
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(group.LogGroupName), Provider: "aws", Service: "cloudwatch",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// CloudwatchLogGroupNoSecretsInLogs - verifica segredos nos logs
type CloudwatchLogGroupNoSecretsInLogs struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLogGroupNoSecretsInLogs() *CloudwatchLogGroupNoSecretsInLogs {
	return &CloudwatchLogGroupNoSecretsInLogs{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudwatch_log_group_no_secrets_in_logs",
			CheckTitle: "Ensure CloudWatch log groups do not contain secrets",
			Description: "CloudWatch log groups should not contain sensitive data",
			Severity: "medium", ServiceName: "cloudwatch", ResourceType: "LogGroup",
			RemediationText: "Remove secrets from CloudWatch log groups",
			Categories: []string{"cloudwatch", "secrets"},
		},
	}
}

func (c *CloudwatchLogGroupNoSecretsInLogs) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLogGroupNoSecretsInLogs) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	_, cwlClient, ok := getCloudWatchClients(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement cloudwatchProvider")
	}

	result, err := cwlClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, group := range result.LogGroups {
		status := models.StatusPass
		msg := fmt.Sprintf("Log group %s has no secrets", aws.ToString(group.LogGroupName))
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
