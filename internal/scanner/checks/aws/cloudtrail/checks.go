package cloudtrail

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type cloudtrailProvider interface {
	CloudTrail(ctx context.Context) (*cloudtrail.Client, error)
}

// LoggingCheck - verifica se CloudTrail está habilitado
type LoggingCheck struct {
	metadata models.CheckMetadata
}

func NewLoggingCheck() *LoggingCheck {
	return &LoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_logging_enabled",
			CheckTitle:      "CloudTrail logging should be enabled",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "Trail",
			Description:     "CloudTrail logging should be enabled",
			RemediationText: "Enable CloudTrail logging",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *LoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	if len(trails.TrailList) == 0 {
		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          models.StatusFail,
			StatusExtended:  "No CloudTrail trails configured",
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      "cloudtrail",
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
		return findings, nil
	}

	for _, trail := range trails.TrailList {
		isLogging := false
		if trail.Name != nil {
			status, err := ctClient.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
				Name: trail.Name,
			})
			if err == nil && status != nil {
				isLogging = aws.ToBool(status.IsLogging)
			}
		}

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is logging", aws.ToString(trail.Name))
		if !isLogging {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not logging", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// MultiRegionCheck - verifica se CloudTrail é multi-região
type MultiRegionCheck struct {
	metadata models.CheckMetadata
}

func NewMultiRegionCheck() *MultiRegionCheck {
	return &MultiRegionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_multi_region",
			CheckTitle:      "CloudTrail should be multi-region",
			ServiceName:     "cloudtrail",
			Severity:        "high",
			ResourceType:    "Trail",
			Description:     "CloudTrail should capture events from all regions",
			RemediationText: "Enable multi-region on CloudTrail",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *MultiRegionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiRegionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		isMultiRegion := aws.ToBool(trail.IsMultiRegionTrail)

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is multi-region", aws.ToString(trail.Name))
		if !isMultiRegion {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not multi-region", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// LogFileValidationCheck - verifica validação de log
type LogFileValidationCheck struct {
	metadata models.CheckMetadata
}

func NewLogFileValidationCheck() *LogFileValidationCheck {
	return &LogFileValidationCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_log_file_validation",
			CheckTitle:      "CloudTrail log file validation should be enabled",
			ServiceName:     "cloudtrail",
			Severity:        "high",
			ResourceType:    "Trail",
			Description:     "CloudTrail log file validation should be enabled",
			RemediationText: "Enable CloudTrail log file validation",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *LogFileValidationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *LogFileValidationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasValidation := aws.ToBool(trail.LogFileValidationEnabled)

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s has log file validation enabled", aws.ToString(trail.Name))
		if !hasValidation {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s does not have log file validation enabled", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// EncryptionCheck - verifica criptografia
type EncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewEncryptionCheck() *EncryptionCheck {
	return &EncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_encryption",
			CheckTitle:      "CloudTrail should use encryption",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "Trail",
			Description:     "CloudTrail logs should be encrypted",
			RemediationText: "Enable CloudTrail encryption",
			Categories:      []string{"cloudtrail", "encryption"},
		},
	}
}

func (c *EncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasEncryption := trail.KmsKeyId != nil && *trail.KmsKeyId != ""

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s uses encryption", aws.ToString(trail.Name))
		if !hasEncryption {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s does not use encryption", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// CloudWatchLogsCheck - verifica integração com CloudWatch Logs
type CloudWatchLogsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudWatchLogsCheck() *CloudWatchLogsCheck {
	return &CloudWatchLogsCheck{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_cloudwatch_logs",
			CheckTitle:      "CloudTrail should be integrated with CloudWatch Logs",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "Trail",
			Description:     "CloudTrail should be integrated with CloudWatch Logs",
			RemediationText: "Enable CloudWatch Logs integration",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *CloudWatchLogsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudWatchLogsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	ctClient, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	trails, err := ctClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("falha ao descrever trails: %w", err)
	}

	for _, trail := range trails.TrailList {
		hasCloudWatch := trail.CloudWatchLogsLogGroupArn != nil && *trail.CloudWatchLogsLogGroupArn != ""

		status := models.StatusPass
		ext := fmt.Sprintf("CloudTrail %s is integrated with CloudWatch Logs", aws.ToString(trail.Name))
		if !hasCloudWatch {
			status = models.StatusFail
			ext = fmt.Sprintf("CloudTrail %s is not integrated with CloudWatch Logs", aws.ToString(trail.Name))
		}

		findings = append(findings, models.Finding{
			ID:              c.metadata.CheckID,
			Title:           c.metadata.CheckTitle,
			Description:     c.metadata.Description,
			Severity:        c.metadata.Severity,
			Status:          status,
			StatusExtended:  ext,
			Provider:        "aws",
			Service:         "cloudtrail",
			ResourceID:      aws.ToString(trail.Name),
			Remediation:     c.metadata.RemediationText,
			Categories:      c.metadata.Categories,
			FoundAt:         time.Now(),
		})
	}

	return findings, nil
}

// ThreatDetectionPrivilegeEscalation - No potential privilege escalation activity detected in CloudTrail
type ThreatDetectionPrivilegeEscalation struct {
	metadata models.CheckMetadata
}

func NewThreatDetectionPrivilegeEscalation() *ThreatDetectionPrivilegeEscalation {
	return &ThreatDetectionPrivilegeEscalation{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_threat_detection_privilege_escalation",
			CheckTitle:      "No potential privilege escalation activity detected in CloudTrail",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail** activity is analyzed for **identities** executing high-risk actions linked to **privilege escalation** (e.g., `Attach*Policy`, `PassRole`, `AssumeRole`, `CreateAccessKey`). Identities exceeding a configurable share of such events within a *recent time window* are highlighted for investigation.",
			RemediationText: "Apply **least privilege** and **defense in depth**: - Restrict `PassRole`, `Attach*Policy`, `UpdateAssumeRolePolicy`, `CreateAccessKey` - Enforce permission boundaries and SCPs - Require MFA and change approvals - Use multi-Region CloudTrail, immutable retention, and alerting on anomalous sequences",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *ThreatDetectionPrivilegeEscalation) Metadata() models.CheckMetadata { return c.metadata }

func (c *ThreatDetectionPrivilegeEscalation) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_threat_detection_privilege_escalation
	_ = client

	return findings, nil
}

// S3DataeventsReadEnabled - CloudTrail trail records S3 object-level read events for all S3 buckets
type S3DataeventsReadEnabled struct {
	metadata models.CheckMetadata
}

func NewS3DataeventsReadEnabled() *S3DataeventsReadEnabled {
	return &S3DataeventsReadEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_s3_dataevents_read_enabled",
			CheckTitle:      "CloudTrail trail records S3 object-level read events for all S3 buckets",
			ServiceName:     "cloudtrail",
			Severity:        "low",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail trails** log **S3 object-level read data events** for all buckets, capturing object access (for example `GetObject`) via selectors targeting `AWS::S3::Object`",
			RemediationText: "Enable CloudTrail **data events** for S3 objects with `ReadOnly` (or `All`) across all current and future buckets. Use a multi-Region trail, centralize logs in an encrypted bucket with lifecycle retention, and integrate monitoring/alerts to support **defense in depth** and accountable access.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *S3DataeventsReadEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3DataeventsReadEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_s3_dataevents_read_enabled
	_ = client

	return findings, nil
}

// LogsS3BucketIsNotPubliclyAccessible - CloudTrail trail S3 bucket is not publicly accessible
type LogsS3BucketIsNotPubliclyAccessible struct {
	metadata models.CheckMetadata
}

func NewLogsS3BucketIsNotPubliclyAccessible() *LogsS3BucketIsNotPubliclyAccessible {
	return &LogsS3BucketIsNotPubliclyAccessible{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
			CheckTitle:      "CloudTrail trail S3 bucket is not publicly accessible",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "AwsS3Bucket",
			Description:     "CloudTrail log destination **S3 buckets** are inspected for ACL grants that expose data to the public `AllUsers` group. Buckets hosted in other accounts are flagged for out-of-scope review.",
			RemediationText: "Apply **least privilege** to the log bucket: - Enable S3 `Block Public Access` (account and bucket) - Remove `AllUsers`/`AuthenticatedUsers` ACLs; avoid wildcard principals - Permit only CloudTrail and constrain with `aws:SourceArn` Use a dedicated private bucket and monitor for permission changes.",
			Categories:      []string{"cloudtrail", "public_access"},
		},
	}
}

func (c *LogsS3BucketIsNotPubliclyAccessible) Metadata() models.CheckMetadata { return c.metadata }

func (c *LogsS3BucketIsNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_logs_s3_bucket_is_not_publicly_accessible
	_ = client

	return findings, nil
}

// CloudwatchLoggingEnabled - CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours
type CloudwatchLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewCloudwatchLoggingEnabled() *CloudwatchLoggingEnabled {
	return &CloudwatchLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_cloudwatch_logging_enabled",
			CheckTitle:      "CloudTrail trail has delivered logs to CloudWatch Logs in the last 24 hours",
			ServiceName:     "cloudtrail",
			Severity:        "low",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail trails** are configured to send events to **CloudWatch Logs**, and show recent delivery within the last `24h`. Trails without integration or without recent CloudWatch delivery are identified, across single-Region and multi-Region trails.",
			RemediationText: "Integrate every trail with **CloudWatch Logs** and maintain continuous, near-real-time delivery. Enforce **least privilege** on the delivery role, prefer **multi-Region** coverage, and implement **metric filters and alerts** for sensitive actions. Centralize retention to support **defense in depth**.",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *CloudwatchLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudwatchLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_cloudwatch_logging_enabled
	_ = client

	return findings, nil
}

// InsightsExist - CloudTrail trail has Insights enabled
type InsightsExist struct {
	metadata models.CheckMetadata
}

func NewInsightsExist() *InsightsExist {
	return &InsightsExist{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_insights_exist",
			CheckTitle:      "CloudTrail trail has Insights enabled",
			ServiceName:     "cloudtrail",
			Severity:        "low",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail trails** that are logging are evaluated for **Insights** via `insight selectors`, which enable anomaly detection on management-event patterns (API call and error rates). The finding pinpoints logging trails where these selectors are missing.",
			RemediationText: "Enable **CloudTrail Insights** on all logging trails (ideally all-Region or organization trails). Activate both `ApiCallRateInsight` and `ApiErrorRateInsight`. Integrate alerts with monitoring and review anomalies regularly. Apply **defense in depth** and least privilege to reduce potential blast radius.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *InsightsExist) Metadata() models.CheckMetadata { return c.metadata }

func (c *InsightsExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_insights_exist
	_ = client

	return findings, nil
}

// ThreatDetectionLlmJacking - No potential LLM jacking activity detected in CloudTrail
type ThreatDetectionLlmJacking struct {
	metadata models.CheckMetadata
}

func NewThreatDetectionLlmJacking() *ThreatDetectionLlmJacking {
	return &ThreatDetectionLlmJacking{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_threat_detection_llm_jacking",
			CheckTitle:      "No potential LLM jacking activity detected in CloudTrail",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail Bedrock activity** is analyzed per identity for a high diversity of LLM-related API calls (e.g., `InvokeModel`, `InvokeModelWithResponseStream`, `GetFoundationModelAvailability`). *If an identity's share of these actions exceeds a configured threshold over a recent window*, it is surfaced as potential **LLM-jacking** behavior.",
			RemediationText: "Apply **least privilege** to Bedrock; restrict `Invoke*` only to required roles and deny broadly via **SCPs** where unused. Enforce **MFA** and short-lived creds; rotate/remove exposed keys. Enable **model invocation logging** and budgets/quotas. Continuously monitor for Bedrock enumeration plus invoke bursts. Use **defense in depth** across identities and networks.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *ThreatDetectionLlmJacking) Metadata() models.CheckMetadata { return c.metadata }

func (c *ThreatDetectionLlmJacking) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_threat_detection_llm_jacking
	_ = client

	return findings, nil
}

// LogsS3BucketAccessLoggingEnabled - CloudTrail trail destination S3 bucket has access logging enabled
type LogsS3BucketAccessLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewLogsS3BucketAccessLoggingEnabled() *LogsS3BucketAccessLoggingEnabled {
	return &LogsS3BucketAccessLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_logs_s3_bucket_access_logging_enabled",
			CheckTitle:      "CloudTrail trail destination S3 bucket has access logging enabled",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "CloudTrail trails deliver logs to an S3 bucket; this evaluates whether that bucket has **S3 server access logging** enabled to record requests against it. *If the destination bucket is outside the account or audit scope, a manual review is indicated.*",
			RemediationText: "Enable **S3 server access logging** on the CloudTrail logs bucket and write logs to a separate, tightly controlled bucket. Apply **least privilege**, enable **versioning**, and consider **Object Lock** to deter tampering. Centralize monitoring to support defense-in-depth and rapid investigation.",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *LogsS3BucketAccessLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *LogsS3BucketAccessLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_logs_s3_bucket_access_logging_enabled
	_ = client

	return findings, nil
}

// ThreatDetectionEnumeration - CloudTrail logs show no potential enumeration activity
type ThreatDetectionEnumeration struct {
	metadata models.CheckMetadata
}

func NewThreatDetectionEnumeration() *ThreatDetectionEnumeration {
	return &ThreatDetectionEnumeration{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_threat_detection_enumeration",
			CheckTitle:      "CloudTrail logs show no potential enumeration activity",
			ServiceName:     "cloudtrail",
			Severity:        "critical",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail activity** is analyzed for AWS identities executing a broad mix of discovery APIs like `List*`, `Describe*`, and `Get*` within a recent time window. An identity exceeding a configurable ratio of these actions indicates potential enumeration behavior by that principal.",
			RemediationText: "Apply **least privilege** to limit `List*`/`Describe*`/`Get*` to necessary resources and roles; use **separation of duties**. - Enforce MFA and short-lived sessions - Use **SCPs** to curb unnecessary discovery - Baseline expected reads and alert on spikes as **defense in depth**",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *ThreatDetectionEnumeration) Metadata() models.CheckMetadata { return c.metadata }

func (c *ThreatDetectionEnumeration) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_threat_detection_enumeration
	_ = client

	return findings, nil
}

// LogFileValidationEnabled - CloudTrail trail has log file validation enabled
type LogFileValidationEnabled struct {
	metadata models.CheckMetadata
}

func NewLogFileValidationEnabled() *LogFileValidationEnabled {
	return &LogFileValidationEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_log_file_validation_enabled",
			CheckTitle:      "CloudTrail trail has log file validation enabled",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**AWS CloudTrail trails** are evaluated for **log file integrity validation** being enabled (`LogFileValidationEnabled`). When enabled, CloudTrail generates signed digest files to verify that S3-delivered log files remain unchanged.",
			RemediationText: "Enable **log file integrity validation** on all trails (`LogFileValidationEnabled=true`). Enforce **least privilege** on the logs bucket, retain and protect digest files (e.g., S3 Object Lock/MFA Delete), and monitor validation results to support **defense in depth**.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *LogFileValidationEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *LogFileValidationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_log_file_validation_enabled
	_ = client

	return findings, nil
}

// BucketRequiresMfaDelete - CloudTrail trail S3 bucket has MFA delete enabled
type BucketRequiresMfaDelete struct {
	metadata models.CheckMetadata
}

func NewBucketRequiresMfaDelete() *BucketRequiresMfaDelete {
	return &BucketRequiresMfaDelete{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_bucket_requires_mfa_delete",
			CheckTitle:      "CloudTrail trail S3 bucket has MFA delete enabled",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail log buckets** for actively logging trails are evaluated for **MFA Delete** on the associated S3 bucket. The assessment determines whether `MFA Delete` is configured on the in-account log bucket; *if the bucket resides in another account, its configuration should be verified separately*.",
			RemediationText: "Enable `MFA Delete` on the CloudTrail log bucket with versioning enabled. Enforce **least privilege** so only tightly controlled identities can delete or alter logs, and require MFA for such actions. Apply **defense in depth** using a dedicated logging account and log file integrity validation.",
			Categories:      []string{"cloudtrail", "iam"},
		},
	}
}

func (c *BucketRequiresMfaDelete) Metadata() models.CheckMetadata { return c.metadata }

func (c *BucketRequiresMfaDelete) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_bucket_requires_mfa_delete
	_ = client

	return findings, nil
}

// S3DataeventsWriteEnabled - CloudTrail trail records all S3 object-level API operations for all buckets
type S3DataeventsWriteEnabled struct {
	metadata models.CheckMetadata
}

func NewS3DataeventsWriteEnabled() *S3DataeventsWriteEnabled {
	return &S3DataeventsWriteEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_s3_dataevents_write_enabled",
			CheckTitle:      "CloudTrail trail records all S3 object-level API operations for all buckets",
			ServiceName:     "cloudtrail",
			Severity:        "low",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail trails** include **S3 object-level data events** for **write (or all) operations** across **all current and future buckets**, via classic or advanced selectors. This records actions like `PutObject`, `DeleteObject`, and multipart uploads at the object level.",
			RemediationText: "Enable **CloudTrail S3 data events** for object-level **write** (and *optionally* read) across all buckets on a multi-Region trail. Apply **least privilege** to log storage, set **lifecycle** retention, and integrate alerts. Use **advanced selectors** to target sensitive buckets/operations for cost control and **defense in depth**.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *S3DataeventsWriteEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *S3DataeventsWriteEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_s3_dataevents_write_enabled
	_ = client

	return findings, nil
}

// BedrockLoggingEnabled - CloudTrail logs Amazon Bedrock API calls for security auditing
type BedrockLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewBedrockLoggingEnabled() *BedrockLoggingEnabled {
	return &BedrockLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_bedrock_logging_enabled",
			CheckTitle:      "CloudTrail logs Amazon Bedrock API calls for security auditing",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**At least one actively logging CloudTrail trail** records **Amazon Bedrock API activity** through management events or advanced event selectors targeting Bedrock resources. This check covers **control-plane** operations such as configuration changes through CloudTrail management events and can also cover **data-plane** Bedrock events when advanced event selectors target Bedrock resource types.",
			RemediationText: "Enable CloudTrail logging for Amazon Bedrock on **at least one actively logging trail**. At minimum, enable **management events** to capture Bedrock control-plane operations. For invocation-level and other data-plane visibility, add **advanced event selectors** targeting Bedrock resource types or pair this control with `bedrock_model_invocation_logging_enabled`. For broader region coverage, pair this control with a separate multi-region CloudTrail check. Centralize logs in an encrypted bucket or CloudWatch Logs to support **defense in depth** and forensic readiness for AI workloads.",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *BedrockLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *BedrockLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_bedrock_logging_enabled
	_ = client

	return findings, nil
}

// MultiRegionEnabledLoggingManagementEvents - CloudTrail trail logs management events for read and write operations
type MultiRegionEnabledLoggingManagementEvents struct {
	metadata models.CheckMetadata
}

func NewMultiRegionEnabledLoggingManagementEvents() *MultiRegionEnabledLoggingManagementEvents {
	return &MultiRegionEnabledLoggingManagementEvents{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_multi_region_enabled_logging_management_events",
			CheckTitle:      "CloudTrail trail logs management events for read and write operations",
			ServiceName:     "cloudtrail",
			Severity:        "low",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**CloudTrail trails** record **management events** (`read` and `write`) in every AWS region and are actively logging, using a multi-region trail or per-region coverage.",
			RemediationText: "Enable a **multi-region CloudTrail** that logs **management events** for `read` and `write` in all regions. Centralize logs in a separate, locked-down account; apply **least privilege**, encryption, retention, and integrity validation; and protect trails and storage with tamper-evident, deny-delete controls for **defense-in-depth**.",
			Categories:      []string{"cloudtrail", "logging"},
		},
	}
}

func (c *MultiRegionEnabledLoggingManagementEvents) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiRegionEnabledLoggingManagementEvents) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_multi_region_enabled_logging_management_events
	_ = client

	return findings, nil
}

// KmsEncryptionEnabled - CloudTrail trail logs are encrypted at rest with a KMS key
type KmsEncryptionEnabled struct {
	metadata models.CheckMetadata
}

func NewKmsEncryptionEnabled() *KmsEncryptionEnabled {
	return &KmsEncryptionEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_kms_encryption_enabled",
			CheckTitle:      "CloudTrail trail logs are encrypted at rest with a KMS key",
			ServiceName:     "cloudtrail",
			Severity:        "medium",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**AWS CloudTrail trails** are evaluated for use of **SSE-KMS** with a customer-managed KMS key to encrypt delivered log files at rest in S3. Trails without a configured KMS key are identified. *Applies to single-Region and multi-Region trails.*",
			RemediationText: "Enable **SSE-KMS** on every trail using a **customer-managed KMS key**. Apply **least privilege** so only authorized roles can `Decrypt`, and enforce **separation of duties** between key admins and log readers. Rotate keys and monitor key usage to provide **defense in depth** for CloudTrail data.",
			Categories:      []string{"cloudtrail", "encryption"},
		},
	}
}

func (c *KmsEncryptionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *KmsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_kms_encryption_enabled
	_ = client

	return findings, nil
}

// MultiRegionEnabled - Region has at least one CloudTrail trail logging
type MultiRegionEnabled struct {
	metadata models.CheckMetadata
}

func NewMultiRegionEnabled() *MultiRegionEnabled {
	return &MultiRegionEnabled{
		metadata: models.CheckMetadata{
			Provider:        "aws",
			CheckID:         "cloudtrail_multi_region_enabled",
			CheckTitle:      "Region has at least one CloudTrail trail logging",
			ServiceName:     "cloudtrail",
			Severity:        "high",
			ResourceType:    "AwsCloudTrailTrail",
			Description:     "**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.",
			RemediationText: "Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones. Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.",
			Categories:      []string{"cloudtrail"},
		},
	}
}

func (c *MultiRegionEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *MultiRegionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudtrailProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudtrailProvider")
	}
	client, err := p.CloudTrail(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	// TODO: Implement check logic for cloudtrail_multi_region_enabled
	_ = client

	return findings, nil
}
