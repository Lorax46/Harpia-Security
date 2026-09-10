package slack

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type slackProvider interface {
	Slack(ctx context.Context) (interface{}, error)
}

// SecurityAlertsCheck - Security alerts are sent to Slack
type SecurityAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewSecurityAlertsCheck() *SecurityAlertsCheck {
	return &SecurityAlertsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_security_alerts",
			CheckTitle:      "Security alerts are sent to Slack",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Alert",
			Description:     "Security alerts are sent to Slack",
			RemediationText: "Review and remediate security alerts are sent to slack",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *SecurityAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecurityAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_security_alerts
	_ = findings
	return findings, nil
}

// IncidentChannelCheck - Incident response channel is configured
type IncidentChannelCheck struct {
	metadata models.CheckMetadata
}

func NewIncidentChannelCheck() *IncidentChannelCheck {
	return &IncidentChannelCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_incident_channel",
			CheckTitle:      "Incident response channel is configured",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Channel",
			Description:     "Incident response channel is configured",
			RemediationText: "Review and remediate incident response channel is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *IncidentChannelCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IncidentChannelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_incident_channel
	_ = findings
	return findings, nil
}

// ComplianceNotificationsCheck - Compliance notifications are sent
type ComplianceNotificationsCheck struct {
	metadata models.CheckMetadata
}

func NewComplianceNotificationsCheck() *ComplianceNotificationsCheck {
	return &ComplianceNotificationsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_compliance_notifications",
			CheckTitle:      "Compliance notifications are sent",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Notification",
			Description:     "Compliance notifications are sent",
			RemediationText: "Review and remediate compliance notifications are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ComplianceNotificationsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ComplianceNotificationsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_compliance_notifications
	_ = findings
	return findings, nil
}

// VulnAlertsCheck - Vulnerability alerts are sent
type VulnAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewVulnAlertsCheck() *VulnAlertsCheck {
	return &VulnAlertsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_vuln_alerts",
			CheckTitle:      "Vulnerability alerts are sent",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Alert",
			Description:     "Vulnerability alerts are sent",
			RemediationText: "Review and remediate vulnerability alerts are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *VulnAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *VulnAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_vuln_alerts
	_ = findings
	return findings, nil
}

// AuditLogIntegrationCheck - Audit logs are sent to Slack
type AuditLogIntegrationCheck struct {
	metadata models.CheckMetadata
}

func NewAuditLogIntegrationCheck() *AuditLogIntegrationCheck {
	return &AuditLogIntegrationCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_audit_log_integration",
			CheckTitle:      "Audit logs are sent to Slack",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Log",
			Description:     "Audit logs are sent to Slack",
			RemediationText: "Review and remediate audit logs are sent to slack",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *AuditLogIntegrationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AuditLogIntegrationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_audit_log_integration
	_ = findings
	return findings, nil
}

// ApprovalWorkflowsCheck - Approval workflows use Slack
type ApprovalWorkflowsCheck struct {
	metadata models.CheckMetadata
}

func NewApprovalWorkflowsCheck() *ApprovalWorkflowsCheck {
	return &ApprovalWorkflowsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_approval_workflows",
			CheckTitle:      "Approval workflows use Slack",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Workflow",
			Description:     "Approval workflows use Slack",
			RemediationText: "Review and remediate approval workflows use slack",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ApprovalWorkflowsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ApprovalWorkflowsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_approval_workflows
	_ = findings
	return findings, nil
}

// OncallNotificationsCheck - On-call notifications are configured
type OncallNotificationsCheck struct {
	metadata models.CheckMetadata
}

func NewOncallNotificationsCheck() *OncallNotificationsCheck {
	return &OncallNotificationsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_oncall_notifications",
			CheckTitle:      "On-call notifications are configured",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "OnCall",
			Description:     "On-call notifications are configured",
			RemediationText: "Review and remediate on-call notifications are configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *OncallNotificationsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OncallNotificationsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_oncall_notifications
	_ = findings
	return findings, nil
}

// RunbookAutomationCheck - Runbook automation uses Slack
type RunbookAutomationCheck struct {
	metadata models.CheckMetadata
}

func NewRunbookAutomationCheck() *RunbookAutomationCheck {
	return &RunbookAutomationCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_runbook_automation",
			CheckTitle:      "Runbook automation uses Slack",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Runbook",
			Description:     "Runbook automation uses Slack",
			RemediationText: "Review and remediate runbook automation uses slack",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *RunbookAutomationCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RunbookAutomationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_runbook_automation
	_ = findings
	return findings, nil
}

// PostureAlertsCheck - Posture alerts are sent
type PostureAlertsCheck struct {
	metadata models.CheckMetadata
}

func NewPostureAlertsCheck() *PostureAlertsCheck {
	return &PostureAlertsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_posture_alerts",
			CheckTitle:      "Posture alerts are sent",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Alert",
			Description:     "Posture alerts are sent",
			RemediationText: "Review and remediate posture alerts are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *PostureAlertsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PostureAlertsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_posture_alerts
	_ = findings
	return findings, nil
}

// DrillNotificationsCheck - Drill notifications are sent
type DrillNotificationsCheck struct {
	metadata models.CheckMetadata
}

func NewDrillNotificationsCheck() *DrillNotificationsCheck {
	return &DrillNotificationsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_drill_notifications",
			CheckTitle:      "Drill notifications are sent",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Drill",
			Description:     "Drill notifications are sent",
			RemediationText: "Review and remediate drill notifications are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *DrillNotificationsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DrillNotificationsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_drill_notifications
	_ = findings
	return findings, nil
}

// ExecutiveSummaryCheck - Executive summaries are sent
type ExecutiveSummaryCheck struct {
	metadata models.CheckMetadata
}

func NewExecutiveSummaryCheck() *ExecutiveSummaryCheck {
	return &ExecutiveSummaryCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_executive_summary",
			CheckTitle:      "Executive summaries are sent",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Report",
			Description:     "Executive summaries are sent",
			RemediationText: "Review and remediate executive summaries are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ExecutiveSummaryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ExecutiveSummaryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_executive_summary
	_ = findings
	return findings, nil
}

// DailyDigestCheck - Daily digest is configured
type DailyDigestCheck struct {
	metadata models.CheckMetadata
}

func NewDailyDigestCheck() *DailyDigestCheck {
	return &DailyDigestCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_daily_digest",
			CheckTitle:      "Daily digest is configured",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Digest",
			Description:     "Daily digest is configured",
			RemediationText: "Review and remediate daily digest is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *DailyDigestCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DailyDigestCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_daily_digest
	_ = findings
	return findings, nil
}

// WeeklyReportCheck - Weekly reports are sent
type WeeklyReportCheck struct {
	metadata models.CheckMetadata
}

func NewWeeklyReportCheck() *WeeklyReportCheck {
	return &WeeklyReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_weekly_report",
			CheckTitle:      "Weekly reports are sent",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Report",
			Description:     "Weekly reports are sent",
			RemediationText: "Review and remediate weekly reports are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *WeeklyReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WeeklyReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_weekly_report
	_ = findings
	return findings, nil
}

// MonthlyReportCheck - Monthly reports are sent
type MonthlyReportCheck struct {
	metadata models.CheckMetadata
}

func NewMonthlyReportCheck() *MonthlyReportCheck {
	return &MonthlyReportCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_monthly_report",
			CheckTitle:      "Monthly reports are sent",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Report",
			Description:     "Monthly reports are sent",
			RemediationText: "Review and remediate monthly reports are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *MonthlyReportCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *MonthlyReportCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_monthly_report
	_ = findings
	return findings, nil
}

// QuarterlyReviewCheck - Quarterly reviews are sent
type QuarterlyReviewCheck struct {
	metadata models.CheckMetadata
}

func NewQuarterlyReviewCheck() *QuarterlyReviewCheck {
	return &QuarterlyReviewCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_quarterly_review",
			CheckTitle:      "Quarterly reviews are sent",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Review",
			Description:     "Quarterly reviews are sent",
			RemediationText: "Review and remediate quarterly reviews are sent",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *QuarterlyReviewCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *QuarterlyReviewCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_quarterly_review
	_ = findings
	return findings, nil
}

// BotSecurityCheck - Slack bot security is configured
type BotSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewBotSecurityCheck() *BotSecurityCheck {
	return &BotSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_bot_security",
			CheckTitle:      "Slack bot security is configured",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Bot",
			Description:     "Slack bot security is configured",
			RemediationText: "Review and remediate slack bot security is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *BotSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *BotSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_bot_security
	_ = findings
	return findings, nil
}

// OauthSecurityCheck - Slack OAuth security is enforced
type OauthSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewOauthSecurityCheck() *OauthSecurityCheck {
	return &OauthSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_oauth_security",
			CheckTitle:      "Slack OAuth security is enforced",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "OAuth",
			Description:     "Slack OAuth security is enforced",
			RemediationText: "Review and remediate slack oauth security is enforced",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *OauthSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *OauthSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_oauth_security
	_ = findings
	return findings, nil
}

// WebhookSecurityCheck - Slack webhook security is enforced
type WebhookSecurityCheck struct {
	metadata models.CheckMetadata
}

func NewWebhookSecurityCheck() *WebhookSecurityCheck {
	return &WebhookSecurityCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_webhook_security",
			CheckTitle:      "Slack webhook security is enforced",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "Webhook",
			Description:     "Slack webhook security is enforced",
			RemediationText: "Review and remediate slack webhook security is enforced",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *WebhookSecurityCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WebhookSecurityCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_webhook_security
	_ = findings
	return findings, nil
}

// ChannelArchivingCheck - Channel archiving is configured
type ChannelArchivingCheck struct {
	metadata models.CheckMetadata
}

func NewChannelArchivingCheck() *ChannelArchivingCheck {
	return &ChannelArchivingCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_channel_archiving",
			CheckTitle:      "Channel archiving is configured",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Channel",
			Description:     "Channel archiving is configured",
			RemediationText: "Review and remediate channel archiving is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ChannelArchivingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ChannelArchivingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_channel_archiving
	_ = findings
	return findings, nil
}

// FileSharingCheck - File sharing is restricted
type FileSharingCheck struct {
	metadata models.CheckMetadata
}

func NewFileSharingCheck() *FileSharingCheck {
	return &FileSharingCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_file_sharing",
			CheckTitle:      "File sharing is restricted",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "File",
			Description:     "File sharing is restricted",
			RemediationText: "Review and remediate file sharing is restricted",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *FileSharingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *FileSharingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_file_sharing
	_ = findings
	return findings, nil
}

// GuestAccessCheck - Guest access is restricted
type GuestAccessCheck struct {
	metadata models.CheckMetadata
}

func NewGuestAccessCheck() *GuestAccessCheck {
	return &GuestAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_guest_access",
			CheckTitle:      "Guest access is restricted",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Guest",
			Description:     "Guest access is restricted",
			RemediationText: "Review and remediate guest access is restricted",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *GuestAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GuestAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_guest_access
	_ = findings
	return findings, nil
}

// DataRetentionCheck - Data retention is configured
type DataRetentionCheck struct {
	metadata models.CheckMetadata
}

func NewDataRetentionCheck() *DataRetentionCheck {
	return &DataRetentionCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_data_retention",
			CheckTitle:      "Data retention is configured",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Retention",
			Description:     "Data retention is configured",
			RemediationText: "Review and remediate data retention is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *DataRetentionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DataRetentionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_data_retention
	_ = findings
	return findings, nil
}

// EkmCheck - Enterprise key management is enabled
type EkmCheck struct {
	metadata models.CheckMetadata
}

func NewEkmCheck() *EkmCheck {
	return &EkmCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_ekm",
			CheckTitle:      "Enterprise key management is enabled",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "EKM",
			Description:     "Enterprise key management is enabled",
			RemediationText: "Review and remediate enterprise key management is enabled",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *EkmCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EkmCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_ekm
	_ = findings
	return findings, nil
}

// DlpCheck - DLP integration is configured
type DlpCheck struct {
	metadata models.CheckMetadata
}

func NewDlpCheck() *DlpCheck {
	return &DlpCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_dlp",
			CheckTitle:      "DLP integration is configured",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "DLP",
			Description:     "DLP integration is configured",
			RemediationText: "Review and remediate dlp integration is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *DlpCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DlpCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_dlp
	_ = findings
	return findings, nil
}

// EDiscoveryCheck - eDiscovery is configured
type EDiscoveryCheck struct {
	metadata models.CheckMetadata
}

func NewEDiscoveryCheck() *EDiscoveryCheck {
	return &EDiscoveryCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_e_discovery",
			CheckTitle:      "eDiscovery is configured",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "EDiscovery",
			Description:     "eDiscovery is configured",
			RemediationText: "Review and remediate ediscovery is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *EDiscoveryCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *EDiscoveryCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_e_discovery
	_ = findings
	return findings, nil
}

// SsoCheck - SSO is configured
type SsoCheck struct {
	metadata models.CheckMetadata
}

func NewSsoCheck() *SsoCheck {
	return &SsoCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_sso",
			CheckTitle:      "SSO is configured",
			ServiceName:     "slack",
			Severity:        "high",
			ResourceType:    "SSO",
			Description:     "SSO is configured",
			RemediationText: "Review and remediate sso is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *SsoCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *SsoCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_sso
	_ = findings
	return findings, nil
}

// ScimCheck - SCIM provisioning is configured
type ScimCheck struct {
	metadata models.CheckMetadata
}

func NewScimCheck() *ScimCheck {
	return &ScimCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_scim",
			CheckTitle:      "SCIM provisioning is configured",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "SCIM",
			Description:     "SCIM provisioning is configured",
			RemediationText: "Review and remediate scim provisioning is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ScimCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ScimCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_scim
	_ = findings
	return findings, nil
}

// WorkflowsCheck - Workflows are secure
type WorkflowsCheck struct {
	metadata models.CheckMetadata
}

func NewWorkflowsCheck() *WorkflowsCheck {
	return &WorkflowsCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_workflows",
			CheckTitle:      "Workflows are secure",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Workflow",
			Description:     "Workflows are secure",
			RemediationText: "Review and remediate workflows are secure",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *WorkflowsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *WorkflowsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_workflows
	_ = findings
	return findings, nil
}

// CanvasCheck - Canvas security is configured
type CanvasCheck struct {
	metadata models.CheckMetadata
}

func NewCanvasCheck() *CanvasCheck {
	return &CanvasCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_canvas",
			CheckTitle:      "Canvas security is configured",
			ServiceName:     "slack",
			Severity:        "low",
			ResourceType:    "Canvas",
			Description:     "Canvas security is configured",
			RemediationText: "Review and remediate canvas security is configured",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *CanvasCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CanvasCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_canvas
	_ = findings
	return findings, nil
}

// ConnectCheck - Slack Connect is secure
type ConnectCheck struct {
	metadata models.CheckMetadata
}

func NewConnectCheck() *ConnectCheck {
	return &ConnectCheck{
		metadata: models.CheckMetadata{
			Provider:        "slack",
			CheckID:         "slack_connect",
			CheckTitle:      "Slack Connect is secure",
			ServiceName:     "slack",
			Severity:        "medium",
			ResourceType:    "Connect",
			Description:     "Slack Connect is secure",
			RemediationText: "Review and remediate slack connect is secure",
			Categories:      []string{"slack", "security"},
		},
	}
}

func (c *ConnectCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConnectCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(slackProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement slackProvider")
	}
	client, err := p.Slack(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	_ = client

	// TODO: implement slack_connect
	_ = findings
	return findings, nil
}
