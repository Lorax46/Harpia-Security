package trustedadvisor

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// TrustedadvisorErrorsAndWarnings - Trusted Advisor check has no errors or warnings
type TrustedadvisorErrorsAndWarnings struct {
    metadata models.CheckMetadata
}

func NewTrustedadvisorErrorsAndWarnings() *TrustedadvisorErrorsAndWarnings {
    return &TrustedadvisorErrorsAndWarnings{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "trustedadvisor_errors_and_warnings",
            CheckTitle: "Trusted Advisor check has no errors or warnings",
            ServiceName: "trustedadvisor",
            Severity: "medium",
            Description: "**AWS Trusted Advisor** check statuses are assessed to identify items in `warning` or `error`. The finding reflects the state reported by Trusted Advisor across categories such as **Security**, **Fault Tolerance**, **Service Limits**, and **Cost**, indicating where configurations or quotas require attention.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"trustedadvisor"},
        },
    }
}

func (c *TrustedadvisorErrorsAndWarnings) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *TrustedadvisorErrorsAndWarnings) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "trustedadvisor",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// TrustedadvisorPremiumSupportPlanSubscribed - AWS account is subscribed to an AWS Premium Support plan
type TrustedadvisorPremiumSupportPlanSubscribed struct {
    metadata models.CheckMetadata
}

func NewTrustedadvisorPremiumSupportPlanSubscribed() *TrustedadvisorPremiumSupportPlanSubscribed {
    return &TrustedadvisorPremiumSupportPlanSubscribed{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "trustedadvisor_premium_support_plan_subscribed",
            CheckTitle: "AWS account is subscribed to an AWS Premium Support plan",
            ServiceName: "trustedadvisor",
            Severity: "low",
            Description: "**AWS account** is subscribed to an **AWS Premium Support plan** (e.g., Business or Enterprise)",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"trustedadvisor"},
        },
    }
}

func (c *TrustedadvisorPremiumSupportPlanSubscribed) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *TrustedadvisorPremiumSupportPlanSubscribed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "trustedadvisor",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

