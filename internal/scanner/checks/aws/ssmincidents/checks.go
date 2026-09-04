package ssmincidents

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SsmincidentsEnabledWithPlans - SSM Incidents replication set is ACTIVE and has at least one response plan
type SsmincidentsEnabledWithPlans struct {
    metadata models.CheckMetadata
}

func NewSsmincidentsEnabledWithPlans() *SsmincidentsEnabledWithPlans {
    return &SsmincidentsEnabledWithPlans{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ssmincidents_enabled_with_plans",
            CheckTitle: "SSM Incidents replication set is ACTIVE and has at least one response plan",
            ServiceName: "ssmincidents",
            Severity: "medium",
            Description: "**Incident Manager** uses a **replication set** and **response plans**. This evaluates whether a replication set exists and is `ACTIVE`, and that at least one response plan is configured for coordinated incident handling.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ssmincidents"},
        },
    }
}

func (c *SsmincidentsEnabledWithPlans) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SsmincidentsEnabledWithPlans) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ssmincidents",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

