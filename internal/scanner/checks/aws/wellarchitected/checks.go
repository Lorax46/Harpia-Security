package wellarchitected

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// WellarchitectedWorkloadNoHighOrMediumRisks - AWS Well-Architected Tool workload has no high or medium risks
type WellarchitectedWorkloadNoHighOrMediumRisks struct {
    metadata models.CheckMetadata
}

func NewWellarchitectedWorkloadNoHighOrMediumRisks() *WellarchitectedWorkloadNoHighOrMediumRisks {
    return &WellarchitectedWorkloadNoHighOrMediumRisks{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "wellarchitected_workload_no_high_or_medium_risks",
            CheckTitle: "AWS Well-Architected Tool workload has no high or medium risks",
            ServiceName: "wellarchitected",
            Severity: "medium",
            Description: "**AWS Well-Architected workloads** are assessed for the presence and count of risks labeled `HIGH` or `MEDIUM` across the framework pillars. The result indicates whether any such risks remain recorded for the workload.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"wellarchitected"},
        },
    }
}

func (c *WellarchitectedWorkloadNoHighOrMediumRisks) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *WellarchitectedWorkloadNoHighOrMediumRisks) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "wellarchitected",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

