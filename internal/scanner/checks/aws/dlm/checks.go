package dlm

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// DlmEbsSnapshotLifecyclePolicyExists - Region with EBS snapshots has at least one EBS snapshot lifecycle policy defined
type DlmEbsSnapshotLifecyclePolicyExists struct {
    metadata models.CheckMetadata
}

func NewDlmEbsSnapshotLifecyclePolicyExists() *DlmEbsSnapshotLifecyclePolicyExists {
    return &DlmEbsSnapshotLifecyclePolicyExists{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "dlm_ebs_snapshot_lifecycle_policy_exists",
            CheckTitle: "Region with EBS snapshots has at least one EBS snapshot lifecycle policy defined",
            ServiceName: "dlm",
            Severity: "medium",
            Description: "**EBS snapshots** are expected to be governed by **Data Lifecycle Manager (DLM) policies** in each Region where snapshots exist.  The evaluation looks for lifecycle policies that automate snapshot creation, retention, and cleanup for those snapshots.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"dlm"},
        },
    }
}

func (c *DlmEbsSnapshotLifecyclePolicyExists) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DlmEbsSnapshotLifecyclePolicyExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "dlm",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

