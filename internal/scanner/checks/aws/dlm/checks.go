package dlm

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type dlmProvider interface {
    DLM() (interface{}, error)
    Region() string
}

// DlmEbsSnapshotLifecyclePolicyExists - Region with EBS snapshots has at least one EBS snapshot lifecycle policy defined
type DlmEbsSnapshotLifecyclePolicyExists struct {
    metadata models.CheckMetadata
}

func NewDlmEbsSnapshotLifecyclePolicyExists() *DlmEbsSnapshotLifecyclePolicyExists {
    return &DlmEbsSnapshotLifecyclePolicyExists{
        metadata: models.CheckMetadata{
            Provider:    "aws",
            CheckID:     "dlm_ebs_snapshot_lifecycle_policy_exists",
            CheckTitle:  "Region with EBS snapshots has at least one EBS snapshot lifecycle policy defined",
            ServiceName: "dlm",
            Severity:    "medium",
            Description: "EBS snapshots are expected to be governed by Data Lifecycle Manager (DLM) policies in each Region where snapshots exist.",
            RemediationText: "Create a DLM lifecycle policy for EBS snapshots.",
            Categories:  []string{"dlm"},
        },
    }
}

func (c *DlmEbsSnapshotLifecyclePolicyExists) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *DlmEbsSnapshotLifecyclePolicyExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    p, ok := provider.(dlmProvider)
    if !ok {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Provider does not implement DLM interface",
            Provider: "aws", Service: "dlm", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    _, err := p.DLM()
    if err != nil {
        return []models.Finding{{
            ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
            Description: c.metadata.Description, Severity: c.metadata.Severity,
            Status: models.StatusInfo, StatusExtended: "Failed to create DLM client",
            Provider: "aws", Service: "dlm", Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories, FoundAt: time.Now(),
        }}, nil
    }

    return []models.Finding{{
        ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
        Description: c.metadata.Description, Severity: c.metadata.Severity,
        Status: models.StatusInfo, StatusExtended: "Requires real AWS credentials to list DLM lifecycle policies",
        Provider: "aws", Service: "dlm", Remediation: c.metadata.RemediationText,
        Categories: c.metadata.Categories, FoundAt: time.Now(),
    }}, nil
}
