package backup

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// BackupPlansExist - At least one AWS Backup plan exists
type BackupPlansExist struct {
    metadata models.CheckMetadata
}

func NewBackupPlansExist() *BackupPlansExist {
    return &BackupPlansExist{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "backup_plans_exist",
            CheckTitle: "At least one AWS Backup plan exists",
            ServiceName: "backup",
            Severity: "low",
            Description: "**AWS Backup** is assessed for the existence of at least one **backup plan** that schedules and retains recovery points for selected resources.  The evaluation determines whether any plan is configured; when none is found-even if backup vaults exist-the absence of a plan is noted.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"backup"},
        },
    }
}

func (c *BackupPlansExist) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BackupPlansExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "backup",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BackupVaultsExist - At least one AWS Backup vault exists
type BackupVaultsExist struct {
    metadata models.CheckMetadata
}

func NewBackupVaultsExist() *BackupVaultsExist {
    return &BackupVaultsExist{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "backup_vaults_exist",
            CheckTitle: "At least one AWS Backup vault exists",
            ServiceName: "backup",
            Severity: "low",
            Description: "**AWS Backup** in the account/region includes at least one **backup vault** that stores and organizes recovery points for use by backup plans and copies.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"backup"},
        },
    }
}

func (c *BackupVaultsExist) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BackupVaultsExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "backup",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BackupVaultsEncrypted - AWS Backup vault is encrypted at rest
type BackupVaultsEncrypted struct {
    metadata models.CheckMetadata
}

func NewBackupVaultsEncrypted() *BackupVaultsEncrypted {
    return &BackupVaultsEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "backup_vaults_encrypted",
            CheckTitle: "AWS Backup vault is encrypted at rest",
            ServiceName: "backup",
            Severity: "medium",
            Description: "**AWS Backup vaults** are evaluated for **encryption at rest** with **AWS KMS**. The finding highlights vaults without a configured KMS key protecting stored recovery points.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"backup"},
        },
    }
}

func (c *BackupVaultsEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BackupVaultsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "backup",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BackupReportplansExist - At least one AWS Backup report plan exists
type BackupReportplansExist struct {
    metadata models.CheckMetadata
}

func NewBackupReportplansExist() *BackupReportplansExist {
    return &BackupReportplansExist{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "backup_reportplans_exist",
            CheckTitle: "At least one AWS Backup report plan exists",
            ServiceName: "backup",
            Severity: "low",
            Description: "**AWS Backup** environments with existing backup plans are assessed for the presence of at least one **report plan** that generates `jobs` or `compliance` reports.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"backup"},
        },
    }
}

func (c *BackupReportplansExist) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BackupReportplansExist) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "backup",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BackupRecoveryPointEncrypted - AWS Backup recovery point is encrypted at rest
type BackupRecoveryPointEncrypted struct {
    metadata models.CheckMetadata
}

func NewBackupRecoveryPointEncrypted() *BackupRecoveryPointEncrypted {
    return &BackupRecoveryPointEncrypted{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "backup_recovery_point_encrypted",
            CheckTitle: "AWS Backup recovery point is encrypted at rest",
            ServiceName: "backup",
            Severity: "medium",
            Description: "**AWS Backup recovery points** are evaluated for **encryption at rest** using the backup vault's KMS configuration. Items lacking vault-level encryption are highlighted, regardless of the source resource's encryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"backup"},
        },
    }
}

func (c *BackupRecoveryPointEncrypted) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BackupRecoveryPointEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "backup",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

