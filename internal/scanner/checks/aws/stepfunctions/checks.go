package stepfunctions

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// StepfunctionsStatemachineLoggingEnabled - Step Functions state machine has logging enabled
type StepfunctionsStatemachineLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewStepfunctionsStatemachineLoggingEnabled() *StepfunctionsStatemachineLoggingEnabled {
    return &StepfunctionsStatemachineLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "stepfunctions_statemachine_logging_enabled",
            CheckTitle: "Step Functions state machine has logging enabled",
            ServiceName: "stepfunctions",
            Severity: "medium",
            Description: "**AWS Step Functions state machines** are configured to emit **execution logs** to CloudWatch Logs via a defined `loggingConfiguration` with a `level` set above `OFF`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"stepfunctions"},
        },
    }
}

func (c *StepfunctionsStatemachineLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *StepfunctionsStatemachineLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "stepfunctions",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// StepfunctionsStatemachineNoSecretsInDefinition - Step Functions state machine has no sensitive credentials in its definition
type StepfunctionsStatemachineNoSecretsInDefinition struct {
    metadata models.CheckMetadata
}

func NewStepfunctionsStatemachineNoSecretsInDefinition() *StepfunctionsStatemachineNoSecretsInDefinition {
    return &StepfunctionsStatemachineNoSecretsInDefinition{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "stepfunctions_statemachine_no_secrets_in_definition",
            CheckTitle: "Step Functions state machine has no sensitive credentials in its definition",
            ServiceName: "stepfunctions",
            Severity: "critical",
            Description: "**AWS Step Functions state machines** are inspected for **hardcoded secrets** (keys, tokens, passwords) embedded directly in the state machine **definition** (Amazon States Language JSON).  Such values indicate sensitive data is stored directly in task parameters instead of being sourced securely.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"stepfunctions"},
        },
    }
}

func (c *StepfunctionsStatemachineNoSecretsInDefinition) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *StepfunctionsStatemachineNoSecretsInDefinition) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "stepfunctions",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// StepfunctionsStatemachineEncryptedWithCmk - Step Functions state machine is encrypted at rest with a customer-managed KMS key
type StepfunctionsStatemachineEncryptedWithCmk struct {
    metadata models.CheckMetadata
}

func NewStepfunctionsStatemachineEncryptedWithCmk() *StepfunctionsStatemachineEncryptedWithCmk {
    return &StepfunctionsStatemachineEncryptedWithCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "stepfunctions_statemachine_encrypted_with_cmk",
            CheckTitle: "Step Functions state machine is encrypted at rest with a customer-managed KMS key",
            ServiceName: "stepfunctions",
            Severity: "medium",
            Description: "**AWS Step Functions state machines** store execution history and input/output data passed between workflow states. This check verifies that each state machine uses a **customer-managed KMS key** (`CUSTOMER_MANAGED_KMS_KEY`) for encryption at rest rather than the default AWS-owned key.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"stepfunctions"},
        },
    }
}

func (c *StepfunctionsStatemachineEncryptedWithCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *StepfunctionsStatemachineEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "stepfunctions",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

