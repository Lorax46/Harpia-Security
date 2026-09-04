package amplify

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AmplifyAppNoSecretsInEnvironment - Amplify app has no sensitive credentials in environment variables or build settings
type AmplifyAppNoSecretsInEnvironment struct {
    metadata models.CheckMetadata
}

func NewAmplifyAppNoSecretsInEnvironment() *AmplifyAppNoSecretsInEnvironment {
    return &AmplifyAppNoSecretsInEnvironment{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "amplify_app_no_secrets_in_environment",
            CheckTitle: "Amplify app has no sensitive credentials in environment variables or build settings",
            ServiceName: "amplify",
            Severity: "high",
            Description: "AWS Amplify apps and their branches are inspected for hardcoded secrets, such as API keys, tokens, or passwords embedded in environment variables or build settings (buildSpec).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"amplify"},
        },
    }
}

func (c *AmplifyAppNoSecretsInEnvironment) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AmplifyAppNoSecretsInEnvironment) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "amplify",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

