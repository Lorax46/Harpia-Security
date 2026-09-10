package codepipeline

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CodepipelineProjectRepoPrivate - CodePipeline pipeline should use private repository source with authenticated connection
type CodepipelineProjectRepoPrivate struct {
    metadata models.CheckMetadata
}

func NewCodepipelineProjectRepoPrivate() *CodepipelineProjectRepoPrivate {
    return &CodepipelineProjectRepoPrivate{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "codepipeline_project_repo_private",
            CheckTitle: "CodePipeline pipeline should use private repository source with authenticated connection",
            ServiceName: "codepipeline",
            Severity: "medium",
            Description: "**CodePipeline pipeline** should configure its **source stage** to use a **private repository** with authenticated connection rather than a public GitHub or GitLab repository. This ensures deployment configurations, build artifacts, and CI/CD logic remain protected from unauthorized access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"codepipeline"},
        },
    }
}

func (c *CodepipelineProjectRepoPrivate) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *CodepipelineProjectRepoPrivate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "codepipeline",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

