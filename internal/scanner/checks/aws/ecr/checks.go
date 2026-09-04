package ecr

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// EcrRepositoriesNotPubliclyAccessible - ECR repository is not publicly accessible
type EcrRepositoriesNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoriesNotPubliclyAccessible() *EcrRepositoriesNotPubliclyAccessible {
    return &EcrRepositoriesNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repositories_not_publicly_accessible",
            CheckTitle: "ECR repository is not publicly accessible",
            ServiceName: "ecr",
            Severity: "critical",
            Description: "**Amazon ECR repositories** are evaluated for **public exposure** via repository policies that allow anonymous principals (e.g., `Principal: '*'`) to access the repo, including image listing, pulling, or modification.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoriesNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoriesNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRegistryEnhancedScanningEnabled - ECR registry has enhanced scanning enabled
type EcrRegistryEnhancedScanningEnabled struct {
    metadata models.CheckMetadata
}

func NewEcrRegistryEnhancedScanningEnabled() *EcrRegistryEnhancedScanningEnabled {
    return &EcrRegistryEnhancedScanningEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_registry_enhanced_scanning_enabled",
            CheckTitle: "ECR registry has enhanced scanning enabled",
            ServiceName: "ecr",
            Severity: "medium",
            Description: "Amazon ECR registries with repositories are evaluated for **enhanced scanning**, the Amazon Inspector-powered scan type that covers operating system **and** programming language packages and can rescan images continuously as new CVEs are published. A registry left on **basic** scanning is reported as failing.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRegistryEnhancedScanningEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRegistryEnhancedScanningEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRepositoriesTagImmutability - ECR repository has image tag immutability enabled
type EcrRepositoriesTagImmutability struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoriesTagImmutability() *EcrRepositoriesTagImmutability {
    return &EcrRepositoriesTagImmutability{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repositories_tag_immutability",
            CheckTitle: "ECR repository has image tag immutability enabled",
            ServiceName: "ecr",
            Severity: "medium",
            Description: "Amazon ECR repositories are assessed for **image tag immutability**. Repositories permitting tag updates (`MUTABLE`) are identified; those enforcing immutable tags (such as `IMMUTABLE`) are recognized.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoriesTagImmutability) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoriesTagImmutability) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRepositoriesLifecyclePolicyEnabled - ECR repository has a lifecycle policy configured
type EcrRepositoriesLifecyclePolicyEnabled struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoriesLifecyclePolicyEnabled() *EcrRepositoriesLifecyclePolicyEnabled {
    return &EcrRepositoriesLifecyclePolicyEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repositories_lifecycle_policy_enabled",
            CheckTitle: "ECR repository has a lifecycle policy configured",
            ServiceName: "ecr",
            Severity: "low",
            Description: "Amazon ECR repositories have a **lifecycle policy** configured to automatically expire container images based on age, count, or tags.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoriesLifecyclePolicyEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoriesLifecyclePolicyEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRepositoriesScanVulnerabilitiesInLatestImage - ECR repository latest image is scanned with no vulnerabilities at or above the configured minimum severity
type EcrRepositoriesScanVulnerabilitiesInLatestImage struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoriesScanVulnerabilitiesInLatestImage() *EcrRepositoriesScanVulnerabilitiesInLatestImage {
    return &EcrRepositoriesScanVulnerabilitiesInLatestImage{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repositories_scan_vulnerabilities_in_latest_image",
            CheckTitle: "ECR repository latest image is scanned with no vulnerabilities at or above the configured minimum severity",
            ServiceName: "ecr",
            Severity: "medium",
            Description: "**Amazon ECR repositories** are assessed on the most recent pushed image to confirm a vulnerability scan exists, completed successfully, and that no results meet or exceed the configured minimum severity (e.g., `CRITICAL`, `HIGH`, `MEDIUM`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoriesScanVulnerabilitiesInLatestImage) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoriesScanVulnerabilitiesInLatestImage) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRegistryScanImagesOnPushEnabled - ECR registry has automated image scanning enabled for all repositories
type EcrRegistryScanImagesOnPushEnabled struct {
    metadata models.CheckMetadata
}

func NewEcrRegistryScanImagesOnPushEnabled() *EcrRegistryScanImagesOnPushEnabled {
    return &EcrRegistryScanImagesOnPushEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_registry_scan_images_on_push_enabled",
            CheckTitle: "ECR registry has automated image scanning enabled for all repositories",
            ServiceName: "ecr",
            Severity: "medium",
            Description: "Amazon ECR registries with repositories are evaluated for automated image scanning at the registry level -- `scan on push` or `continuous scanning` -- with scan rules that cover all repositories (no restrictive filters), for either **basic** or **enhanced** scanning. A registry whose rules specify only `MANUAL` scanning does not scan pushed images.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRegistryScanImagesOnPushEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRegistryScanImagesOnPushEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRepositoriesScanImagesOnPushEnabled - [DEPRECATED] ECR repository has image scanning on push enabled
type EcrRepositoriesScanImagesOnPushEnabled struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoriesScanImagesOnPushEnabled() *EcrRepositoriesScanImagesOnPushEnabled {
    return &EcrRepositoriesScanImagesOnPushEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repositories_scan_images_on_push_enabled",
            CheckTitle: "[DEPRECATED] ECR repository has image scanning on push enabled",
            ServiceName: "ecr",
            Severity: "medium",
            Description: "[DEPRECATED] **Amazon ECR repositories** are evaluated for **image scanning on push**; when configured, new image uploads automatically trigger a vulnerability scan (`scan_on_push`).",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoriesScanImagesOnPushEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoriesScanImagesOnPushEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EcrRepositoryImageNoSecrets - ECR repository image contains no hardcoded secrets
type EcrRepositoryImageNoSecrets struct {
    metadata models.CheckMetadata
}

func NewEcrRepositoryImageNoSecrets() *EcrRepositoryImageNoSecrets {
    return &EcrRepositoryImageNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "ecr_repository_image_no_secrets",
            CheckTitle: "ECR repository image contains no hardcoded secrets",
            ServiceName: "ecr",
            Severity: "high",
            Description: "The **latest image** pushed to each **Amazon ECR repository** is analyzed for **embedded secrets**: environment variables and build history (Dockerfile instructions) recorded in the image configuration, plus the file contents of every filesystem layer. Findings reference the variable, build step, or file, never the secret value.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"ecr"},
        },
    }
}

func (c *EcrRepositoryImageNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EcrRepositoryImageNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "ecr",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

