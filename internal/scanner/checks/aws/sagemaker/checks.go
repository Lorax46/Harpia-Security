package sagemaker

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// SagemakerNotebookInstanceNoSecrets - SageMaker notebook instance lifecycle configuration contains no hardcoded secrets
type SagemakerNotebookInstanceNoSecrets struct {
    metadata models.CheckMetadata
}

func NewSagemakerNotebookInstanceNoSecrets() *SagemakerNotebookInstanceNoSecrets {
    return &SagemakerNotebookInstanceNoSecrets{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_notebook_instance_no_secrets",
            CheckTitle: "SageMaker notebook instance lifecycle configuration contains no hardcoded secrets",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**SageMaker notebook instance lifecycle configuration scripts** (`OnCreate` and `OnStart`) are analyzed for **embedded secrets**, detecting patterns like API keys, passwords, tokens, and connection strings. Findings reference the lifecycle hook and line numbers where potential secrets appear.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerNotebookInstanceNoSecrets) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerNotebookInstanceNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled - Amazon SageMaker training job volume has KMS encryption enabled
type SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerTrainingJobsVolumeAndOutputEncryptionEnabled() *SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled {
    return &SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_training_jobs_volume_and_output_encryption_enabled",
            CheckTitle: "Amazon SageMaker training job volume has KMS encryption enabled",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**Amazon SageMaker training jobs** use **KMS encryption** for their attached ML storage volumes via `VolumeKmsKeyId`.  The finding identifies training jobs where the volume encryption key is not configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerTrainingJobsVolumeAndOutputEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerTrainingJobsNetworkIsolationEnabled - Amazon SageMaker training job has network isolation enabled
type SagemakerTrainingJobsNetworkIsolationEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerTrainingJobsNetworkIsolationEnabled() *SagemakerTrainingJobsNetworkIsolationEnabled {
    return &SagemakerTrainingJobsNetworkIsolationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_training_jobs_network_isolation_enabled",
            CheckTitle: "Amazon SageMaker training job has network isolation enabled",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**SageMaker training jobs** have **network isolation** enabled, preventing the training container from making any inbound or outbound network calls during execution",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerTrainingJobsNetworkIsolationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerTrainingJobsNetworkIsolationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerTrainingJobsIntercontainerEncryptionEnabled - Amazon SageMaker training job has inter-container traffic encryption enabled
type SagemakerTrainingJobsIntercontainerEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerTrainingJobsIntercontainerEncryptionEnabled() *SagemakerTrainingJobsIntercontainerEncryptionEnabled {
    return &SagemakerTrainingJobsIntercontainerEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_training_jobs_intercontainer_encryption_enabled",
            CheckTitle: "Amazon SageMaker training job has inter-container traffic encryption enabled",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "Amazon SageMaker training jobs have **inter-container traffic encryption** configured for container-to-container communications during training.  The evaluation inspects the `EnableInterContainerTrafficEncryption` setting on training jobs.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerTrainingJobsIntercontainerEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerTrainingJobsIntercontainerEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerEndpointConfigKmsEncryptionEnabled - SageMaker endpoint configuration is encrypted with a KMS key
type SagemakerEndpointConfigKmsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerEndpointConfigKmsEncryptionEnabled() *SagemakerEndpointConfigKmsEncryptionEnabled {
    return &SagemakerEndpointConfigKmsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_endpoint_config_kms_encryption_enabled",
            CheckTitle: "SageMaker endpoint configuration is encrypted with a KMS key",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "**Amazon SageMaker endpoint configurations** are assessed for **at-rest encryption** using an AWS KMS key. The finding reflects whether a `KmsKeyId` is configured on the endpoint configuration so inference data volumes and related storage use KMS encryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerEndpointConfigKmsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerEndpointConfigKmsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured - Amazon SageMaker notebook instance has direct internet access disabled
type SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured struct {
    metadata models.CheckMetadata
}

func NewSagemakerNotebookInstanceWithoutDirectInternetAccessConfigured() *SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured {
    return &SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_notebook_instance_without_direct_internet_access_configured",
            CheckTitle: "Amazon SageMaker notebook instance has direct internet access disabled",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "Amazon SageMaker notebook instances are evaluated for the `DirectInternetAccess` setting.  Instances with it disabled use only VPC connectivity; instances with it enabled permit direct outbound internet access.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerNotebookInstanceWithoutDirectInternetAccessConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerNotebookInstanceRootAccessDisabled - Amazon SageMaker notebook instance has root access disabled
type SagemakerNotebookInstanceRootAccessDisabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerNotebookInstanceRootAccessDisabled() *SagemakerNotebookInstanceRootAccessDisabled {
    return &SagemakerNotebookInstanceRootAccessDisabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_notebook_instance_root_access_disabled",
            CheckTitle: "Amazon SageMaker notebook instance has root access disabled",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "**Amazon SageMaker notebook instances** with user **root access disabled**. The evaluation checks whether interactive users can obtain root privileges on the instance, highlighting notebooks where `RootAccess` is not set to `Disabled`.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerNotebookInstanceRootAccessDisabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerNotebookInstanceRootAccessDisabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerDomainSsoConfigured - SageMaker domains use SSO authentication instead of IAM mode
type SagemakerDomainSsoConfigured struct {
    metadata models.CheckMetadata
}

func NewSagemakerDomainSsoConfigured() *SagemakerDomainSsoConfigured {
    return &SagemakerDomainSsoConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_domain_sso_configured",
            CheckTitle: "SageMaker domains use SSO authentication instead of IAM mode",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "**SageMaker Domain** configured with **IAM Identity Center (SSO) authentication**. The check validates that each SageMaker Domain uses SSO mode (`AuthMode: SSO`) and is associated with an IAM Identity Center instance (`SingleSignOnManagedApplicationInstanceId` or `SingleSignOnApplicationArn` present), ensuring user access is centrally managed through AWS IAM Identity Center.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerDomainSsoConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerDomainSsoConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerEndpointConfigProdVariantInstances - SageMaker endpoint configuration has all production variants with at least two initial instances
type SagemakerEndpointConfigProdVariantInstances struct {
    metadata models.CheckMetadata
}

func NewSagemakerEndpointConfigProdVariantInstances() *SagemakerEndpointConfigProdVariantInstances {
    return &SagemakerEndpointConfigProdVariantInstances{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_endpoint_config_prod_variant_instances",
            CheckTitle: "SageMaker endpoint configuration has all production variants with at least two initial instances",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "Amazon SageMaker endpoint configurations are evaluated to ensure each production variant uses an **initial instance count** of at least two. Variants with `InitialInstanceCount` less than two in instance-based endpoints are identified, indicating no built-in multi-AZ redundancy.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerEndpointConfigProdVariantInstances) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerEndpointConfigProdVariantInstances) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerModelsNetworkIsolationEnabled - Amazon SageMaker model has network isolation enabled
type SagemakerModelsNetworkIsolationEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerModelsNetworkIsolationEnabled() *SagemakerModelsNetworkIsolationEnabled {
    return &SagemakerModelsNetworkIsolationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_models_network_isolation_enabled",
            CheckTitle: "Amazon SageMaker model has network isolation enabled",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**SageMaker models** are evaluated for **network isolation** status, indicating whether model containers are blocked from initiating network connections during hosting/inference, aside from required service control traffic.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerModelsNetworkIsolationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerModelsNetworkIsolationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerTrainingJobsVpcSettingsConfigured - Amazon SageMaker training job has VPC configuration enabled
type SagemakerTrainingJobsVpcSettingsConfigured struct {
    metadata models.CheckMetadata
}

func NewSagemakerTrainingJobsVpcSettingsConfigured() *SagemakerTrainingJobsVpcSettingsConfigured {
    return &SagemakerTrainingJobsVpcSettingsConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_training_jobs_vpc_settings_configured",
            CheckTitle: "Amazon SageMaker training job has VPC configuration enabled",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**SageMaker training jobs** are evaluated for **VPC configuration** by detecting defined `subnets` in the job settings. With VPC settings, ENIs place the job in your VPC so traffic for training volumes and outputs uses private networking.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerTrainingJobsVpcSettingsConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerTrainingJobsVpcSettingsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerNotebookInstanceVpcSettingsConfigured - Amazon SageMaker notebook instance has VPC settings configured
type SagemakerNotebookInstanceVpcSettingsConfigured struct {
    metadata models.CheckMetadata
}

func NewSagemakerNotebookInstanceVpcSettingsConfigured() *SagemakerNotebookInstanceVpcSettingsConfigured {
    return &SagemakerNotebookInstanceVpcSettingsConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_notebook_instance_vpc_settings_configured",
            CheckTitle: "Amazon SageMaker notebook instance has VPC settings configured",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**SageMaker notebook instances** are evaluated for **VPC attachment**. Instances configured with a VPC (via a `subnet_id` and security groups) use private networking; those without VPC settings rely on public networking.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerNotebookInstanceVpcSettingsConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerNotebookInstanceVpcSettingsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerModelsMonitorEnabled - Amazon SageMaker has a monitoring schedule scheduled
type SagemakerModelsMonitorEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerModelsMonitorEnabled() *SagemakerModelsMonitorEnabled {
    return &SagemakerModelsMonitorEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_models_monitor_enabled",
            CheckTitle: "Amazon SageMaker has a monitoring schedule scheduled",
            ServiceName: "sagemaker",
            Severity: "low",
            Description: "**SageMaker Models Monitor** detects data drift, model quality issues, and bias drift in production.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerModelsMonitorEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerModelsMonitorEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerModelsVpcSettingsConfigured - Amazon SageMaker model has VPC settings enabled
type SagemakerModelsVpcSettingsConfigured struct {
    metadata models.CheckMetadata
}

func NewSagemakerModelsVpcSettingsConfigured() *SagemakerModelsVpcSettingsConfigured {
    return &SagemakerModelsVpcSettingsConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_models_vpc_settings_configured",
            CheckTitle: "Amazon SageMaker model has VPC settings enabled",
            ServiceName: "sagemaker",
            Severity: "medium",
            Description: "**SageMaker models** use **VPC settings** (`VpcConfig` with subnets and security groups) so inference containers communicate through a selected VPC rather than the public internet.  This evaluates whether a model defines VPC subnets for its network path.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerModelsVpcSettingsConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerModelsVpcSettingsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerClarifyExists - Amazon SageMaker Clarify processing jobs exist in the region
type SagemakerClarifyExists struct {
    metadata models.CheckMetadata
}

func NewSagemakerClarifyExists() *SagemakerClarifyExists {
    return &SagemakerClarifyExists{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_clarify_exists",
            CheckTitle: "Amazon SageMaker Clarify processing jobs exist in the region",
            ServiceName: "sagemaker",
            Severity: "low",
            Description: "**SageMaker Clarify** provides bias detection and model explainability for ML workloads.  This check verifies that at least one SageMaker processing job using the AWS-managed Clarify container image exists in each successfully scanned region. The absence of Clarify jobs indicates that responsible-AI controls such as bias detection and explainability are not in place.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerClarifyExists) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerClarifyExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerModelsRegistryInUse - Amazon SageMaker Model Registry should have at least one approved model package
type SagemakerModelsRegistryInUse struct {
    metadata models.CheckMetadata
}

func NewSagemakerModelsRegistryInUse() *SagemakerModelsRegistryInUse {
    return &SagemakerModelsRegistryInUse{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_models_registry_in_use",
            CheckTitle: "Amazon SageMaker Model Registry should have at least one approved model package",
            ServiceName: "sagemaker",
            Severity: "low",
            Description: "**SageMaker Model Registry** is evaluated to verify that at least one Model Package Group exists and contains at least one model package with **ModelApprovalStatus = Approved**. This confirms that the ML governance workflow (register → review → approve → deploy) is actively in use.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerModelsRegistryInUse) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerModelsRegistryInUse) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// SagemakerNotebookInstanceEncryptionEnabled - SageMaker notebook instance is encrypted with a KMS key
type SagemakerNotebookInstanceEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewSagemakerNotebookInstanceEncryptionEnabled() *SagemakerNotebookInstanceEncryptionEnabled {
    return &SagemakerNotebookInstanceEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "sagemaker_notebook_instance_encryption_enabled",
            CheckTitle: "SageMaker notebook instance is encrypted with a KMS key",
            ServiceName: "sagemaker",
            Severity: "high",
            Description: "**Amazon SageMaker notebook instances** are assessed for **at-rest encryption** using an AWS KMS key. The finding reflects whether a `KmsKeyId` is configured for the notebook's ML volume encryption.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"sagemaker"},
        },
    }
}

func (c *SagemakerNotebookInstanceEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *SagemakerNotebookInstanceEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "sagemaker",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

