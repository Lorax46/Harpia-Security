package awslambda

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// AwslambdaFunctionInsideVpc - Lambda function is deployed inside a VPC
type AwslambdaFunctionInsideVpc struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionInsideVpc() *AwslambdaFunctionInsideVpc {
    return &AwslambdaFunctionInsideVpc{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_inside_vpc",
            CheckTitle: "Lambda function is deployed inside a VPC",
            ServiceName: "awslambda",
            Severity: "low",
            Description: "**AWS Lambda function** uses **VPC networking** with specified subnets and security groups, rather than the default Lambda-managed network.  Presence of a VPC association (`vpc_id`) indicates private connectivity to VPC resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionInsideVpc) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionInsideVpc) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionNotPubliclyAccessible - Lambda function resource-based policy does not allow public access
type AwslambdaFunctionNotPubliclyAccessible struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionNotPubliclyAccessible() *AwslambdaFunctionNotPubliclyAccessible {
    return &AwslambdaFunctionNotPubliclyAccessible{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_not_publicly_accessible",
            CheckTitle: "Lambda function resource-based policy does not allow public access",
            ServiceName: "awslambda",
            Severity: "critical",
            Description: "**AWS Lambda** function resource-based policies are assessed for **public access**. The finding identifies policies with wildcard or empty `Principal` that allow actions like `lambda:InvokeFunction` to any principal.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionNotPubliclyAccessible) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionNotPubliclyAccessible) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionUrlCorsPolicy - Lambda function URL CORS does not allow wildcard origins (*)
type AwslambdaFunctionUrlCorsPolicy struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionUrlCorsPolicy() *AwslambdaFunctionUrlCorsPolicy {
    return &AwslambdaFunctionUrlCorsPolicy{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_url_cors_policy",
            CheckTitle: "Lambda function URL CORS does not allow wildcard origins (*)",
            ServiceName: "awslambda",
            Severity: "medium",
            Description: "**Lambda function URL** CORS policy is reviewed for `AllowOrigins`. The presence of `*` indicates a wide origin allowance in the CORS configuration.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionUrlCorsPolicy) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionUrlCorsPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionVpcMultiAz - Lambda function is configured with VPC subnets in at least two Availability Zones
type AwslambdaFunctionVpcMultiAz struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionVpcMultiAz() *AwslambdaFunctionVpcMultiAz {
    return &AwslambdaFunctionVpcMultiAz{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_vpc_multi_az",
            CheckTitle: "Lambda function is configured with VPC subnets in at least two Availability Zones",
            ServiceName: "awslambda",
            Severity: "medium",
            Description: "**AWS Lambda** functions attached to a VPC use subnets that span at least the required number of **Availability Zones** (`2` by default).  The evaluation counts the unique AZs of the function's configured subnets.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionVpcMultiAz) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionVpcMultiAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled - Lambda function Invoke API calls are recorded by CloudTrail
type AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled() *AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled {
    return &AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            CheckTitle: "Lambda function Invoke API calls are recorded by CloudTrail",
            ServiceName: "awslambda",
            Severity: "low",
            Description: "**AWS Lambda** function invocations are recorded as **CloudTrail data events** when trails include `AWS::Lambda::Function` resources.  The finding reflects whether a function's `Invoke` activity is being logged by an eligible trail.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionInvokeApiOperationsCloudtrailLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionNoSecretsInCode - Lambda function code contains no hardcoded secrets
type AwslambdaFunctionNoSecretsInCode struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionNoSecretsInCode() *AwslambdaFunctionNoSecretsInCode {
    return &AwslambdaFunctionNoSecretsInCode{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_no_secrets_in_code",
            CheckTitle: "Lambda function code contains no hardcoded secrets",
            ServiceName: "awslambda",
            Severity: "critical",
            Description: "**Lambda function code** is analyzed for **embedded secrets** across files in the deployment package, detecting patterns like API keys, passwords, tokens, and connection strings. Findings reference file names and line numbers where potential secrets appear.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionNoSecretsInCode) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionNoSecretsInCode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionUsingSupportedRuntimes - Lambda function uses a supported runtime
type AwslambdaFunctionUsingSupportedRuntimes struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionUsingSupportedRuntimes() *AwslambdaFunctionUsingSupportedRuntimes {
    return &AwslambdaFunctionUsingSupportedRuntimes{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_using_supported_runtimes",
            CheckTitle: "Lambda function uses a supported runtime",
            ServiceName: "awslambda",
            Severity: "medium",
            Description: "**Lambda functions** using **obsolete runtimes**-such as `python3.8`, `nodejs14.x`, `go1.x`, `ruby2.7`-are identified against a curated list of deprecated runtime identifiers.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionUsingSupportedRuntimes) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionUsingSupportedRuntimes) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionUrlPublic - Lambda function URL is not publicly accessible
type AwslambdaFunctionUrlPublic struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionUrlPublic() *AwslambdaFunctionUrlPublic {
    return &AwslambdaFunctionUrlPublic{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_url_public",
            CheckTitle: "Lambda function URL is not publicly accessible",
            ServiceName: "awslambda",
            Severity: "high",
            Description: "**AWS Lambda function URLs** are assessed to determine whether `AuthType` enforces **AWS IAM authentication** or permits **public invocation**.  Applies to functions with a function URL and highlights when requests must be authenticated and authorized via IAM principals.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionUrlPublic) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionUrlPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionUsingCrossAccountLayers - Lambda function does not use cross-account layers
type AwslambdaFunctionUsingCrossAccountLayers struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionUsingCrossAccountLayers() *AwslambdaFunctionUsingCrossAccountLayers {
    return &AwslambdaFunctionUsingCrossAccountLayers{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_using_cross_account_layers",
            CheckTitle: "Lambda function does not use cross-account layers",
            ServiceName: "awslambda",
            Severity: "high",
            Description: "**AWS Lambda functions** use only **layers published within the same AWS account**, rather than layers owned by external accounts.  A Lambda layer bundles shared code or dependencies that are injected into the function execution environment at runtime.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionUsingCrossAccountLayers) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionUsingCrossAccountLayers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaLayerNoSecretsInContent - Lambda layer content contains no hardcoded secrets
type AwslambdaLayerNoSecretsInContent struct {
    metadata models.CheckMetadata
}

func NewAwslambdaLayerNoSecretsInContent() *AwslambdaLayerNoSecretsInContent {
    return &AwslambdaLayerNoSecretsInContent{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_layer_no_secrets_in_content",
            CheckTitle: "Lambda layer content contains no hardcoded secrets",
            ServiceName: "awslambda",
            Severity: "high",
            Description: "**Lambda layer content** is analyzed for **embedded secrets** across files in the layer's package, detecting patterns like API keys, passwords, tokens, and connection strings. Findings reference file names and line numbers where potential secrets appear.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaLayerNoSecretsInContent) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaLayerNoSecretsInContent) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionNoSecretsInVariables - Lambda function environment variables do not contain secrets
type AwslambdaFunctionNoSecretsInVariables struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionNoSecretsInVariables() *AwslambdaFunctionNoSecretsInVariables {
    return &AwslambdaFunctionNoSecretsInVariables{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_no_secrets_in_variables",
            CheckTitle: "Lambda function environment variables do not contain secrets",
            ServiceName: "awslambda",
            Severity: "critical",
            Description: "AWS Lambda function environment variables are analyzed for content that resembles **secrets** (API keys, tokens, passwords). Pattern-based detection highlights potential hardcoded credentials present in the function's environment.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionNoSecretsInVariables) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionNoSecretsInVariables) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionEnvVarsNotEncryptedWithCmk - Lambda function environment variables are encrypted with a customer-managed KMS key
type AwslambdaFunctionEnvVarsNotEncryptedWithCmk struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionEnvVarsNotEncryptedWithCmk() *AwslambdaFunctionEnvVarsNotEncryptedWithCmk {
    return &AwslambdaFunctionEnvVarsNotEncryptedWithCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_env_vars_not_encrypted_with_cmk",
            CheckTitle: "Lambda function environment variables are encrypted with a customer-managed KMS key",
            ServiceName: "awslambda",
            Severity: "medium",
            Description: "**AWS Lambda function** environment variables are encrypted at rest using a **customer-managed KMS key (CMK)** rather than the default AWS-managed Lambda service key.  The presence of a `KMSKeyArn` on the function configuration indicates CMK-based encryption is active.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionEnvVarsNotEncryptedWithCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionEnvVarsNotEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// AwslambdaFunctionNoDeadLetterQueue - Lambda function has a Dead Letter Queue configured
type AwslambdaFunctionNoDeadLetterQueue struct {
    metadata models.CheckMetadata
}

func NewAwslambdaFunctionNoDeadLetterQueue() *AwslambdaFunctionNoDeadLetterQueue {
    return &AwslambdaFunctionNoDeadLetterQueue{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "awslambda_function_no_dead_letter_queue",
            CheckTitle: "Lambda function has a Dead Letter Queue configured",
            ServiceName: "awslambda",
            Severity: "medium",
            Description: "**AWS Lambda functions** have a **Dead Letter Queue (DLQ)** configured — an SQS queue or SNS topic that receives records of failed asynchronous invocations.  Without a DLQ, failed invocations are silently discarded after exhausting retries.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"awslambda"},
        },
    }
}

func (c *AwslambdaFunctionNoDeadLetterQueue) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *AwslambdaFunctionNoDeadLetterQueue) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "awslambda",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

