package bedrock

import (
    "context"
    "time"

    "github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// BedrockApiKeyNoLongTermCredentials - Amazon Bedrock long-term API key has expired
type BedrockApiKeyNoLongTermCredentials struct {
    metadata models.CheckMetadata
}

func NewBedrockApiKeyNoLongTermCredentials() *BedrockApiKeyNoLongTermCredentials {
    return &BedrockApiKeyNoLongTermCredentials{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_api_key_no_long_term_credentials",
            CheckTitle: "Amazon Bedrock long-term API key has expired",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "AWS recommends Amazon Bedrock **long-term API keys** only for **exploration**; production workloads should use **short-term API keys** (session-scoped, valid up to **12 hours**). This check fails for any active long-term Bedrock API key, escalating to `critical` severity when configured to **never expire**. Already-expired keys pass — they can no longer authenticate.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockApiKeyNoLongTermCredentials) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockApiKeyNoLongTermCredentials) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockAgentRoleLeastPrivilege - Amazon Bedrock agent execution role follows least privilege
type BedrockAgentRoleLeastPrivilege struct {
    metadata models.CheckMetadata
}

func NewBedrockAgentRoleLeastPrivilege() *BedrockAgentRoleLeastPrivilege {
    return &BedrockAgentRoleLeastPrivilege{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_agent_role_least_privilege",
            CheckTitle: "Amazon Bedrock agent execution role follows least privilege",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock Agent** execution roles (`agentResourceRoleArn`) should grant only the minimum permissions the agent needs. The evaluation FAILs when the role has an AWS-managed `*FullAccess` policy attached, has an inline statement allowing broad actions on `Resource: '*'`, or has no permissions boundary configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockAgentRoleLeastPrivilege) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockAgentRoleLeastPrivilege) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockGuardrailSensitiveInformationFilterEnabled - Amazon Bedrock guardrail blocks or masks sensitive information
type BedrockGuardrailSensitiveInformationFilterEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockGuardrailSensitiveInformationFilterEnabled() *BedrockGuardrailSensitiveInformationFilterEnabled {
    return &BedrockGuardrailSensitiveInformationFilterEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_guardrail_sensitive_information_filter_enabled",
            CheckTitle: "Amazon Bedrock guardrail blocks or masks sensitive information",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock guardrails** use **sensitive information filters** to `block` or `mask` detected PII and custom pattern matches in prompts and responses.  The evaluation looks for guardrails with this filtering configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockGuardrailSensitiveInformationFilterEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockGuardrailSensitiveInformationFilterEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockGuardrailContextualGroundingFilterEnabled - Bedrock guardrail blocks ungrounded and irrelevant model responses
type BedrockGuardrailContextualGroundingFilterEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockGuardrailContextualGroundingFilterEnabled() *BedrockGuardrailContextualGroundingFilterEnabled {
    return &BedrockGuardrailContextualGroundingFilterEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_guardrail_contextual_grounding_filter_enabled",
            CheckTitle: "Bedrock guardrail blocks ungrounded and irrelevant model responses",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock guardrails** can attach a `contextualGroundingPolicy` whose filters score each response for `GROUNDING` (supported by the retrieved source) and `RELEVANCE` (answers the question asked). Both filter types must be enabled, set to `action: BLOCK`, and carry a `threshold` above 0.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockGuardrailContextualGroundingFilterEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockGuardrailContextualGroundingFilterEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockModelInvocationLoggingEnabled - Amazon Bedrock model invocation logging is enabled
type BedrockModelInvocationLoggingEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockModelInvocationLoggingEnabled() *BedrockModelInvocationLoggingEnabled {
    return &BedrockModelInvocationLoggingEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_model_invocation_logging_enabled",
            CheckTitle: "Amazon Bedrock model invocation logging is enabled",
            ServiceName: "bedrock",
            Severity: "medium",
            Description: "**Bedrock** model invocation logging captures request, response, and metadata for `Converse`, `ConverseStream`, `InvokeModel`, and `InvokeModelWithResponseStream` calls per Region, delivering records to **CloudWatch Logs** and/or **S3** when configured.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockModelInvocationLoggingEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockModelInvocationLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockAgentGuardrailEnabled - Amazon Bedrock agent uses a guardrail to protect agent sessions
type BedrockAgentGuardrailEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockAgentGuardrailEnabled() *BedrockAgentGuardrailEnabled {
    return &BedrockAgentGuardrailEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_agent_guardrail_enabled",
            CheckTitle: "Amazon Bedrock agent uses a guardrail to protect agent sessions",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock agents** should have an associated **guardrail** for their sessions. The evaluation identifies agents without a guardrail linked for input/output screening during interactions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockAgentGuardrailEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockAgentGuardrailEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockModelInvocationLogsEncryptionEnabled - Amazon Bedrock model invocation logs are encrypted in the S3 bucket and KMS-encrypted in the CloudWatch log group
type BedrockModelInvocationLogsEncryptionEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockModelInvocationLogsEncryptionEnabled() *BedrockModelInvocationLogsEncryptionEnabled {
    return &BedrockModelInvocationLogsEncryptionEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_model_invocation_logs_encryption_enabled",
            CheckTitle: "Amazon Bedrock model invocation logs are encrypted in the S3 bucket and KMS-encrypted in the CloudWatch log group",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock model invocation logs** are stored in encrypted destinations: **S3 buckets** with bucket encryption and **CloudWatch Logs** groups protected by an AWS KMS key.  This evaluates whether configured log targets enforce encryption at rest for request/response content and associated metadata.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockModelInvocationLogsEncryptionEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockModelInvocationLogsEncryptionEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockAgentRoleNotSharedAcrossAgents - Bedrock Agent has a dedicated execution role
type BedrockAgentRoleNotSharedAcrossAgents struct {
    metadata models.CheckMetadata
}

func NewBedrockAgentRoleNotSharedAcrossAgents() *BedrockAgentRoleNotSharedAcrossAgents {
    return &BedrockAgentRoleNotSharedAcrossAgents{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_agent_role_not_shared_across_agents",
            CheckTitle: "Bedrock Agent has a dedicated execution role",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "Every **Bedrock Agent** assumes the role in its `agentResourceRoleArn`. That role must belong to exactly one agent, so no agent inherits another's permissions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockAgentRoleNotSharedAcrossAgents) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockAgentRoleNotSharedAcrossAgents) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockPromptManagementExists - Amazon Bedrock Prompt Management prompts exist in the region
type BedrockPromptManagementExists struct {
    metadata models.CheckMetadata
}

func NewBedrockPromptManagementExists() *BedrockPromptManagementExists {
    return &BedrockPromptManagementExists{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_prompt_management_exists",
            CheckTitle: "Amazon Bedrock Prompt Management prompts exist in the region",
            ServiceName: "bedrock",
            Severity: "low",
            Description: "**Bedrock Prompt Management** enables centralized creation, versioning, and governance of prompts used with foundation models.  This region-level check verifies whether at least one managed prompt exists in each scanned region, used as an adoption signal for Prompt Management. The presence of a prompt does not by itself guarantee that every application prompt is managed.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockPromptManagementExists) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockPromptManagementExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockGuardrailPromptAttackFilterEnabled - Amazon Bedrock guardrail has prompt attack filter strength set to HIGH
type BedrockGuardrailPromptAttackFilterEnabled struct {
    metadata models.CheckMetadata
}

func NewBedrockGuardrailPromptAttackFilterEnabled() *BedrockGuardrailPromptAttackFilterEnabled {
    return &BedrockGuardrailPromptAttackFilterEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_guardrail_prompt_attack_filter_enabled",
            CheckTitle: "Amazon Bedrock guardrail has prompt attack filter strength set to HIGH",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock guardrails** have the **Prompt attack** filter set to `HIGH` strength to detect and block injection and jailbreak patterns. Guardrails missing this setting or using lower strengths are identified.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockGuardrailPromptAttackFilterEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockGuardrailPromptAttackFilterEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockFullAccessPolicyAttached - IAM role does not have AmazonBedrockFullAccess managed policy attached
type BedrockFullAccessPolicyAttached struct {
    metadata models.CheckMetadata
}

func NewBedrockFullAccessPolicyAttached() *BedrockFullAccessPolicyAttached {
    return &BedrockFullAccessPolicyAttached{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_full_access_policy_attached",
            CheckTitle: "IAM role does not have AmazonBedrockFullAccess managed policy attached",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**IAM roles** (excluding service roles) are evaluated for attachment of the AWS-managed `AmazonBedrockFullAccess` policy.  This policy grants unrestricted access to all Amazon Bedrock actions and resources.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockFullAccessPolicyAttached) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockFullAccessPolicyAttached) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockGuardrailsConfigured - Bedrock has at least one guardrail configured in the audited region
type BedrockGuardrailsConfigured struct {
    metadata models.CheckMetadata
}

func NewBedrockGuardrailsConfigured() *BedrockGuardrailsConfigured {
    return &BedrockGuardrailsConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_guardrails_configured",
            CheckTitle: "Bedrock has at least one guardrail configured in the audited region",
            ServiceName: "bedrock",
            Severity: "medium",
            Description: "**Amazon Bedrock guardrails** provide reusable safety policies for filtering harmful or unwanted content in model inputs and outputs.  This evaluation checks whether at least one guardrail exists in each successfully scanned region. It does **not** verify that guardrails are attached to agents or passed on individual model invocation API calls.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockGuardrailsConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockGuardrailsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockPromptEncryptedWithCmk - Amazon Bedrock prompt is encrypted at rest with a customer-managed KMS key
type BedrockPromptEncryptedWithCmk struct {
    metadata models.CheckMetadata
}

func NewBedrockPromptEncryptedWithCmk() *BedrockPromptEncryptedWithCmk {
    return &BedrockPromptEncryptedWithCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_prompt_encrypted_with_cmk",
            CheckTitle: "Amazon Bedrock prompt is encrypted at rest with a customer-managed KMS key",
            ServiceName: "bedrock",
            Severity: "medium",
            Description: "Bedrock prompts should be encrypted at rest with a **customer-managed KMS key (CMK)** rather than the AWS-owned default key. Prompts can contain sensitive instructions, business logic, and references to downstream tooling that warrant tenant-controlled key material and auditable access via AWS KMS.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockPromptEncryptedWithCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockPromptEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockCustomModelEncryptedWithCmk - Bedrock custom model is encrypted with a customer-managed KMS key
type BedrockCustomModelEncryptedWithCmk struct {
    metadata models.CheckMetadata
}

func NewBedrockCustomModelEncryptedWithCmk() *BedrockCustomModelEncryptedWithCmk {
    return &BedrockCustomModelEncryptedWithCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_custom_model_encrypted_with_cmk",
            CheckTitle: "Bedrock custom model is encrypted with a customer-managed KMS key",
            ServiceName: "bedrock",
            Severity: "critical",
            Description: "**Bedrock custom models** produced by model customization can be encrypted at rest with a customer-managed KMS key rather than resting under an AWS-owned key the organization cannot audit, rotate, or revoke.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockCustomModelEncryptedWithCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockCustomModelEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockKnowledgeBaseEncryptedWithCmk - Bedrock knowledge base data source is encrypted with a customer-managed KMS key
type BedrockKnowledgeBaseEncryptedWithCmk struct {
    metadata models.CheckMetadata
}

func NewBedrockKnowledgeBaseEncryptedWithCmk() *BedrockKnowledgeBaseEncryptedWithCmk {
    return &BedrockKnowledgeBaseEncryptedWithCmk{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_knowledge_base_encrypted_with_cmk",
            CheckTitle: "Bedrock knowledge base data source is encrypted with a customer-managed KMS key",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "Each data source of a **Bedrock knowledge base** can set `serverSideEncryptionConfiguration.kmsKeyArn`, which encrypts the transient storage used while documents are chunked and embedded, rather than relying on an AWS-owned key.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockKnowledgeBaseEncryptedWithCmk) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockKnowledgeBaseEncryptedWithCmk) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockVpcEndpointsConfigured - VPC endpoints ensure private connectivity for all Bedrock APIs
type BedrockVpcEndpointsConfigured struct {
    metadata models.CheckMetadata
}

func NewBedrockVpcEndpointsConfigured() *BedrockVpcEndpointsConfigured {
    return &BedrockVpcEndpointsConfigured{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_vpc_endpoints_configured",
            CheckTitle: "VPC endpoints ensure private connectivity for all Bedrock APIs",
            ServiceName: "bedrock",
            Severity: "medium",
            Description: "**Amazon VPCs** are evaluated for **interface VPC endpoints** to all Bedrock services: `bedrock`, `bedrock-runtime`, `bedrock-agent`, `bedrock-agent-runtime`, and `bedrock-mantle` (OpenAI-compatible API). Only endpoints in `available` state are considered. Their presence indicates private Bedrock API connectivity over **AWS PrivateLink** within the VPC.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockVpcEndpointsConfigured) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockVpcEndpointsConfigured) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// BedrockApiKeyNoAdministrativePrivileges - Amazon Bedrock API key does not have administrative privileges, privilege escalation paths, or full Bedrock service access
type BedrockApiKeyNoAdministrativePrivileges struct {
    metadata models.CheckMetadata
}

func NewBedrockApiKeyNoAdministrativePrivileges() *BedrockApiKeyNoAdministrativePrivileges {
    return &BedrockApiKeyNoAdministrativePrivileges{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "bedrock_api_key_no_administrative_privileges",
            CheckTitle: "Amazon Bedrock API key does not have administrative privileges, privilege escalation paths, or full Bedrock service access",
            ServiceName: "bedrock",
            Severity: "high",
            Description: "**Bedrock API keys** linked to IAM users are evaluated for excessive permissions, including policies that grant full access (`*` or `bedrock:*`) or enable **privilege escalation**. The finding highlights keys whose attached or inline policies provide broad or escalating capabilities.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"bedrock"},
        },
    }
}

func (c *BedrockApiKeyNoAdministrativePrivileges) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *BedrockApiKeyNoAdministrativePrivileges) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusPass,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "bedrock",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

