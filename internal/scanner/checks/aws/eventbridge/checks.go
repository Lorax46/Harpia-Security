package eventbridge

import (
    "context"
    "time"

    "github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// EventbridgeBusCrossAccountAccess - AWS EventBridge event bus does not allow cross-account access
type EventbridgeBusCrossAccountAccess struct {
    metadata models.CheckMetadata
}

func NewEventbridgeBusCrossAccountAccess() *EventbridgeBusCrossAccountAccess {
    return &EventbridgeBusCrossAccountAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eventbridge_bus_cross_account_access",
            CheckTitle: "AWS EventBridge event bus does not allow cross-account access",
            ServiceName: "eventbridge",
            Severity: "high",
            Description: "**EventBridge event bus** has a **resource policy** that grants **cross-account event delivery** to principals outside the account, including broad or public access.  Focus is on buses whose policies permit external accounts to send events.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eventbridge"},
        },
    }
}

func (c *EventbridgeBusCrossAccountAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EventbridgeBusCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eventbridge",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EventbridgeGlobalEndpointEventReplicationEnabled - EventBridge global endpoint has event replication enabled
type EventbridgeGlobalEndpointEventReplicationEnabled struct {
    metadata models.CheckMetadata
}

func NewEventbridgeGlobalEndpointEventReplicationEnabled() *EventbridgeGlobalEndpointEventReplicationEnabled {
    return &EventbridgeGlobalEndpointEventReplicationEnabled{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eventbridge_global_endpoint_event_replication_enabled",
            CheckTitle: "EventBridge global endpoint has event replication enabled",
            ServiceName: "eventbridge",
            Severity: "medium",
            Description: "**EventBridge global endpoints** are configured with **event replication** `ENABLED` (not `DISABLED`) so custom events are replicated to both the primary and secondary Regions.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eventbridge"},
        },
    }
}

func (c *EventbridgeGlobalEndpointEventReplicationEnabled) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EventbridgeGlobalEndpointEventReplicationEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eventbridge",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EventbridgeBusExposed - AWS EventBridge event bus policy does not allow public access
type EventbridgeBusExposed struct {
    metadata models.CheckMetadata
}

func NewEventbridgeBusExposed() *EventbridgeBusExposed {
    return &EventbridgeBusExposed{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eventbridge_bus_exposed",
            CheckTitle: "AWS EventBridge event bus policy does not allow public access",
            ServiceName: "eventbridge",
            Severity: "high",
            Description: "EventBridge event bus resource policy is evaluated for **public access**, such as a `Principal: '*'` or overly broad conditions that allow any AWS account to publish events or manage rules on the bus.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eventbridge"},
        },
    }
}

func (c *EventbridgeBusExposed) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EventbridgeBusExposed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eventbridge",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

// EventbridgeSchemaRegistryCrossAccountAccess - AWS EventBridge schema registry does not allow cross-account access
type EventbridgeSchemaRegistryCrossAccountAccess struct {
    metadata models.CheckMetadata
}

func NewEventbridgeSchemaRegistryCrossAccountAccess() *EventbridgeSchemaRegistryCrossAccountAccess {
    return &EventbridgeSchemaRegistryCrossAccountAccess{
        metadata: models.CheckMetadata{
            Provider: "aws",
            CheckID: "eventbridge_schema_registry_cross_account_access",
            CheckTitle: "AWS EventBridge schema registry does not allow cross-account access",
            ServiceName: "eventbridge",
            Severity: "high",
            Description: "**EventBridge schema registry** resource policies are assessed for **cross-account access**. It identifies statements that grant external or public principals (e.g., `Principal: *` or other accounts) permissions to interact with the registry and its schemas.",
            RemediationText: "See AWS documentation for remediation",
            Categories: []string{"eventbridge"},
        },
    }
}

func (c *EventbridgeSchemaRegistryCrossAccountAccess) Metadata() models.CheckMetadata {
    return c.metadata
}

func (c *EventbridgeSchemaRegistryCrossAccountAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
    return []models.Finding{
        {
            ID: c.metadata.CheckID,
            Title: c.metadata.CheckTitle,
            Description: c.metadata.Description,
            Severity: c.metadata.Severity,
            Status: models.StatusInfo,
            StatusExtended: "Check requires implementation - use AWS SDK",
            Provider: "aws",
            Service: "eventbridge",
            Remediation: c.metadata.RemediationText,
            Categories: c.metadata.Categories,
            FoundAt: time.Now(),
        },
    }, nil
}

