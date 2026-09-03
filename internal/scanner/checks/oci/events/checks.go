package events

import (
	"context"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// EventsRuleIamPolicyChanges - high
type EventsRuleIamPolicyChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleIamPolicyChanges cria nova instância
func NewEventsRuleIamPolicyChanges() *EventsRuleIamPolicyChanges {
	return &EventsRuleIamPolicyChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_iam_policy_changes",
			CheckTitle:     "Event rule monitoring IAM policy changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** configured to capture **IAM policy create, update, and delete** events (`com.oraclecloud.identitycontrolplane.createpolicy`, `com",
			RemediationText: "Create OCI Events rules for `...createpolicy`, `...updatepolicy`, and `...deletepolicy` with a **not",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleIamPolicyChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleIamPolicyChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleCloudguardProblems - high
type EventsRuleCloudguardProblems struct {
	metadata models.CheckMetadata
}

// NewEventsRuleCloudguardProblems cria nova instância
func NewEventsRuleCloudguardProblems() *EventsRuleCloudguardProblems {
	return &EventsRuleCloudguardProblems{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_cloudguard_problems",
			CheckTitle:     "Event rule monitoring Cloud Guard problems has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** subscribe to **Cloud Guard problem lifecycle events**-`com.oraclecloud.cloudguard.problemdetected`, `com.oraclecloud.cloudguard.p",
			RemediationText: "Implement **event-driven alerts** for Cloud Guard problem lifecycle events and route them to trusted",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleCloudguardProblems) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleCloudguardProblems) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleVcnChanges - medium
type EventsRuleVcnChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleVcnChanges cria nova instância
func NewEventsRuleVcnChanges() *EventsRuleVcnChanges {
	return &EventsRuleVcnChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_vcn_changes",
			CheckTitle:     "Event rule monitoring VCN changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "medium",
			Description:    "**OCI Events rules** exist to capture **VCN lifecycle changes** (`create`, `update`, `delete`) via event types `com.oraclecloud.virtualnetwork.createv",
			RemediationText: "Create and enable **Events rules** for VCN lifecycle changes (**create**, **update**, **delete**) wi",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleVcnChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleVcnChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleIdpGroupMappingChanges - high
type EventsRuleIdpGroupMappingChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleIdpGroupMappingChanges cria nova instância
func NewEventsRuleIdpGroupMappingChanges() *EventsRuleIdpGroupMappingChanges {
	return &EventsRuleIdpGroupMappingChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_idp_group_mapping_changes",
			CheckTitle:     "Event rule for IdP group mapping changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** monitor **IdP group mapping changes** with **notification actions** for `com.oraclecloud.identitycontrolplane.addidpgroupmapping`",
			RemediationText: "Define **Events rules** for IdP group mapping changes (`com.oraclecloud.identitycontrolplane.addidpg",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleIdpGroupMappingChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleIdpGroupMappingChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleIamGroupChanges - high
type EventsRuleIamGroupChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleIamGroupChanges cria nova instância
func NewEventsRuleIamGroupChanges() *EventsRuleIamGroupChanges {
	return &EventsRuleIamGroupChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_iam_group_changes",
			CheckTitle:     "Event rule monitoring IAM group changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** monitor **IAM group lifecycle events** (`creategroup`, `updategroup`, `deletegroup`) and include **notification actions** to gene",
			RemediationText: "Create **Events rules** for IAM group `create`, `update`, and `delete` and route them to **Notificat",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleIamGroupChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleIamGroupChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleNetworkGatewayChanges - high
type EventsRuleNetworkGatewayChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleNetworkGatewayChanges cria nova instância
func NewEventsRuleNetworkGatewayChanges() *EventsRuleNetworkGatewayChanges {
	return &EventsRuleNetworkGatewayChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_network_gateway_changes",
			CheckTitle:     "Event rule monitoring network gateway changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** monitor **network gateway** lifecycle and attachment changes (DRG, Internet, NAT, Service, and Local Peering gateways) and includ",
			RemediationText: "Define **event rules** that match `create`, `update`, `delete`, `attach`, and `detach` actions for a",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleNetworkGatewayChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleNetworkGatewayChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleIdentityProviderChanges - high
type EventsRuleIdentityProviderChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleIdentityProviderChanges cria nova instância
func NewEventsRuleIdentityProviderChanges() *EventsRuleIdentityProviderChanges {
	return &EventsRuleIdentityProviderChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_identity_provider_changes",
			CheckTitle:     "Event rule for identity provider changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** monitor **IAM identity provider** creation, update, and deletion and include a **notification action**. The evaluation identifies",
			RemediationText: "Configure rules to capture **identity provider** `create`, `update`, and `delete` events and send no",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleIdentityProviderChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleIdentityProviderChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleLocalUserAuthentication - medium
type EventsRuleLocalUserAuthentication struct {
	metadata models.CheckMetadata
}

// NewEventsRuleLocalUserAuthentication cria nova instância
func NewEventsRuleLocalUserAuthentication() *EventsRuleLocalUserAuthentication {
	return &EventsRuleLocalUserAuthentication{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_local_user_authentication",
			CheckTitle:     "Event rule monitoring local OCI user authentication has notification actions configured",
			ServiceName:    "events",
			Severity:       "medium",
			Description:    "**OCI Events rules** targeting `com.oraclecloud.identitysignon.interactivelogin` are assessed for configured **notification actions** to monitor local",
			RemediationText: "Create an Events rule for `com.oraclecloud.identitysignon.interactivelogin` with **notification acti",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleLocalUserAuthentication) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleLocalUserAuthentication) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleRouteTableChanges - high
type EventsRuleRouteTableChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleRouteTableChanges cria nova instância
func NewEventsRuleRouteTableChanges() *EventsRuleRouteTableChanges {
	return &EventsRuleRouteTableChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_route_table_changes",
			CheckTitle:     "Event rule for route table changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** for **VCN route tables** monitor lifecycle and compartment changes and include **notification actions**.  The evaluation looks fo",
			RemediationText: "Create an **Events rule** that captures route table `create`, `update`, `delete`, and `changeCompart",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleRouteTableChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleRouteTableChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleNetworkSecurityGroupChanges - medium
type EventsRuleNetworkSecurityGroupChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleNetworkSecurityGroupChanges cria nova instância
func NewEventsRuleNetworkSecurityGroupChanges() *EventsRuleNetworkSecurityGroupChanges {
	return &EventsRuleNetworkSecurityGroupChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_network_security_group_changes",
			CheckTitle:     "Event rule monitoring network security group changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "medium",
			Description:    "**OCI Events rules** targeting **Network Security Group (NSG)** changes are evaluated for **notification actions**. Monitored events: `createnetworkse",
			RemediationText: "Implement **Events** rules for NSG lifecycle changes with **notification actions** to a monitored to",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleNetworkSecurityGroupChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleNetworkSecurityGroupChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleUserChanges - high
type EventsRuleUserChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleUserChanges cria nova instância
func NewEventsRuleUserChanges() *EventsRuleUserChanges {
	return &EventsRuleUserChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_user_changes",
			CheckTitle:     "Event rule monitoring user changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** targeting **IAM user changes** (e.g., `com.oraclecloud.identitycontrolplane.createuser` and related update/delete/state events) a",
			RemediationText: "Create and maintain **Events rules** for IAM user lifecycle changes and attach reliable **notificati",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleUserChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleUserChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsRuleSecurityListChanges - high
type EventsRuleSecurityListChanges struct {
	metadata models.CheckMetadata
}

// NewEventsRuleSecurityListChanges cria nova instância
func NewEventsRuleSecurityListChanges() *EventsRuleSecurityListChanges {
	return &EventsRuleSecurityListChanges{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_rule_security_list_changes",
			CheckTitle:     "Event rule monitoring security list changes has notification actions configured",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Events rules** for VCN **security lists** monitor lifecycle changes-create, update, delete, and compartment moves-and include **notification act",
			RemediationText: "Define **Events** rules for security list create/update/delete and route them to **Notifications** o",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsRuleSecurityListChanges) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsRuleSecurityListChanges) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

// EventsNotificationTopicAndSubscriptionExists - high
type EventsNotificationTopicAndSubscriptionExists struct {
	metadata models.CheckMetadata
}

// NewEventsNotificationTopicAndSubscriptionExists cria nova instância
func NewEventsNotificationTopicAndSubscriptionExists() *EventsNotificationTopicAndSubscriptionExists {
	return &EventsNotificationTopicAndSubscriptionExists{
		metadata: models.CheckMetadata{
			Provider:       "oci",
			CheckID:        "events_notification_topic_and_subscription_exists",
			CheckTitle:     "Tenancy has at least one notification topic with active subscriptions",
			ServiceName:    "events",
			Severity:       "high",
			Description:    "**OCI Notifications** is evaluated for the existence of at least one **topic** that has one or more **subscriptions**.  The focus is on whether subscr",
			RemediationText: "Create a centralized **Notifications** topic with one or more **subscriptions**, and route critical ",
			Categories:     []string{"events"},
		},
	}
}

// Metadata retorna os metadados
func (c *EventsNotificationTopicAndSubscriptionExists) Metadata() models.CheckMetadata {
	return c.metadata
}

// Execute executa o check
func (c *EventsNotificationTopicAndSubscriptionExists) Execute(ctx context.Context) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
		},
	}, nil
}

