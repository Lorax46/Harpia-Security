package events

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/events"
)

// NotificationTopicAndSubscriptionExistsCheck verifica se existe tópico de notificação
type NotificationTopicAndSubscriptionExistsCheck struct {
	metadata models.CheckMetadata
}

func NewNotificationTopicAndSubscriptionExistsCheck() *NotificationTopicAndSubscriptionExistsCheck {
	return &NotificationTopicAndSubscriptionExistsCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_notification_topic_and_subscription_exists",
			CheckTitle:      "Ensure notification topic and subscription exist",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Notification topics and subscriptions should exist for alerting",
			RemediationText: "Create notification topics and subscriptions",
			Categories:      []string{"events"},
		},
	}
}

func (c *NotificationTopicAndSubscriptionExistsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *NotificationTopicAndSubscriptionExistsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusInfo,
			StatusExtended: "Check requires implementation - use ons SDK",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

// RuleCloudguardProblemsCheck verifica se existe regra para problemas do Cloudguard
type RuleCloudguardProblemsCheck struct {
	metadata models.CheckMetadata
}

func NewRuleCloudguardProblemsCheck() *RuleCloudguardProblemsCheck {
	return &RuleCloudguardProblemsCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_cloudguard_problems",
			CheckTitle:      "Ensure event rule exists for Cloudguard problems",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for Cloudguard problem detection",
			RemediationText: "Create event rule for Cloudguard problems",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleCloudguardProblemsCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleCloudguardProblemsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasCloudguardRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "cloudguard") {
			hasCloudguardRule = true
			break
		}
	}

	if hasCloudguardRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Cloudguard event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No Cloudguard event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleIamPolicyChangesCheck verifica se existe regra para mudanças de política IAM
type RuleIamPolicyChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleIamPolicyChangesCheck() *RuleIamPolicyChangesCheck {
	return &RuleIamPolicyChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_iam_policy_changes",
			CheckTitle:      "Ensure event rule exists for IAM policy changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for IAM policy change detection",
			RemediationText: "Create event rule for IAM policy changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleIamPolicyChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleIamPolicyChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasIamRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "iam") {
			hasIamRule = true
			break
		}
	}

	if hasIamRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "IAM event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No IAM event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleUserChangesCheck verifica se existe regra para mudanças de usuário
type RuleUserChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleUserChangesCheck() *RuleUserChangesCheck {
	return &RuleUserChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_user_changes",
			CheckTitle:      "Ensure event rule exists for user changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for user change detection",
			RemediationText: "Create event rule for user changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleUserChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleUserChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasUserRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "user") {
			hasUserRule = true
			break
		}
	}

	if hasUserRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "User event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No user event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleIamGroupChangesCheck verifica se existe regra para mudanças de grupo IAM
type RuleIamGroupChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleIamGroupChangesCheck() *RuleIamGroupChangesCheck {
	return &RuleIamGroupChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_iam_group_changes",
			CheckTitle:      "Ensure event rule exists for IAM group changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for IAM group change detection",
			RemediationText: "Create event rule for IAM group changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleIamGroupChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleIamGroupChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasGroupRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "group") {
			hasGroupRule = true
			break
		}
	}

	if hasGroupRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Group event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No group event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleNetworkSecurityGroupChangesCheck verifica se existe regra para mudanças de NSG
type RuleNetworkSecurityGroupChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleNetworkSecurityGroupChangesCheck() *RuleNetworkSecurityGroupChangesCheck {
	return &RuleNetworkSecurityGroupChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_network_security_group_changes",
			CheckTitle:      "Ensure event rule exists for network security group changes",
			ServiceName:     "events",
			Severity:        "medium",
			Description:     "Event rules should exist for network security group change detection",
			RemediationText: "Create event rule for network security group changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleNetworkSecurityGroupChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleNetworkSecurityGroupChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasNsgRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "security") {
			hasNsgRule = true
			break
		}
	}

	if hasNsgRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Network security group event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No network security group event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleVcnChangesCheck verifica se existe regra para mudanças de VCN
type RuleVcnChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleVcnChangesCheck() *RuleVcnChangesCheck {
	return &RuleVcnChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_vcn_changes",
			CheckTitle:      "Ensure event rule exists for VCN changes",
			ServiceName:     "events",
			Severity:        "medium",
			Description:     "Event rules should exist for VCN change detection",
			RemediationText: "Create event rule for VCN changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleVcnChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleVcnChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasVcnRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "vcn") {
			hasVcnRule = true
			break
		}
	}

	if hasVcnRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "VCN event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No VCN event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleRouteTableChangesCheck verifica se existe regra para mudanças de route table
type RuleRouteTableChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleRouteTableChangesCheck() *RuleRouteTableChangesCheck {
	return &RuleRouteTableChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_route_table_changes",
			CheckTitle:      "Ensure event rule exists for route table changes",
			ServiceName:     "events",
			Severity:        "medium",
			Description:     "Event rules should exist for route table change detection",
			RemediationText: "Create event rule for route table changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleRouteTableChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleRouteTableChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasRouteRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "route") {
			hasRouteRule = true
			break
		}
	}

	if hasRouteRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Route table event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No route table event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleSecurityListChangesCheck verifica se existe regra para mudanças de security list
type RuleSecurityListChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleSecurityListChangesCheck() *RuleSecurityListChangesCheck {
	return &RuleSecurityListChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_security_list_changes",
			CheckTitle:      "Ensure event rule exists for security list changes",
			ServiceName:     "events",
			Severity:        "medium",
			Description:     "Event rules should exist for security list change detection",
			RemediationText: "Create event rule for security list changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleSecurityListChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleSecurityListChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasSlRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "security list") {
			hasSlRule = true
			break
		}
	}

	if hasSlRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Security list event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No security list event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleNetworkGatewayChangesCheck verifica se existe regra para mudanças de network gateway
type RuleNetworkGatewayChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleNetworkGatewayChangesCheck() *RuleNetworkGatewayChangesCheck {
	return &RuleNetworkGatewayChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_network_gateway_changes",
			CheckTitle:      "Ensure event rule exists for network gateway changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for network gateway change detection",
			RemediationText: "Create event rule for network gateway changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleNetworkGatewayChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleNetworkGatewayChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasGatewayRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "gateway") {
			hasGatewayRule = true
			break
		}
	}

	if hasGatewayRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Network gateway event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No network gateway event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleIdentityProviderChangesCheck verifica se existe regra para mudanças de identity provider
type RuleIdentityProviderChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleIdentityProviderChangesCheck() *RuleIdentityProviderChangesCheck {
	return &RuleIdentityProviderChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_identity_provider_changes",
			CheckTitle:      "Ensure event rule exists for identity provider changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for identity provider change detection",
			RemediationText: "Create event rule for identity provider changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleIdentityProviderChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleIdentityProviderChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasIdpRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "identity") {
			hasIdpRule = true
			break
		}
	}

	if hasIdpRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Identity provider event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No identity provider event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleIdpGroupMappingChangesCheck verifica se existe regra para mudanças de mapeamento de grupo IDP
type RuleIdpGroupMappingChangesCheck struct {
	metadata models.CheckMetadata
}

func NewRuleIdpGroupMappingChangesCheck() *RuleIdpGroupMappingChangesCheck {
	return &RuleIdpGroupMappingChangesCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_idp_group_mapping_changes",
			CheckTitle:      "Ensure event rule exists for IDP group mapping changes",
			ServiceName:     "events",
			Severity:        "high",
			Description:     "Event rules should exist for IDP group mapping change detection",
			RemediationText: "Create event rule for IDP group mapping changes",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleIdpGroupMappingChangesCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleIdpGroupMappingChangesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasIdpGroupRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "idp") {
			hasIdpGroupRule = true
			break
		}
	}

	if hasIdpGroupRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "IDP group mapping event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No IDP group mapping event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// RuleLocalUserAuthenticationCheck verifica se existe regra para autenticação de usuário local
type RuleLocalUserAuthenticationCheck struct {
	metadata models.CheckMetadata
}

func NewRuleLocalUserAuthenticationCheck() *RuleLocalUserAuthenticationCheck {
	return &RuleLocalUserAuthenticationCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "events_rule_local_user_authentication",
			CheckTitle:      "Ensure event rule exists for local user authentication",
			ServiceName:     "events",
			Severity:        "medium",
			Description:     "Event rules should exist for local user authentication detection",
			RemediationText: "Create event rule for local user authentication",
			Categories:      []string{"events"},
		},
	}
}

func (c *RuleLocalUserAuthenticationCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *RuleLocalUserAuthenticationCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Events() (events.EventsClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Events()")
	}

	client, err := p.Events()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	req := events.ListRulesRequest{
		CompartmentId: &tenancyId,
	}
	rules, err := client.ListRules(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar regras: %w", err)
	}

	hasAuthRule := false
	for _, rule := range rules.Items {
		if rule.DisplayName != nil && strings.Contains(strings.ToLower(*rule.DisplayName), "auth") {
			hasAuthRule = true
			break
		}
	}

	if hasAuthRule {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Local user authentication event rule exists",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	} else {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusFail,
			StatusExtended: "No local user authentication event rule found",
			Provider:       "oci",
			Service:        "events",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}
