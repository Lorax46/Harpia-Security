package rules

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// RulesAdminPrivilegeGrantedAlertConfiguredCheck checks for admin privilege change alert
type RulesAdminPrivilegeGrantedAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesAdminPrivilegeGrantedAlertConfiguredCheck() executor.Check {
	return &RulesAdminPrivilegeGrantedAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_admin_privilege_granted_alert_configured",
			CheckTitle: "Admin privilege granted alert configured",
			ServiceName: "rules",
			Severity: "high",
			Description: "Alert should be configured for admin privilege grants",
			RemediationText: "Configure alerts for admin privilege changes in Admin Console > Rules > Alert Rules",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesAdminPrivilegeGrantedAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesAdminPrivilegeGrantedAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "admin_privilege_granted" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Admin privilege granted alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Admin privilege granted alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesGmailEmployeeSpoofingAlertConfiguredCheck checks for employee spoofing alert
type RulesGmailEmployeeSpoofingAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesGmailEmployeeSpoofingAlertConfiguredCheck() executor.Check {
	return &RulesGmailEmployeeSpoofingAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_gmail_employee_spoofing_alert_configured",
			CheckTitle: "Gmail employee spoofing alert configured",
			ServiceName: "rules",
			Severity: "high",
			Description: "Alert should be configured for employee name spoofing attempts",
			RemediationText: "Configure employee spoofing alert in Admin Console > Rules > Alert Rules",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesGmailEmployeeSpoofingAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesGmailEmployeeSpoofingAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "gmail_employee_spoofing" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Gmail employee spoofing alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Gmail employee spoofing alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesGovernmentBackedAttacksAlertConfiguredCheck checks for government-backed attacks alert
type RulesGovernmentBackedAttacksAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesGovernmentBackedAttacksAlertConfiguredCheck() executor.Check {
	return &RulesGovernmentBackedAttacksAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_government_backed_attacks_alert_configured",
			CheckTitle: "Government-backed attacks alert configured",
			ServiceName: "rules",
			Severity: "critical",
			Description: "Alert should be configured for government-backed attack notifications",
			RemediationText: "Enable government-backed attack notifications in Admin Console > Security > Alert Center",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesGovernmentBackedAttacksAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesGovernmentBackedAttacksAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "government_backed_attacks" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Government-backed attacks alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Government-backed attacks alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesLeakedPasswordAlertConfiguredCheck checks for leaked password alert
type RulesLeakedPasswordAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesLeakedPasswordAlertConfiguredCheck() executor.Check {
	return &RulesLeakedPasswordAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_leaked_password_alert_configured",
			CheckTitle: "Leaked password alert configured",
			ServiceName: "rules",
			Severity: "critical",
			Description: "Alert should be configured for leaked password notifications",
			RemediationText: "Configure leaked password alerts in Admin Console > Security > Alert Center",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesLeakedPasswordAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesLeakedPasswordAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "leaked_password" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Leaked password alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Leaked password alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesPasswordChangedAlertConfiguredCheck checks for password changed alert
type RulesPasswordChangedAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesPasswordChangedAlertConfiguredCheck() executor.Check {
	return &RulesPasswordChangedAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_password_changed_alert_configured",
			CheckTitle: "Password changed alert configured",
			ServiceName: "rules",
			Severity: "medium",
			Description: "Alert should be configured for password change notifications",
			RemediationText: "Configure password change alerts in Admin Console > Rules > Alert Rules",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesPasswordChangedAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesPasswordChangedAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "password_changed" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Password changed alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Password changed alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesSuspiciousActivitySuspensionAlertConfiguredCheck checks for suspicious activity suspension alert
type RulesSuspiciousActivitySuspensionAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesSuspiciousActivitySuspensionAlertConfiguredCheck() executor.Check {
	return &RulesSuspiciousActivitySuspensionAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_suspicious_activity_suspension_alert_configured",
			CheckTitle: "Suspicious activity suspension alert configured",
			ServiceName: "rules",
			Severity: "high",
			Description: "Alert should be configured for suspicious activity suspension notifications",
			RemediationText: "Configure suspicious activity suspension alerts in Admin Console > Security > Alert Center",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesSuspiciousActivitySuspensionAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesSuspiciousActivitySuspensionAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "suspicious_activity_suspension" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Suspicious activity suspension alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Suspicious activity suspension alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesSuspiciousLoginAlertConfiguredCheck checks for suspicious login alert
type RulesSuspiciousLoginAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesSuspiciousLoginAlertConfiguredCheck() executor.Check {
	return &RulesSuspiciousLoginAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_suspicious_login_alert_configured",
			CheckTitle: "Suspicious login alert configured",
			ServiceName: "rules",
			Severity: "high",
			Description: "Alert should be configured for suspicious login notifications",
			RemediationText: "Configure suspicious login alerts in Admin Console > Security > Alert Center",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesSuspiciousLoginAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesSuspiciousLoginAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "suspicious_login" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Suspicious login alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Suspicious login alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// RulesSuspiciousProgrammaticLoginAlertConfiguredCheck checks for suspicious programmatic login alert
type RulesSuspiciousProgrammaticLoginAlertConfiguredCheck struct {
	metadata models.CheckMetadata
}

func NewRulesSuspiciousProgrammaticLoginAlertConfiguredCheck() executor.Check {
	return &RulesSuspiciousProgrammaticLoginAlertConfiguredCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "rules_suspicious_programmatic_login_alert_configured",
			CheckTitle: "Suspicious programmatic login alert configured",
			ServiceName: "rules",
			Severity: "high",
			Description: "Alert should be configured for suspicious programmatic login notifications",
			RemediationText: "Configure suspicious programmatic login alerts in Admin Console > Security > Alert Center",
			Categories: []string{"monitoring", "rules"},
		},
	}
}

func (c *RulesSuspiciousProgrammaticLoginAlertConfiguredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *RulesSuspiciousProgrammaticLoginAlertConfiguredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	rules, err := p.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	found := false
	for _, rule := range rules {
		if rule.Type == "alert" && rule.Name == "suspicious_programmatic_login" {
			found = true
			break
		}
	}

	status := models.StatusFail
	msg := "Suspicious programmatic login alert is not configured"
	if found {
		status = models.StatusPass
		msg = "Suspicious programmatic login alert is configured"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "rules",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
