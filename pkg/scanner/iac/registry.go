// Package iac provides Infrastructure as Code security checks.
package iac

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// NewIACChecks returns all IaC security checks.
func NewIACChecks() []CheckFactory {
	return []CheckFactory{
		// Terraform checks
		{ID: "terraform_state_encryption", New: func() Checker { return NewTerraformStateEncryptionCheck() }},
		{ID: "terraform_no_hardcoded_secrets", New: func() Checker { return NewTerraformNoHardcodedSecretsCheck() }},
		{ID: "terraform_version_pinned", New: func() Checker { return NewTerraformVersionPinnedCheck() }},
		{ID: "terraform_remote_state", New: func() Checker { return NewTerraformRemoteStateCheck() }},
		{ID: "terraform_no_public_s3", New: func() Checker { return NewTerraformNoPublicS3Check() }},

		// CloudFormation checks
		{ID: "cloudformation_stack_policy", New: func() Checker { return NewCloudFormationStackPolicyCheck() }},
		{ID: "cloudformation_no_plaintext_secrets", New: func() Checker { return NewCloudFormationNoPlaintextSecretsCheck() }},
		{ID: "cloudformation_encryption_enabled", New: func() Checker { return NewCloudFormationEncryptionEnabledCheck() }},
		{ID: "cloudformation_termination_protection", New: func() Checker { return NewCloudFormationTerminationProtectionCheck() }},

		// Helm checks
		{ID: "helm_values_no_secrets", New: func() Checker { return NewHelmValuesNoSecretsCheck() }},
		{ID: "helm_chart_signed", New: func() Checker { return NewHelmChartSignedCheck() }},
		{ID: "helm_security_context", New: func() Checker { return NewHelmSecurityContextCheck() }},

		// Dockerfile checks
		{ID: "dockerfile_non_root_user", New: func() Checker { return NewDockerfileNonRootUserCheck() }},
		{ID: "dockerfile_no_privileged", New: func() Checker { return NewDockerfileNoPrivilegedCheck() }},
		{ID: "dockerfile_healthcheck", New: func() Checker { return NewDockerfileHealthcheckCheck() }},
		{ID: "dockerfile_no_latest_tag", New: func() Checker { return NewDockerfileNoLatestTagCheck() }},
	}
}

// CheckFactory creates new check instances.
type CheckFactory struct {
	ID  string
	New func() Checker
}

// Checker is the interface for IaC security checks.
type Checker interface {
	Metadata() models.CheckMetadata
	Execute(ctx context.Context, provider interface{}) ([]models.Finding, error)
}

// TerraformStateEncryptionCheck ensures Terraform state is encrypted.
type TerraformStateEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformStateEncryptionCheck() *TerraformStateEncryptionCheck {
	return &TerraformStateEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider: "terraform", CheckID: "terraform_state_encryption",
			CheckTitle: "Ensure Terraform state is encrypted",
			Description: "Terraform state files should be encrypted at rest",
			ServiceName: "terraform", Severity: "high", ResourceType: "State",
			Categories: []string{"terraform", "encryption"},
		},
	}
}

func (c *TerraformStateEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformStateEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(TerraformProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement TerraformProvider")
	}
	findings := []models.Finding{}
	states, err := p.ListStates(ctx)
	if err != nil {
		return nil, err
	}
	for _, state := range states {
		if !state.Encrypted {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Terraform state %s is not encrypted", state.Name),
				ResourceID: state.Name, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Terraform state %s is encrypted", state.Name),
				ResourceID: state.Name, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// TerraformNoHardcodedSecretsCheck ensures no hardcoded secrets in Terraform.
type TerraformNoHardcodedSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformNoHardcodedSecretsCheck() *TerraformNoHardcodedSecretsCheck {
	return &TerraformNoHardcodedSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "terraform", CheckID: "terraform_no_hardcoded_secrets",
			CheckTitle: "Ensure no hardcoded secrets in Terraform",
			Description: "Terraform configurations should not contain hardcoded secrets",
			ServiceName: "terraform", Severity: "critical", ResourceType: "Configuration",
			Categories: []string{"terraform", "secrets"},
		},
	}
}

func (c *TerraformNoHardcodedSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformNoHardcodedSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(TerraformProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement TerraformProvider")
	}
	findings := []models.Finding{}
	configs, err := p.ListConfigurations(ctx)
	if err != nil {
		return nil, err
	}
	for _, config := range configs {
		if config.HasHardcodedSecrets {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Terraform config %s contains hardcoded secrets", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Terraform config %s has no hardcoded secrets", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// TerraformVersionPinnedCheck ensures Terraform versions are pinned.
type TerraformVersionPinnedCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformVersionPinnedCheck() *TerraformVersionPinnedCheck {
	return &TerraformVersionPinnedCheck{
		metadata: models.CheckMetadata{
			Provider: "terraform", CheckID: "terraform_version_pinned",
			CheckTitle: "Ensure Terraform versions are pinned",
			Description: "Terraform configurations should pin provider and module versions",
			ServiceName: "terraform", Severity: "medium", ResourceType: "Configuration",
			Categories: []string{"terraform", "versioning"},
		},
	}
}

func (c *TerraformVersionPinnedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformVersionPinnedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(TerraformProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement TerraformProvider")
	}
	findings := []models.Finding{}
	configs, err := p.ListConfigurations(ctx)
	if err != nil {
		return nil, err
	}
	for _, config := range configs {
		if !config.VersionsPinned {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Terraform config %s does not pin versions", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Terraform config %s pins versions", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// TerraformRemoteStateCheck ensures Terraform uses remote state.
type TerraformRemoteStateCheck struct {
	metadata models.CheckMetadata
}

func NewTerraformRemoteStateCheck() *TerraformRemoteStateCheck {
	return &TerraformRemoteStateCheck{
		metadata: models.CheckMetadata{
			Provider: "terraform", CheckID: "terraform_remote_state",
			CheckTitle: "Ensure Terraform uses remote state",
			Description: "Terraform should use remote state backends (S3, GCS, Azure)",
			ServiceName: "terraform", Severity: "medium", ResourceType: "State",
			Categories: []string{"terraform", "state"},
		},
	}
}

func (c *TerraformRemoteStateCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformRemoteStateCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(TerraformProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement TerraformProvider")
	}
	findings := []models.Finding{}
	configs, err := p.ListConfigurations(ctx)
	if err != nil {
		return nil, err
	}
	for _, config := range configs {
		if !config.UsesRemoteState {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Terraform config %s uses local state", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Terraform config %s uses remote state", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// TerraformNoPublicS3Check ensures no public S3 buckets in Terraform.
type TerraformNoPublicS3Check struct {
	metadata models.CheckMetadata
}

func NewTerraformNoPublicS3Check() *TerraformNoPublicS3Check {
	return &TerraformNoPublicS3Check{
		metadata: models.CheckMetadata{
			Provider: "terraform", CheckID: "terraform_no_public_s3",
			CheckTitle: "Ensure no public S3 buckets in Terraform",
			Description: "Terraform should not create public S3 buckets",
			ServiceName: "terraform", Severity: "high", ResourceType: "Configuration",
			Categories: []string{"terraform", "s3", "public-access"},
		},
	}
}

func (c *TerraformNoPublicS3Check) Metadata() models.CheckMetadata { return c.metadata }

func (c *TerraformNoPublicS3Check) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(TerraformProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement TerraformProvider")
	}
	findings := []models.Finding{}
	configs, err := p.ListConfigurations(ctx)
	if err != nil {
		return nil, err
	}
	for _, config := range configs {
		if config.HasPublicS3 {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Terraform config %s creates public S3 buckets", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Terraform config %s does not create public S3 buckets", config.Path),
				ResourceID: config.Path, Provider: "terraform", Service: "terraform",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// CloudFormationStackPolicyCheck ensures CloudFormation stack policy.
type CloudFormationStackPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFormationStackPolicyCheck() *CloudFormationStackPolicyCheck {
	return &CloudFormationStackPolicyCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudformation_stack_policy",
			CheckTitle: "Ensure CloudFormation stack policy is configured",
			Description: "CloudFormation stacks should have stack policies to prevent accidental updates",
			ServiceName: "cloudformation", Severity: "medium", ResourceType: "Stack",
			Categories: []string{"cloudformation", "stack-policy"},
		},
	}
}

func (c *CloudFormationStackPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFormationStackPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(CloudFormationProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement CloudFormationProvider")
	}
	findings := []models.Finding{}
	stacks, err := p.ListStacks(ctx)
	if err != nil {
		return nil, err
	}
	for _, stack := range stacks {
		if !stack.HasStackPolicy {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s does not have a stack policy", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s has a stack policy", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// CloudFormationNoPlaintextSecretsCheck ensures no plaintext secrets in CloudFormation.
type CloudFormationNoPlaintextSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFormationNoPlaintextSecretsCheck() *CloudFormationNoPlaintextSecretsCheck {
	return &CloudFormationNoPlaintextSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudformation_no_plaintext_secrets",
			CheckTitle: "Ensure no plaintext secrets in CloudFormation",
			Description: "CloudFormation templates should not contain plaintext secrets",
			ServiceName: "cloudformation", Severity: "critical", ResourceType: "Template",
			Categories: []string{"cloudformation", "secrets"},
		},
	}
}

func (c *CloudFormationNoPlaintextSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFormationNoPlaintextSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(CloudFormationProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement CloudFormationProvider")
	}
	findings := []models.Finding{}
	templates, err := p.ListTemplates(ctx)
	if err != nil {
		return nil, err
	}
	for _, tmpl := range templates {
		if tmpl.HasPlaintextSecrets {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("CloudFormation template %s contains plaintext secrets", tmpl.Name),
				ResourceID: tmpl.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("CloudFormation template %s has no plaintext secrets", tmpl.Name),
				ResourceID: tmpl.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// CloudFormationEncryptionEnabledCheck ensures CloudFormation encryption.
type CloudFormationEncryptionEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFormationEncryptionEnabledCheck() *CloudFormationEncryptionEnabledCheck {
	return &CloudFormationEncryptionEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudformation_encryption_enabled",
			CheckTitle: "Ensure CloudFormation encryption is enabled",
			Description: "CloudFormation stacks should have encryption enabled for sensitive resources",
			ServiceName: "cloudformation", Severity: "high", ResourceType: "Stack",
			Categories: []string{"cloudformation", "encryption"},
		},
	}
}

func (c *CloudFormationEncryptionEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFormationEncryptionEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(CloudFormationProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement CloudFormationProvider")
	}
	findings := []models.Finding{}
	stacks, err := p.ListStacks(ctx)
	if err != nil {
		return nil, err
	}
	for _, stack := range stacks {
		if !stack.EncryptionEnabled {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s does not have encryption enabled", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s has encryption enabled", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// CloudFormationTerminationProtectionCheck ensures CloudFormation termination protection.
type CloudFormationTerminationProtectionCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFormationTerminationProtectionCheck() *CloudFormationTerminationProtectionCheck {
	return &CloudFormationTerminationProtectionCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "cloudformation_termination_protection",
			CheckTitle: "Ensure CloudFormation termination protection is enabled",
			Description: "CloudFormation stacks should have termination protection enabled",
			ServiceName: "cloudformation", Severity: "medium", ResourceType: "Stack",
			Categories: []string{"cloudformation", "termination-protection"},
		},
	}
}

func (c *CloudFormationTerminationProtectionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFormationTerminationProtectionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(CloudFormationProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement CloudFormationProvider")
	}
	findings := []models.Finding{}
	stacks, err := p.ListStacks(ctx)
	if err != nil {
		return nil, err
	}
	for _, stack := range stacks {
		if !stack.TerminationProtection {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s does not have termination protection", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("CloudFormation stack %s has termination protection", stack.Name),
				ResourceID: stack.Name, Provider: "aws", Service: "cloudformation",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// HelmValuesNoSecretsCheck ensures no secrets in Helm values.
type HelmValuesNoSecretsCheck struct {
	metadata models.CheckMetadata
}

func NewHelmValuesNoSecretsCheck() *HelmValuesNoSecretsCheck {
	return &HelmValuesNoSecretsCheck{
		metadata: models.CheckMetadata{
			Provider: "helm", CheckID: "helm_values_no_secrets",
			CheckTitle: "Ensure no secrets in Helm values",
			Description: "Helm values files should not contain plaintext secrets",
			ServiceName: "helm", Severity: "critical", ResourceType: "Chart",
			Categories: []string{"helm", "secrets"},
		},
	}
}

func (c *HelmValuesNoSecretsCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HelmValuesNoSecretsCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(HelmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement HelmProvider")
	}
	findings := []models.Finding{}
	charts, err := p.ListCharts(ctx)
	if err != nil {
		return nil, err
	}
	for _, chart := range charts {
		if chart.HasSecretsInValues {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Helm chart %s has secrets in values", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Helm chart %s has no secrets in values", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// HelmChartSignedCheck ensures Helm charts are signed.
type HelmChartSignedCheck struct {
	metadata models.CheckMetadata
}

func NewHelmChartSignedCheck() *HelmChartSignedCheck {
	return &HelmChartSignedCheck{
		metadata: models.CheckMetadata{
			Provider: "helm", CheckID: "helm_chart_signed",
			CheckTitle: "Ensure Helm charts are signed",
			Description: "Helm charts should be signed for supply chain security",
			ServiceName: "helm", Severity: "medium", ResourceType: "Chart",
			Categories: []string{"helm", "supply-chain"},
		},
	}
}

func (c *HelmChartSignedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HelmChartSignedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(HelmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement HelmProvider")
	}
	findings := []models.Finding{}
	charts, err := p.ListCharts(ctx)
	if err != nil {
		return nil, err
	}
	for _, chart := range charts {
		if !chart.Signed {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Helm chart %s is not signed", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Helm chart %s is signed", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// HelmSecurityContextCheck ensures Helm security context.
type HelmSecurityContextCheck struct {
	metadata models.CheckMetadata
}

func NewHelmSecurityContextCheck() *HelmSecurityContextCheck {
	return &HelmSecurityContextCheck{
		metadata: models.CheckMetadata{
			Provider: "helm", CheckID: "helm_security_context",
			CheckTitle: "Ensure Helm security context is defined",
			Description: "Helm charts should define security context for pods",
			ServiceName: "helm", Severity: "high", ResourceType: "Chart",
			Categories: []string{"helm", "security"},
		},
	}
}

func (c *HelmSecurityContextCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *HelmSecurityContextCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(HelmProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement HelmProvider")
	}
	findings := []models.Finding{}
	charts, err := p.ListCharts(ctx)
	if err != nil {
		return nil, err
	}
	for _, chart := range charts {
		if !chart.HasSecurityContext {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Helm chart %s does not define security context", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Helm chart %s defines security context", chart.Name),
				ResourceID: chart.Name, Provider: "helm", Service: "helm",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileNonRootUserCheck ensures Dockerfile uses non-root user.
type DockerfileNonRootUserCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileNonRootUserCheck() *DockerfileNonRootUserCheck {
	return &DockerfileNonRootUserCheck{
		metadata: models.CheckMetadata{
			Provider: "dockerfile", CheckID: "dockerfile_non_root_user",
			CheckTitle: "Ensure Dockerfile uses non-root user",
			Description: "Dockerfile should specify a non-root USER instruction",
			ServiceName: "dockerfile", Severity: "high", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "security"},
		},
	}
}

func (c *DockerfileNonRootUserCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileNonRootUserCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DockerfileProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DockerfileProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if !df.HasNonRootUser {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not use non-root user", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s uses non-root user", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileNoPrivilegedCheck ensures Dockerfile does not use privileged mode.
type DockerfileNoPrivilegedCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileNoPrivilegedCheck() *DockerfileNoPrivilegedCheck {
	return &DockerfileNoPrivilegedCheck{
		metadata: models.CheckMetadata{
			Provider: "dockerfile", CheckID: "dockerfile_no_privileged",
			CheckTitle: "Ensure Dockerfile does not use privileged mode",
			Description: "Dockerfile should not use --privileged flag",
			ServiceName: "dockerfile", Severity: "critical", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "security"},
		},
	}
}

func (c *DockerfileNoPrivilegedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileNoPrivilegedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DockerfileProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DockerfileProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if df.HasPrivileged {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s uses privileged mode", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not use privileged mode", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileHealthcheckCheck ensures Dockerfile has HEALTHCHECK.
type DockerfileHealthcheckCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileHealthcheckCheck() *DockerfileHealthcheckCheck {
	return &DockerfileHealthcheckCheck{
		metadata: models.CheckMetadata{
			Provider: "dockerfile", CheckID: "dockerfile_healthcheck",
			CheckTitle: "Ensure Dockerfile has HEALTHCHECK",
			Description: "Dockerfile should include HEALTHCHECK instruction",
			ServiceName: "dockerfile", Severity: "medium", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "reliability"},
		},
	}
}

func (c *DockerfileHealthcheckCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileHealthcheckCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DockerfileProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DockerfileProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if !df.HasHealthcheck {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s does not have HEALTHCHECK", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s has HEALTHCHECK", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// DockerfileNoLatestTagCheck ensures Dockerfile does not use latest tag.
type DockerfileNoLatestTagCheck struct {
	metadata models.CheckMetadata
}

func NewDockerfileNoLatestTagCheck() *DockerfileNoLatestTagCheck {
	return &DockerfileNoLatestTagCheck{
		metadata: models.CheckMetadata{
			Provider: "dockerfile", CheckID: "dockerfile_no_latest_tag",
			CheckTitle: "Ensure Dockerfile does not use latest tag",
			Description: "Dockerfile should use specific base image tags, not 'latest'",
			ServiceName: "dockerfile", Severity: "medium", ResourceType: "Dockerfile",
			Categories: []string{"dockerfile", "supply-chain"},
		},
	}
}

func (c *DockerfileNoLatestTagCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DockerfileNoLatestTagCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(DockerfileProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement DockerfileProvider")
	}
	findings := []models.Finding{}
	dockerfiles, err := p.ListDockerfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, df := range dockerfiles {
		if df.UsesLatestTag {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("Dockerfile %s uses 'latest' tag", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Dockerfile %s uses specific tag", df.Path),
				ResourceID: df.Path, Provider: "dockerfile", Service: "dockerfile",
				Categories: c.metadata.Categories, FoundAt: time.Now(),
			})
		}
	}
	return findings, nil
}

// Provider interfaces for IaC

// TerraformProvider is the interface for Terraform access.
type TerraformProvider interface {
	ListStates(ctx context.Context) ([]TerraformState, error)
	ListConfigurations(ctx context.Context) ([]TerraformConfig, error)
}

// TerraformState represents a Terraform state.
type TerraformState struct {
	Name      string
	Encrypted bool
}

// TerraformConfig represents a Terraform configuration.
type TerraformConfig struct {
	Path               string
	HasHardcodedSecrets bool
	VersionsPinned     bool
	UsesRemoteState    bool
	HasPublicS3        bool
}

// CloudFormationProvider is the interface for CloudFormation access.
type CloudFormationProvider interface {
	ListStacks(ctx context.Context) ([]CloudFormationStack, error)
	ListTemplates(ctx context.Context) ([]CloudFormationTemplate, error)
}

// CloudFormationStack represents a CloudFormation stack.
type CloudFormationStack struct {
	Name                  string
	HasStackPolicy        bool
	EncryptionEnabled     bool
	TerminationProtection bool
}

// CloudFormationTemplate represents a CloudFormation template.
type CloudFormationTemplate struct {
	Name                string
	HasPlaintextSecrets bool
}

// HelmProvider is the interface for Helm access.
type HelmProvider interface {
	ListCharts(ctx context.Context) ([]HelmChart, error)
}

// HelmChart represents a Helm chart.
type HelmChart struct {
	Name                string
	HasSecretsInValues  bool
	Signed              bool
	HasSecurityContext  bool
}

// DockerfileProvider is the interface for Dockerfile access.
type DockerfileProvider interface {
	ListDockerfiles(ctx context.Context) ([]DockerfileIaC, error)
}

// DockerfileIaC represents a Dockerfile for IaC scanning.
type DockerfileIaC struct {
	Path           string
	HasNonRootUser bool
	HasPrivileged  bool
	HasHealthcheck bool
	UsesLatestTag  bool
}
