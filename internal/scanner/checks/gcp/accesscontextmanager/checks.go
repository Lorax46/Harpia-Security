package accesscontextmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/accesscontextmanager/v1"
)

type accessContextManagerProvider interface {
	AccessContextManager(ctx context.Context) (*accesscontextmanager.Service, error)
	ProjectID() string
}

// AccessLevelCheck verifica se os access levels estão configurados
type AccessLevelCheck struct {
	metadata models.CheckMetadata
}

func NewAccessLevelCheck() *AccessLevelCheck {
	return &AccessLevelCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "accesscontextmanager_access_level",
			CheckTitle:      "Access Context Manager access levels are configured",
			ServiceName:     "accesscontextmanager",
			Severity:        "medium",
			Description:     "Access Context Manager should have access levels configured",
			RemediationText: "Configure access levels in Access Context Manager",
			Categories:      []string{"identity"},
		},
	}
}

func (c *AccessLevelCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessLevelCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(accessContextManagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement accessContextManagerProvider")
	}
	svc, err := p.AccessContextManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policies, err := svc.AccessPolicies.List().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %w", err)
	}

	if len(policies.AccessPolicies) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No access policies found",
			Provider: "gcp", Service: "accesscontextmanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
		return findings, nil
	}

	for _, policy := range policies.AccessPolicies {
		levels, err := svc.AccessPolicies.AccessLevels.List(policy.Name).Do()
		if err != nil {
			continue
		}
		if len(levels.AccessLevels) == 0 {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("No access levels found in policy %s", policy.Name),
				ResourceID: policy.Name,
				Provider: "gcp", Service: "accesscontextmanager",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		} else {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Found %d access levels in policy %s", len(levels.AccessLevels), policy.Name),
				ResourceID: policy.Name,
				Provider: "gcp", Service: "accesscontextmanager",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// ServicePerimeterCheck verifica se os service perimeters estão configurados
type ServicePerimeterCheck struct {
	metadata models.CheckMetadata
}

func NewServicePerimeterCheck() *ServicePerimeterCheck {
	return &ServicePerimeterCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "accesscontextmanager_service_perimeter",
			CheckTitle:      "Access Context Manager service perimeters are configured",
			ServiceName:     "accesscontextmanager",
			Severity:        "medium",
			Description:     "Access Context Manager should have service perimeters configured",
			RemediationText: "Configure service perimeters in Access Context Manager",
			Categories:      []string{"identity"},
		},
	}
}

func (c *ServicePerimeterCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *ServicePerimeterCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(accessContextManagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement accessContextManagerProvider")
	}
	svc, err := p.AccessContextManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policies, err := svc.AccessPolicies.List().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %w", err)
	}

	for _, policy := range policies.AccessPolicies {
		perimeters, err := svc.AccessPolicies.ServicePerimeters.List(policy.Name).Do()
		if err != nil {
			continue
		}
		if len(perimeters.ServicePerimeters) == 0 {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusFail,
				StatusExtended: fmt.Sprintf("No service perimeters found in policy %s", policy.Name),
				ResourceID: policy.Name,
				Provider: "gcp", Service: "accesscontextmanager",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		} else {
			for _, perimeter := range perimeters.ServicePerimeters {
				findings = append(findings, models.Finding{
					ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
					Description: c.metadata.Description, Severity: c.metadata.Severity,
					Status: models.StatusPass,
					StatusExtended: fmt.Sprintf("Service perimeter %s is configured", perimeter.Name),
					ResourceID: perimeter.Name,
					Provider: "gcp", Service: "accesscontextmanager",
					Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
					FoundAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// GcpUserAccessCheck verifica GCP user access via access levels
type GcpUserAccessCheck struct {
	metadata models.CheckMetadata
}

func NewGcpUserAccessCheck() *GcpUserAccessCheck {
	return &GcpUserAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "accesscontextmanager_gcp_user_access",
			CheckTitle:      "GCP user access is restricted",
			ServiceName:     "accesscontextmanager",
			Severity:        "medium",
			Description:     "GCP user access should be restricted via Access Context Manager",
			RemediationText: "Configure GCP user access restrictions",
			Categories:      []string{"identity"},
		},
	}
}

func (c *GcpUserAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *GcpUserAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(accessContextManagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement accessContextManagerProvider")
	}
	svc, err := p.AccessContextManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policies, err := svc.AccessPolicies.List().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %w", err)
	}

	for _, policy := range policies.AccessPolicies {
		levels, err := svc.AccessPolicies.AccessLevels.List(policy.Name).Do()
		if err != nil {
			continue
		}

		hasGcpUserAccess := false
		for _, level := range levels.AccessLevels {
			if level.Basic != nil {
				for _, condition := range level.Basic.Conditions {
					for _, member := range condition.Members {
						if member == "user:*" || member == "allUsers" {
							hasGcpUserAccess = true
							break
						}
					}
				}
			}
		}

		status := models.StatusPass
		ext := "GCP user access is properly restricted"
		if hasGcpUserAccess {
			status = models.StatusFail
			ext = "GCP user access is not restricted"
		}

		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: ext,
			ResourceID: policy.Name,
			Provider: "gcp", Service: "accesscontextmanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	}

	return findings, nil
}

// AccessPolicyCheck verifica access policies
type AccessPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewAccessPolicyCheck() *AccessPolicyCheck {
	return &AccessPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "accesscontextmanager_access_policy",
			CheckTitle:      "Access policies are configured",
			ServiceName:     "accesscontextmanager",
			Severity:        "medium",
			Description:     "Access policies should be configured",
			RemediationText: "Configure access policies",
			Categories:      []string{"identity"},
		},
	}
}

func (c *AccessPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *AccessPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(accessContextManagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement accessContextManagerProvider")
	}
	svc, err := p.AccessContextManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policies, err := svc.AccessPolicies.List().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %w", err)
	}

	if len(policies.AccessPolicies) == 0 {
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: models.StatusFail,
			StatusExtended: "No access policies found",
			Provider: "gcp", Service: "accesscontextmanager",
			Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
			FoundAt: time.Now(),
		})
	} else {
		for _, policy := range policies.AccessPolicies {
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: models.StatusPass,
				StatusExtended: fmt.Sprintf("Access policy %s is configured", policy.Name),
				ResourceID: policy.Name,
				Provider: "gcp", Service: "accesscontextmanager",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// IngressPolicyCheck verifica ingress policies
type IngressPolicyCheck struct {
	metadata models.CheckMetadata
}

func NewIngressPolicyCheck() *IngressPolicyCheck {
	return &IngressPolicyCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "accesscontextmanager_ingress_policy",
			CheckTitle:      "Ingress policies are configured",
			ServiceName:     "accesscontextmanager",
			Severity:        "medium",
			Description:     "Ingress policies should be configured for service perimeters",
			RemediationText: "Configure ingress policies",
			Categories:      []string{"identity"},
		},
	}
}

func (c *IngressPolicyCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *IngressPolicyCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(accessContextManagerProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement accessContextManagerProvider")
	}
	svc, err := p.AccessContextManager(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	policies, err := svc.AccessPolicies.List().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list access policies: %w", err)
	}

	for _, policy := range policies.AccessPolicies {
		perimeters, err := svc.AccessPolicies.ServicePerimeters.List(policy.Name).Do()
		if err != nil {
			continue
		}

		for _, perimeter := range perimeters.ServicePerimeters {
			// Check if perimeter has ingress policies via status field
			hasIngressPolicy := perimeter.Status != nil && len(perimeter.Status.IngressPolicies) > 0
			status := models.StatusPass
			ext := fmt.Sprintf("Service perimeter %s has ingress policies configured", perimeter.Name)
			if !hasIngressPolicy {
				status = models.StatusFail
				ext = fmt.Sprintf("Service perimeter %s does not have ingress policies configured", perimeter.Name)
			}

			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: ext,
				ResourceID: perimeter.Name,
				Provider: "gcp", Service: "accesscontextmanager",
				Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
				FoundAt: time.Now(),
			})
		}
	}

	return findings, nil
}
