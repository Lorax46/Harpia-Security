package directory

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	gwProv "github.com/Lorax46/Harpia-Security/internal/scanner/providers/googleworkspace"
)

// DirectorySuperAdminCountCheck checks that the number of super admins is minimized
type DirectorySuperAdminCountCheck struct {
	metadata models.CheckMetadata
}

func NewDirectorySuperAdminCountCheck() executor.Check {
	return &DirectorySuperAdminCountCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "directory_super_admin_count",
			CheckTitle: "Super administrator count minimized",
			ServiceName: "directory",
			Severity: "high",
			Description: "The number of super administrator accounts should be minimized to reduce risk",
			RemediationText: "Minimize the number of super administrator accounts and use delegated roles instead",
			Categories: []string{"identity", "directory"},
		},
	}
}

func (c *DirectorySuperAdminCountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DirectorySuperAdminCountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	superAdminCount := 0
	for _, u := range users {
		if u.IsAdmin {
			superAdminCount++
		}
	}

	maxSuperAdmins := 5
	status := models.StatusPass
	msg := fmt.Sprintf("Number of super administrators: %d (within limit of %d)", superAdminCount, maxSuperAdmins)

	if superAdminCount > maxSuperAdmins {
		status = models.StatusFail
		msg = fmt.Sprintf("Too many super administrators: %d (max recommended: %d)", superAdminCount, maxSuperAdmins)
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "directory",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}

// DirectorySuperAdminOnlyAdminRolesCheck checks that only super admins have admin roles
type DirectorySuperAdminOnlyAdminRolesCheck struct {
	metadata models.CheckMetadata
}

func NewDirectorySuperAdminOnlyAdminRolesCheck() executor.Check {
	return &DirectorySuperAdminOnlyAdminRolesCheck{
		metadata: models.CheckMetadata{
			Provider: "googleworkspace",
			CheckID: "directory_super_admin_only_admin_roles",
			CheckTitle: "Only super admins have admin roles",
			ServiceName: "directory",
			Severity: "high",
			Description: "Only super administrator accounts should have admin roles assigned",
			RemediationText: "Remove admin roles from non-super-admin accounts and use delegated roles",
			Categories: []string{"identity", "directory"},
		},
	}
}

func (c *DirectorySuperAdminOnlyAdminRolesCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *DirectorySuperAdminOnlyAdminRolesCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(gwProv.GoogleWorkspaceProviderClient)
	if !ok {
		return nil, fmt.Errorf("provider does not implement GoogleWorkspaceProviderClient")
	}

	users, err := p.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Check for delegated admins with elevated privileges
	delegatedAdmins := 0
	for _, u := range users {
		if u.IsDelegatedAdmin {
			delegatedAdmins++
		}
	}

	status := models.StatusPass
	msg := "All admin privileges are held by super administrators only"

	if delegatedAdmins > 0 {
		status = models.StatusFail
		msg = fmt.Sprintf("Found %d delegated administrators with elevated privileges", delegatedAdmins)
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		ResourceID: "domain", Provider: "googleworkspace", Service: "directory",
		Remediation: c.metadata.RemediationText, Categories: c.metadata.Categories,
	}}, nil
}
