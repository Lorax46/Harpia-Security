package cloudfunctions

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"google.golang.org/api/cloudfunctions/v1"
)

type cloudfunctionsProvider interface {
	CloudFunctions(ctx context.Context) (*cloudfunctions.Service, error)
	ProjectID() string
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. CloudFunctionPublicAccessCheck
// ─────────────────────────────────────────────────────────────────────────────

type CloudFunctionPublicAccessCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFunctionPublicAccessCheck() *CloudFunctionPublicAccessCheck {
	return &CloudFunctionPublicAccessCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudfunction_public_access",
			CheckTitle:      "Cloud Function should not be publicly accessible",
			ServiceName:     "cloudfunctions",
			Severity:        "critical",
			ResourceType:    "Function",
			Description:     "Cloud Functions should not be publicly accessible",
			RemediationText: "Remove allUsers from Cloud Function IAM",
			Categories:      []string{"cloudfunctions", "serverless"},
		},
	}
}

func (c *CloudFunctionPublicAccessCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFunctionPublicAccessCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudfunctionsProvider")
	}
	cfService, err := p.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := cfService.Projects.Locations.Functions.List("projects/" + p.ProjectID() + "/locations/-")
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			isPublic := false
			policy, err := cfService.Projects.Locations.Functions.GetIamPolicy(fn.Name).Context(ctx).Do()
			if err == nil && policy != nil {
				for _, binding := range policy.Bindings {
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							isPublic = true
							break
						}
					}
					if isPublic {
						break
					}
				}
			}
			status := models.StatusPass
			ext := "Function is not publicly accessible"
			if isPublic {
				status = models.StatusFail
				ext = "Function is publicly accessible"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "cloudfunctions",
				ResourceID:     fn.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. CloudFunctionEncryptionCheck
// ─────────────────────────────────────────────────────────────────────────────

type CloudFunctionEncryptionCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFunctionEncryptionCheck() *CloudFunctionEncryptionCheck {
	return &CloudFunctionEncryptionCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudfunction_encryption",
			CheckTitle:      "Cloud Function should use customer-managed encryption keys (CMEK)",
			ServiceName:     "cloudfunctions",
			Severity:        "high",
			ResourceType:    "Function",
			Description:     "Cloud Functions should be encrypted with customer-managed encryption keys (CMEK) rather than Google-managed keys",
			RemediationText: "Configure a Cloud KMS key for the Cloud Function",
			Categories:      []string{"cloudfunctions", "serverless", "encryption"},
		},
	}
}

func (c *CloudFunctionEncryptionCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFunctionEncryptionCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudfunctionsProvider")
	}
	cfService, err := p.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := cfService.Projects.Locations.Functions.List("projects/" + p.ProjectID() + "/locations/-")
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			hasCMEK := fn.KmsKeyName != ""
			status := models.StatusPass
			ext := "Function uses customer-managed encryption key (CMEK)"
			if !hasCMEK {
				status = models.StatusFail
				ext = "Function uses Google-managed encryption key instead of CMEK"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "cloudfunctions",
				ResourceID:     fn.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CloudFunctionLoggingCheck
// ─────────────────────────────────────────────────────────────────────────────

type CloudFunctionLoggingCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFunctionLoggingCheck() *CloudFunctionLoggingCheck {
	return &CloudFunctionLoggingCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudfunction_logging",
			CheckTitle:      "Cloud Function should have logging enabled",
			ServiceName:     "cloudfunctions",
			Severity:        "medium",
			ResourceType:    "Function",
			Description:     "Cloud Functions should have logging enabled to track execution and diagnose issues",
			RemediationText: "Ensure the Cloud Function has logging configured and the logging service account has permissions to write logs",
			Categories:      []string{"cloudfunctions", "serverless", "logging"},
		},
	}
}

func (c *CloudFunctionLoggingCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFunctionLoggingCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudfunctionsProvider")
	}
	cfService, err := p.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := cfService.Projects.Locations.Functions.List("projects/" + p.ProjectID() + "/locations/-")
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			hasLogging := false
			if fn.EnvironmentVariables != nil {
				for key := range fn.EnvironmentVariables {
					if strings.Contains(strings.ToUpper(key), "LOG") || strings.Contains(strings.ToUpper(key), "STACKDRIVER") {
						hasLogging = true
						break
					}
				}
			}
			if !hasLogging && fn.Labels != nil {
				for key := range fn.Labels {
					if strings.Contains(strings.ToUpper(key), "LOG") {
						hasLogging = true
						break
					}
				}
			}
			status := models.StatusPass
			ext := "Function has logging configuration"
			if !hasLogging {
				status = models.StatusFail
				ext = "Function does not have explicit logging configuration"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "cloudfunctions",
				ResourceID:     fn.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CloudFunctionVpcConnectorCheck
// ─────────────────────────────────────────────────────────────────────────────

type CloudFunctionVpcConnectorCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFunctionVpcConnectorCheck() *CloudFunctionVpcConnectorCheck {
	return &CloudFunctionVpcConnectorCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudfunction_vpc_connector",
			CheckTitle:      "Cloud Function should use a VPC connector",
			ServiceName:     "cloudfunctions",
			Severity:        "high",
			ResourceType:    "Function",
			Description:     "Cloud Functions should be connected to a VPC to access private resources and reduce exposure to the public internet",
			RemediationText: "Configure a VPC connector for the Cloud Function",
			Categories:      []string{"cloudfunctions", "serverless", "networking"},
		},
	}
}

func (c *CloudFunctionVpcConnectorCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFunctionVpcConnectorCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudfunctionsProvider")
	}
	cfService, err := p.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := cfService.Projects.Locations.Functions.List("projects/" + p.ProjectID() + "/locations/-")
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			hasVpcConnector := fn.VpcConnector != ""
			status := models.StatusPass
			ext := "Function uses VPC connector"
			if !hasVpcConnector {
				status = models.StatusFail
				ext = "Function does not use a VPC connector"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "cloudfunctions",
				ResourceID:     fn.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CloudFunctionServiceAccountCheck
// ─────────────────────────────────────────────────────────────────────────────

type CloudFunctionServiceAccountCheck struct {
	metadata models.CheckMetadata
}

func NewCloudFunctionServiceAccountCheck() *CloudFunctionServiceAccountCheck {
	return &CloudFunctionServiceAccountCheck{
		metadata: models.CheckMetadata{
			Provider:        "gcp",
			CheckID:         "cloudfunction_service_account",
			CheckTitle:      "Cloud Function should use a custom service account",
			ServiceName:     "cloudfunctions",
			Severity:        "high",
			ResourceType:    "Function",
			Description:     "Cloud Functions should use a custom service account with least privilege instead of the default compute service account",
			RemediationText: "Create a custom service account with minimum required permissions and assign it to the Cloud Function",
			Categories:      []string{"cloudfunctions", "serverless", "iam"},
		},
	}
}

func (c *CloudFunctionServiceAccountCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CloudFunctionServiceAccountCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(cloudfunctionsProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa cloudfunctionsProvider")
	}
	cfService, err := p.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	req := cfService.Projects.Locations.Functions.List("projects/" + p.ProjectID() + "/locations/-")
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			usesCustomSA := true
			if fn.ServiceAccountEmail == "" {
				usesCustomSA = false
			} else {
				sa := fn.ServiceAccountEmail
				if strings.Contains(sa, "@developer.gserviceaccount.com") ||
					strings.Contains(sa, "compute@developer.gserviceaccount.com") ||
					strings.Contains(sa, ".iam.gserviceaccount.com") && strings.Contains(sa, "-compute@") {
					usesCustomSA = false
				}
			}
			status := models.StatusPass
			ext := "Function uses a custom service account"
			if !usesCustomSA {
				status = models.StatusFail
				ext = "Function uses the default compute service account or no service account"
			}
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: ext,
				Provider:       "gcp",
				Service:        "cloudfunctions",
				ResourceID:     fn.Name,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now(),
			})
		}
		return nil
	})
	return findings, err
}