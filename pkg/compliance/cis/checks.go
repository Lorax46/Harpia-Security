// Package cis provides CIS Benchmark compliance checks.
package cis

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

// CISCheck represents a CIS Benchmark check.
type CISCheck struct {
	metadata   models.CheckMetadata
	controlID  string
	severity   string
	provider   string
}

// NewCISCheck creates a new CIS check.
func NewCISCheck(provider, controlID, title, description, severity string) *CISCheck {
	return &CISCheck{
		controlID: controlID,
		severity:  severity,
		provider:  provider,
		metadata: models.CheckMetadata{
			Provider:     provider,
			CheckID:      fmt.Sprintf("cis_%s_%s", provider, controlID),
			CheckTitle:   title,
			Description:  description,
			ServiceName:  "cis",
			Severity:     severity,
			ResourceType: "Compliance",
			Categories:   []string{"cis", "benchmark", provider},
		},
	}
}

func (c *CISCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *CISCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	// CIS checks are typically manual verification or framework-level
	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusManual,
			StatusExtended: fmt.Sprintf("CIS Control %s requires manual verification or framework-level check", c.controlID),
			Provider:       c.provider,
			Service:        "cis",
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		},
	}, nil
}

// CISChecks returns all CIS checks for a provider.
func CISChecks(provider string) []CISCheck {
	switch provider {
	case "aws":
		return cisAWSChecks()
	case "gcp":
		return cisGCPChecks()
	case "azure":
		return cisAzureChecks()
	case "kubernetes":
		return cisKubernetesChecks()
	default:
		return nil
	}
}

func cisAWSChecks() []CISCheck {
	return []CISCheck{
		*NewCISCheck("aws", "1.1", "Maintain current contact details", "Ensure contact email and phone are current", "medium"),
		*NewCISCheck("aws", "1.2", "Ensure security contact information is registered", "Register security contact information", "medium"),
		*NewCISCheck("aws", "1.3", "Ensure security questions are registered", "Register security questions in AWS", "medium"),
		*NewCISCheck("aws", "1.4", "Ensure no root access keys exist", "Delete root access keys", "critical"),
		*NewCISCheck("aws", "1.5", "Ensure MFA is enabled for root", "Enable MFA for root account", "critical"),
		*NewCISCheck("aws", "1.6", "Ensure root hardware MFA is enabled", "Enable hardware MFA for root", "critical"),
		*NewCISCheck("aws", "1.7", "Eliminate use of root account", "Stop using root account for daily tasks", "high"),
		*NewCISCheck("aws", "1.8", "Ensure IAM password policy requires minimum length", "Set password minimum length to 14", "high"),
		*NewCISCheck("aws", "1.9", "Ensure IAM password policy prevents password reuse", "Prevent password reuse", "high"),
		*NewCISCheck("aws", "1.10", "Ensure IAM password policy expires passwords", "Set password expiration", "medium"),
		*NewCISCheck("aws", "2.1", "Ensure CloudTrail is enabled in all regions", "Enable multi-region CloudTrail", "high"),
		*NewCISCheck("aws", "2.2", "Ensure CloudTrail log file validation is enabled", "Enable log file validation", "medium"),
		*NewCISCheck("aws", "2.3", "Ensure S3 bucket access logging is enabled", "Enable S3 access logging", "medium"),
		*NewCISCheck("aws", "2.4", "Ensure CloudTrail logs are encrypted", "Encrypt CloudTrail logs", "high"),
		*NewCISCheck("aws", "3.1", "Ensure VPC flow logging is enabled", "Enable VPC flow logs", "medium"),
		*NewCISCheck("aws", "3.2", "Ensure S3 bucket versioning is enabled", "Enable S3 versioning", "low"),
		*NewCISCheck("aws", "3.3", "Ensure S3 bucket default encryption is enabled", "Enable S3 encryption", "high"),
		*NewCISCheck("aws", "3.4", "Ensure S3 bucket public access is blocked", "Block S3 public access", "high"),
		*NewCISCheck("aws", "4.1", "Ensure security groups do not allow unrestricted ingress", "Restrict security groups", "high"),
		*NewCISCheck("aws", "4.2", "Ensure network ACLs do not allow unrestricted ingress", "Restrict network ACLs", "medium"),
		*NewCISCheck("aws", "5.1", "Ensure IAM password policy prevents password reuse", "Prevent password reuse", "high"),
	}
}

func cisGCPChecks() []CISCheck {
	return []CISCheck{
		*NewCISCheck("gcp", "1.1", "Ensure OS Login is enabled", "Enable OS Login", "high"),
		*NewCISCheck("gcp", "1.2", "Ensure project-level SSH keys are blocked", "Block project-level SSH keys", "high"),
		*NewCISCheck("gcp", "1.3", "Ensure Cloud KMS keys are rotated", "Rotate Cloud KMS keys", "medium"),
		*NewCISCheck("gcp", "1.4", "Ensure IAM default service account is not used", "Disable default service account", "high"),
		*NewCISCheck("gcp", "1.5", "Ensure Kubernetes logging is enabled", "Enable GKE logging", "high"),
		*NewCISCheck("gcp", "1.6", "Ensure private cluster is enabled", "Enable private GKE clusters", "high"),
		*NewCISCheck("gcp", "1.7", "Ensure shielded nodes are enabled", "Enable shielded nodes", "high"),
	}
}

func cisAzureChecks() []CISCheck {
	return []CISCheck{
		*NewCISCheck("azure", "1.1", "Ensure MFA is enabled for all users", "Enable MFA for all users", "critical"),
		*NewCISCheck("azure", "1.2", "Ensure self-service password reset is enabled", "Enable self-service password reset", "medium"),
		*NewCISCheck("azure", "2.1", "Ensure Microsoft Defender for Cloud is enabled", "Enable Defender for Cloud", "high"),
		*NewCISCheck("azure", "2.2", "Ensure diagnostic logging is enabled", "Enable diagnostic logging", "high"),
		*NewCISCheck("azure", "3.1", "Ensure storage account encryption is enabled", "Enable storage encryption", "high"),
		*NewCISCheck("azure", "3.2", "Ensure storage account public access is disabled", "Disable public storage access", "high"),
	}
}

func cisKubernetesChecks() []CISCheck {
	return []CISCheck{
		*NewCISCheck("kubernetes", "1.1", "Ensure master node file permissions", "Set proper file permissions", "medium"),
		*NewCISCheck("kubernetes", "1.2", "Ensure API server security", "Secure API server configuration", "high"),
		*NewCISCheck("kubernetes", "1.3", "Ensure controller manager security", "Secure controller manager", "medium"),
		*NewCISCheck("kubernetes", "1.4", "Ensure scheduler security", "Secure scheduler configuration", "low"),
		*NewCISCheck("kubernetes", "2.1", "Ensure etcd encryption", "Enable etcd encryption", "high"),
		*NewCISCheck("kubernetes", "3.1", "Ensure control plane security", "Secure control plane", "medium"),
		*NewCISCheck("kubernetes", "4.1", "Ensure worker node security", "Secure worker nodes", "high"),
		*NewCISCheck("kubernetes", "5.1", "Ensure network policies", "Apply network policies", "high"),
		*NewCISCheck("kubernetes", "5.2", "Ensure pod security standards", "Apply pod security standards", "high"),
	}
}
