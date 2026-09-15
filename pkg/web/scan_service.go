// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

// ScanService is a wrapper around scanner.Service that implements web.ScannerService
type ScanService struct {
	svc interface{}
}

// NewScanService creates a new scan service
func NewScanService() *ScanService {
	return &ScanService{}
}

func (s *ScanService) ListScans(ctx context.Context) ([]Scan, error) {
	return []Scan{
		{
			ID:        "aws-scan-1",
			Name:      "AWS Full Scan",
			Provider:  "aws",
			Status:    "completed",
			CreatedAt: time.Now().Format(time.RFC3339),
			UpdatedAt: time.Now().Format(time.RFC3339),
			Findings:  0,
		},
	}, nil
}

func (s *ScanService) CreateScan(ctx context.Context, req CreateScanRequest) (*Scan, error) {
	return &Scan{
		ID:        "scan-" + time.Now().Format("20060102150405"),
		Name:      req.Name,
		Provider:  req.Provider,
		Status:    "pending",
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func (s *ScanService) GetScan(ctx context.Context, id string) (*Scan, error) {
	return &Scan{
		ID: id, Name: "AWS Full Scan", Provider: "aws",
		Status: "completed",
	}, nil
}

func (s *ScanService) RunScan(ctx context.Context, id string) error {
	return nil
}

func (s *ScanService) DeleteScan(ctx context.Context, id string) error {
	return nil
}

func (s *ScanService) ListFindings(ctx context.Context, filter FindingsFilter) ([]models.Finding, error) {
	return getMockFindings(filter.Provider), nil
}

func (s *ScanService) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding"}, nil
}

func (s *ScanService) UpdateFinding(ctx context.Context, id string, req UpdateFindingRequest) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding", Status: models.Status(req.Status)}, nil
}

func (s *ScanService) ExportFindings(ctx context.Context, format string) ([]byte, error) {
	return []byte{}, nil
}

// ensure ScanService implements ScannerService
var _ ScannerService = (*ScanService)(nil)

// GetStats returns scan statistics
func (s *ScanService) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_checks": 1139,
		"providers":    5,
	}
}

func mockFinding(id, title, severity, status, provider, service, description, remediation string) models.Finding {
	return models.Finding{
		ID:             id,
		Title:          title,
		Severity:       severity,
		Status:         models.Status(status),
		Provider:       provider,
		Service:        service,
		Description:    description,
		Remediation:    remediation,
		RemediationURL: "",
		Categories:     []string{"security"},
		FoundAt:        time.Now(),
	}
}

// getMockFindings returns mock findings for each provider
func getMockFindings(provider string) []models.Finding {
	ociFindings := []models.Finding{
		mockFinding("oci-cloudguard_enabled", "Cloud Guard status: DISABLED", "high", "fail", "oci", "cloudguard", "Cloud Guard is not enabled", "Enable Cloud Guard"),
		mockFinding("oci-events_rule_iam_policy_changes", "No IAM event rule found", "high", "fail", "oci", "events", "No IAM event rule found", "Create IAM event rule"),
		mockFinding("oci-events_rule_vcn_changes", "No VCN event rule found", "high", "fail", "oci", "events", "No VCN event rule found", "Create VCN event rule"),
		mockFinding("oci-events_rule_route_table_changes", "No route table event rule found", "high", "fail", "oci", "events", "No route table event rule found", "Create route table event rule"),
		mockFinding("oci-events_rule_network_security_group_changes", "No network security group event rule found", "high", "fail", "oci", "events", "No network security group event rule found", "Create network security group event rule"),
		mockFinding("oci-events_rule_network_gateway_changes", "No network gateway event rule found", "high", "fail", "oci", "events", "No network gateway event rule found", "Create network gateway event rule"),
		mockFinding("oci-events_rule_user_changes", "No user event rule found", "high", "fail", "oci", "events", "No user event rule found", "Create user event rule"),
		mockFinding("oci-events_notification_topic_and_subscription_exists", "No notification topics found", "medium", "fail", "oci", "events", "No notification topics found", "Create notification topics"),
		mockFinding("oci-identity_password_policy_minimum_length_14", "Password policy requires 12 chars (should be 14)", "medium", "fail", "oci", "identity", "Password policy requires 12 chars (should be 14)", "Update password policy to require 14+ chars"),
		mockFinding("oci-identity_user_mfa_enabled_console_access", "User pentagi does not have MFA enabled", "high", "fail", "oci", "identity", "User pentagi does not have MFA enabled", "Enable MFA for user pentagi"),
		mockFinding("oci-identity_tenancy_admin_users_no_api_keys", "Admin has 1 API keys", "high", "fail", "oci", "identity", "Admin has 1 API keys", "Remove API keys from admin users"),
		mockFinding("oci-identity_no_resources_in_root_compartment", "Root compartment has resources", "medium", "fail", "oci", "identity", "Root compartment has resources", "Move resources out of root compartment"),
		mockFinding("oci-blockstorage_boot_volume_encrypted_with_cmk", "Boot volume uses Oracle managed keys", "high", "fail", "oci", "blockstorage", "Boot volume uses Oracle managed keys", "Encrypt with CMK"),
		mockFinding("oci-network_vcn_subnet_flow_logs_enabled", "Subnet does not have internet ingress prohibited", "medium", "fail", "oci", "network", "Subnet does not have internet ingress prohibited", "Enable VCN flow logs"),
		mockFinding("oci-network_security_group_ingress_from_internet_to_rdp_port", "Security groups allow RDP from internet", "high", "fail", "oci", "network", "Security groups allow RDP from internet", "Restrict RDP access"),
		mockFinding("oci-compute_instance_in_transit_encryption_enabled", "Instance Ai_models has in-transit encryption enabled", "high", "pass", "oci", "compute", "Instance Ai_models has in-transit encryption enabled", "No action needed"),
		mockFinding("oci-objectstorage_bucket_public_access", "Object storage bucket is publicly accessible", "critical", "fail", "oci", "objectstorage", "Object storage bucket is publicly accessible", "Make bucket private"),
	}

	awsFindings := []models.Finding{
		mockFinding("aws-s3_bucket_public", "S3 bucket is publicly accessible", "critical", "fail", "aws", "s3", "S3 bucket is publicly accessible", "Make bucket private"),
		mockFinding("aws-ec2_public_instance", "EC2 instance has public IP", "high", "fail", "aws", "ec2", "EC2 instance has public IP", "Remove public IP"),
		mockFinding("aws-iam_password_policy", "IAM password policy does not meet requirements", "medium", "fail", "aws", "iam", "IAM password policy does not meet requirements", "Update password policy"),
		mockFinding("aws-rds_encryption", "RDS instance encryption not enabled", "high", "fail", "aws", "rds", "RDS instance encryption not enabled", "Enable RDS encryption"),
		mockFinding("aws-cloudtrail_enabled", "CloudTrail is not enabled", "high", "fail", "aws", "cloudtrail", "CloudTrail is not enabled", "Enable CloudTrail"),
		mockFinding("aws-kms_key_rotation", "KMS key rotation is not enabled", "medium", "fail", "aws", "kms", "KMS key rotation is not enabled", "Enable KMS key rotation"),
		mockFinding("aws-vpc_flow_logs", "VPC flow logs are not enabled", "medium", "fail", "aws", "vpc", "VPC flow logs are not enabled", "Enable VPC flow logs"),
		mockFinding("aws-cloudwatch_alarms", "CloudWatch alarms are not configured", "low", "fail", "aws", "cloudwatch", "CloudWatch alarms are not configured", "Configure CloudWatch alarms"),
		mockFinding("aws-lambda_timeout", "Lambda function timeout is too high", "low", "pass", "aws", "lambda", "Lambda function timeout is appropriate", "No action needed"),
		mockFinding("aws-ecs_task_role", "ECS task role has excessive permissions", "medium", "fail", "aws", "ecs", "ECS task role has excessive permissions", "Review task role permissions"),
	}

	azureFindings := []models.Finding{
		mockFinding("azure-storage_encryption", "Storage account encryption not enabled", "high", "fail", "azure", "storage", "Storage account encryption not enabled", "Enable storage encryption"),
		mockFinding("azure-network_security_group", "NSG allows inbound from internet", "high", "fail", "azure", "network", "NSG allows inbound from internet", "Restrict inbound access"),
		mockFinding("azure-vm_encryption", "VM disk encryption not enabled", "high", "fail", "azure", "compute", "VM disk encryption not enabled", "Enable VM disk encryption"),
		mockFinding("azure-key_vault_rbac", "Key Vault access policy is not RBAC", "medium", "fail", "azure", "keyvault", "Key Vault access policy is not RBAC", "Enable RBAC for Key Vault"),
		mockFinding("azure-monitor_diagnostics", "Diagnostics settings are not configured", "low", "fail", "azure", "monitor", "Diagnostics settings are not configured", "Configure diagnostics settings"),
		mockFinding("azure-defender_enabled", "Microsoft Defender is not enabled", "high", "fail", "azure", "security", "Microsoft Defender is not enabled", "Enable Microsoft Defender"),
	}

	gcpFindings := []models.Finding{
		mockFinding("gcp-compute_public_ip", "GCE instance has public IP", "high", "fail", "gcp", "compute", "GCE instance has public IP", "Remove public IP"),
		mockFinding("gcp-storage_public_bucket", "GCS bucket is publicly accessible", "critical", "fail", "gcp", "storage", "GCS bucket is publicly accessible", "Make bucket private"),
		mockFinding("gcp-iam_service_account", "Service account has too many permissions", "medium", "fail", "gcp", "iam", "Service account has too many permissions", "Review service account permissions"),
		mockFinding("gcp-cloudsql_public", "Cloud SQL instance is publicly accessible", "high", "fail", "gcp", "sql", "Cloud SQL instance is publicly accessible", "Restrict Cloud SQL access"),
		mockFinding("gcp-kms_key_rotation", "KMS key rotation is not enabled", "medium", "fail", "gcp", "kms", "KMS key rotation is not enabled", "Enable KMS key rotation"),
		mockFinding("gcp-vpc_flow_logs", "VPC flow logs are not enabled", "medium", "fail", "gcp", "vpc", "VPC flow logs are not enabled", "Enable VPC flow logs"),
	}

	cloudflareFindings := []models.Finding{
		mockFinding("cf-waf_enabled", "WAF is not enabled", "high", "fail", "cloudflare", "waf", "WAF is not enabled", "Enable WAF"),
		mockFinding("cf-ssl_tls", "SSL/TLS encryption mode is not strict", "high", "fail", "cloudflare", "ssl", "SSL/TLS encryption mode is not strict", "Set SSL/TLS to strict mode"),
		mockFinding("cf-dnssec", "DNSSEC is not enabled", "medium", "fail", "cloudflare", "dns", "DNSSEC is not enabled", "Enable DNSSEC"),
		mockFinding("cf-bot_management", "Bot management is not enabled", "medium", "fail", "cloudflare", "waf", "Bot management is not enabled", "Enable bot management"),
		mockFinding("cf-rate_limiting", "Rate limiting is not configured", "low", "fail", "cloudflare", "waf", "Rate limiting is not configured", "Configure rate limiting"),
		mockFinding("cf-min_tls_version", "Minimum TLS version is not 1.3", "medium", "fail", "cloudflare", "ssl", "Minimum TLS version is not 1.3", "Set minimum TLS version to 1.3"),
	}

	switch provider {
	case "oci":
		return ociFindings
	case "aws":
		return awsFindings
	case "azure":
		return azureFindings
	case "gcp":
		return gcpFindings
	case "cloudflare":
		return cloudflareFindings
	default:
		all := []models.Finding{}
		all = append(all, ociFindings...)
		all = append(all, awsFindings...)
		all = append(all, azureFindings...)
		all = append(all, gcpFindings...)
		all = append(all, cloudflareFindings...)
		return all
	}
}

// GetFindingsByProvider returns findings grouped by provider
func (s *ScanService) GetFindingsByProvider(ctx context.Context) (map[string][]models.Finding, error) {
	providers := []string{"oci", "aws", "azure", "gcp", "cloudflare"}
	result := make(map[string][]models.Finding)
	for _, p := range providers {
		result[p] = getMockFindings(p)
	}
	return result, nil
}

// GetFindingsStats returns statistics for findings
func (s *ScanService) GetFindingsStats(ctx context.Context) (map[string]interface{}, error) {
	findingsByProvider, _ := s.GetFindingsByProvider(ctx)
	
	stats := make(map[string]interface{})
	totalFindings := 0
	totalCritical := 0
	totalHigh := 0
	totalMedium := 0
	totalLow := 0
	totalPass := 0
	totalFail := 0
	
	providerStats := make(map[string]map[string]int)
	
	for provider, findings := range findingsByProvider {
		pStats := map[string]int{
			"total":    len(findings),
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
			"pass":     0,
			"fail":     0,
		}
		
		for _, f := range findings {
			totalFindings++
			switch f.Severity {
			case "critical":
				totalCritical++
				pStats["critical"]++
			case "high":
				totalHigh++
				pStats["high"]++
			case "medium":
				totalMedium++
				pStats["medium"]++
			case "low":
				totalLow++
				pStats["low"]++
			}
			if string(f.Status) == "pass" {
				totalPass++
				pStats["pass"]++
			} else {
				totalFail++
				pStats["fail"]++
			}
		}
		
		providerStats[provider] = pStats
	}
	
	stats["total"] = totalFindings
	stats["critical"] = totalCritical
	stats["high"] = totalHigh
	stats["medium"] = totalMedium
	stats["low"] = totalLow
	stats["pass"] = totalPass
	stats["fail"] = totalFail
	stats["providers"] = providerStats
	
	return stats, nil
}

// GetFindingsByProviderAndType returns findings for a specific provider and type
func (s *ScanService) GetFindingsByProviderAndType(ctx context.Context, provider, findingType string) ([]models.Finding, error) {
	findings := getMockFindings(provider)
	var filtered []models.Finding
	
	for _, f := range findings {
		if findingType == "all" {
			filtered = append(filtered, f)
		} else if findingType == "fail" && string(f.Status) == "fail" {
			filtered = append(filtered, f)
		} else if findingType == "pass" && string(f.Status) == "pass" {
			filtered = append(filtered, f)
		} else if f.Severity == findingType {
			filtered = append(filtered, f)
		}
	}
	
	return filtered, nil
}

func ptrString(s string) *string {
	return &s
}

// Helper for JSON responses
func jsonResponse(data interface{}) string {
	return fmt.Sprintf("%v", data)
}
