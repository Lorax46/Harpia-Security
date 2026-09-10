// Package web provides service interfaces for the web layer.
package web

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Lorax46/Harpia-Security/pkg/compliance"
	"github.com/Lorax46/Harpia-Security/pkg/inventory"
)

// ScannerService provides scan operations.
type ScannerService interface {
	ListScans(ctx context.Context) ([]Scan, error)
	CreateScan(ctx context.Context, req CreateScanRequest) (*Scan, error)
	GetScan(ctx context.Context, id string) (*Scan, error)
	RunScan(ctx context.Context, id string) error
	DeleteScan(ctx context.Context, id string) error
	ListFindings(ctx context.Context, filter FindingsFilter) ([]models.Finding, error)
	GetFinding(ctx context.Context, id string) (*models.Finding, error)
	UpdateFinding(ctx context.Context, id string, req UpdateFindingRequest) (*models.Finding, error)
	ExportFindings(ctx context.Context, format string) ([]byte, error)
}

// InventoryService provides inventory operations.
type InventoryService interface {
	ListResources(ctx context.Context, provider, service string, filter inventory.Filter) ([]inventory.Resource, error)
	GetResource(ctx context.Context, provider, service, id string) (inventory.Resource, error)
	SyncResources(ctx context.Context, provider string) error
}

// ComplianceService provides compliance operations.
type ComplianceService interface {
	ListFrameworks(ctx context.Context) []compliance.Framework
	ListReports(ctx context.Context) ([]compliance.ComplianceReport, error)
	GenerateReport(ctx context.Context, frameworkID string, findings []models.Finding) (*compliance.ComplianceReport, error)
	GetReport(ctx context.Context, id string) (*compliance.ComplianceReport, error)
	ExportReport(ctx context.Context, id string, format string) ([]byte, error)
}

// Scan represents a scan.
type Scan struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Status    string    `json:"status"` // pending, running, completed, failed
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
	Findings  int       `json:"findings"`
}

// CreateScanRequest represents a scan creation request.
type CreateScanRequest struct {
	Name     string `json:"name" binding:"required"`
	Provider string `json:"provider" binding:"required"`
}

// FindingsFilter represents a findings filter.
type FindingsFilter struct {
	Provider string `json:"provider"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

// UpdateFindingRequest represents a finding update request.
type UpdateFindingRequest struct {
	Status string `json:"status"`
}

// ProviderConfig represents a cloud provider configuration.
type ProviderConfig struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
}

// Settings represents dashboard settings.
type Settings struct {
	Providers []ProviderConfig `json:"providers"`
}

// MockScannerService is a mock implementation for development.
type MockScannerService struct{}

func NewMockScannerService() *MockScannerService {
	return &MockScannerService{}
}

func (s *MockScannerService) ListScans(ctx context.Context) ([]Scan, error) {
	return []Scan{
		{
			ID: "scan-1", Name: "AWS Production Scan", Provider: "aws",
			Status: "completed", CreatedAt: "2026-09-08T10:00:00Z",
			UpdatedAt: "2026-09-08T10:05:00Z", Findings: 142,
		},
		{
			ID: "scan-2", Name: "GCP Dev Scan", Provider: "gcp",
			Status: "completed", CreatedAt: "2026-09-08T11:00:00Z",
			UpdatedAt: "2026-09-08T11:03:00Z", Findings: 38,
		},
		{
			ID: "scan-3", Name: "Azure Scan", Provider: "azure",
			Status: "running", CreatedAt: "2026-09-08T12:00:00Z",
			UpdatedAt: "2026-09-08T12:01:00Z", Findings: 0,
		},
	}, nil
}

func (s *MockScannerService) CreateScan(ctx context.Context, req CreateScanRequest) (*Scan, error) {
	return &Scan{
		ID:        "scan-" + req.Provider,
		Name:      req.Name,
		Provider:  req.Provider,
		Status:    "pending",
		CreatedAt: "2026-09-08T12:00:00Z",
		UpdatedAt: "2026-09-08T12:00:00Z",
	}, nil
}

func (s *MockScannerService) GetScan(ctx context.Context, id string) (*Scan, error) {
	return &Scan{
		ID: id, Name: "Mock Scan", Provider: "aws",
		Status: "completed", CreatedAt: "2026-09-08T10:00:00Z",
		UpdatedAt: "2026-09-08T10:05:00Z", Findings: 142,
	}, nil
}

func (s *MockScannerService) RunScan(ctx context.Context, id string) error {
	return nil
}

func (s *MockScannerService) DeleteScan(ctx context.Context, id string) error {
	return nil
}

func (s *MockScannerService) ListFindings(ctx context.Context, filter FindingsFilter) ([]models.Finding, error) {
	now := time.Now().UTC()
	return []models.Finding{
		{
			ID: "iam_user_mfa_enabled", Title: "Ensure MFA is enabled for all IAM users",
			Description: "MFA should be enabled for all IAM users",
			Severity: "critical", Status: models.StatusFail,
			Provider: "aws", Service: "iam",
			ResourceID: "user/admin", FoundAt: now,
		},
		{
			ID: "cloudtrail_multi_region_enabled", Title: "Ensure CloudTrail is enabled in all regions",
			Description: "CloudTrail should be enabled in all regions",
			Severity: "high", Status: models.StatusPass,
			Provider: "aws", Service: "cloudtrail",
			ResourceID: "trail/main", FoundAt: now,
		},
		{
			ID: "s3_bucket_encryption", Title: "Ensure S3 bucket encryption is enabled",
			Description: "S3 buckets should have default encryption enabled",
			Severity: "high", Status: models.StatusFail,
			Provider: "aws", Service: "s3",
			ResourceID: "bucket/my-bucket", FoundAt: now,
		},
		{
			ID: "vpc_flow_logs_enabled", Title: "Ensure VPC flow logs are enabled",
			Description: "VPC flow logs should be enabled",
			Severity: "medium", Status: models.StatusPass,
			Provider: "aws", Service: "vpc",
			ResourceID: "vpc-12345", FoundAt: now,
		},
		{
			ID: "kubernetes_cis_benchmark", Title: "CIS Kubernetes Benchmark",
			Description: "Kubernetes cluster should pass CIS benchmark",
			Severity: "high", Status: models.StatusManual,
			Provider: "kubernetes", Service: "kubernetes",
			ResourceID: "cluster/eks-prod", FoundAt: now,
		},
	}, nil
}

func (s *MockScannerService) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	return &models.Finding{
		ID: id, Title: "Mock Finding",
		Description: "Mock finding description",
		Severity: "high", Status: models.StatusFail,
		Provider: "aws", Service: "ec2",
		ResourceID: "i-12345", FoundAt: time.Now().UTC(),
	}, nil
}

func (s *MockScannerService) UpdateFinding(ctx context.Context, id string, req UpdateFindingRequest) (*models.Finding, error) {
	return &models.Finding{
		ID: id, Title: "Mock Finding",
		Description: "Mock finding description",
		Severity: "high", Status: models.Status(req.Status),
		Provider: "aws", Service: "ec2",
		ResourceID: "i-12345", FoundAt: time.Now().UTC(),
	}, nil
}

func (s *MockScannerService) ExportFindings(ctx context.Context, format string) ([]byte, error) {
	return []byte("id,title,severity,status\niam_user_mfa_enabled,MFA,high,fail\n"), nil
}

// MockInventoryService is a mock implementation for development.
type MockInventoryService struct{}

func NewMockInventoryService() *MockInventoryService {
	return &MockInventoryService{}
}

func (s *MockInventoryService) ListResources(ctx context.Context, provider, service string, filter inventory.Filter) ([]inventory.Resource, error) {
	return []inventory.Resource{
		inventory.BaseResource{
			ID: "aws:ec2:i-12345", Type: "ec2_instance", Provider: "aws", Service: "ec2", Region: "us-east-1",
			Tags: map[string]string{"Name": "web-server", "Environment": "production"},
		},
		inventory.BaseResource{
			ID: "aws:s3:my-bucket", Type: "s3_bucket", Provider: "aws", Service: "s3", Region: "us-east-1",
			Tags: map[string]string{"Environment": "production"},
		},
		inventory.BaseResource{
			ID: "gcp:compute:instance-1", Type: "compute_instance", Provider: "gcp", Service: "compute", Region: "us-central1",
			Tags: map[string]string{"name": "api-server"},
		},
	}, nil
}

func (s *MockInventoryService) GetResource(ctx context.Context, provider, service, id string) (inventory.Resource, error) {
	return inventory.BaseResource{
		ID: provider + ":" + service + ":" + id, Type: service, Provider: provider, Service: service, Region: "us-east-1",
		Tags: map[string]string{"Name": "test-resource"},
	}, nil
}

func (s *MockInventoryService) SyncResources(ctx context.Context, provider string) error {
	return nil
}

// MockComplianceService is a mock implementation for development.
type MockComplianceService struct{}

func NewMockComplianceService() *MockComplianceService {
	return &MockComplianceService{}
}

func (s *MockComplianceService) ListFrameworks(ctx context.Context) []compliance.Framework {
	return []compliance.Framework{
		{ID: "cis_aws_v1.5.0", Name: "CIS AWS Foundations Benchmark", Version: "v1.5.0", Description: "CIS AWS Benchmark"},
		{ID: "cis_gcp_v1.3.0", Name: "CIS GCP Foundations Benchmark", Version: "v1.3.0", Description: "CIS GCP Benchmark"},
		{ID: "cis_azure_v1.5.0", Name: "CIS Azure Foundations Benchmark", Version: "v1.5.0", Description: "CIS Azure Benchmark"},
		{ID: "cis_kubernetes_v1.6.0", Name: "CIS Kubernetes Benchmark", Version: "v1.6.0", Description: "CIS Kubernetes Benchmark"},
		{ID: "soc2_type2", Name: "SOC 2 Type II", Version: "2017", Description: "SOC 2 Type II"},
		{ID: "hipaa", Name: "HIPAA", Version: "2013", Description: "HIPAA Security Rule"},
		{ID: "pci_dss_v4.0", Name: "PCI DSS", Version: "v4.0", Description: "PCI Data Security Standard"},
		{ID: "nist_800_53_rev5", Name: "NIST SP 800-53", Version: "Rev 5", Description: "NIST Security Controls"},
		{ID: "iso_27001_2022", Name: "ISO 27001", Version: "2022", Description: "Information Security Management"},
		{ID: "gdpr", Name: "GDPR", Version: "2018", Description: "General Data Protection Regulation"},
		{ID: "fedramp_moderate", Name: "FedRAMP", Version: "Moderate", Description: "Federal Risk Authorization"},
		{ID: "mitre_attack", Name: "MITRE ATT&CK", Version: "v14.0", Description: "Adversarial Tactics"},
	}
}

func (s *MockComplianceService) ListReports(ctx context.Context) ([]compliance.ComplianceReport, error) {
	return []compliance.ComplianceReport{
		{
			Framework: compliance.Framework{ID: "soc2_type2", Name: "SOC 2 Type II", Version: "2017"},
			Total:     50, Passed: 42, Failed: 5, Manual: 3,
		},
		{
			Framework: compliance.Framework{ID: "hipaa", Name: "HIPAA", Version: "2013"},
			Total:     30, Passed: 25, Failed: 3, Manual: 2,
		},
	}, nil
}

func (s *MockComplianceService) GenerateReport(ctx context.Context, frameworkID string, findings []models.Finding) (*compliance.ComplianceReport, error) {
	engine := compliance.NewEngine()
	results, err := engine.RunCompliance(ctx, frameworkID, findings)
	if err != nil {
		return nil, err
	}
	report := engine.GenerateReport(results)
	return &report, nil
}

func (s *MockComplianceService) GetReport(ctx context.Context, id string) (*compliance.ComplianceReport, error) {
	return &compliance.ComplianceReport{
		Framework: compliance.Framework{ID: "soc2_type2", Name: "SOC 2 Type II", Version: "2017"},
		Total:     50, Passed: 42, Failed: 5, Manual: 3,
	}, nil
}

func (s *MockComplianceService) ExportReport(ctx context.Context, id string, format string) ([]byte, error) {
	return []byte("control_id,description,status\nCC6.1,Access Controls,pass\nCC6.2,User Auth,fail\n"), nil
}

