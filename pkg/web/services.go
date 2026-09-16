// Package web provides service interfaces for the web layer.
package web

import (
	"context"

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
	GetFindingsByProvider(ctx context.Context) (map[string][]models.Finding, error)
	GetFindingsStats(ctx context.Context) (map[string]interface{}, error)
	GetFindingsByProviderAndType(ctx context.Context, provider, findingType string) ([]models.Finding, error)
	StoreCredentials(provider string, creds map[string]string)
	HasCredentials(provider string) bool
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
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Findings  int    `json:"findings"`
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

// MockScannerService for development.
type MockScannerService struct{}

func NewMockScannerService() *MockScannerService { return &MockScannerService{} }

func (s *MockScannerService) ListScans(ctx context.Context) ([]Scan, error) {
	return []Scan{{ID: "scan-oci", Name: "OCI Scan", Provider: "oci", Status: "pending"}}, nil
}
func (s *MockScannerService) CreateScan(ctx context.Context, req CreateScanRequest) (*Scan, error) {
	return &Scan{ID: "scan-" + req.Provider, Name: req.Name, Provider: req.Provider, Status: "pending"}, nil
}
func (s *MockScannerService) GetScan(ctx context.Context, id string) (*Scan, error) {
	return &Scan{ID: id, Name: "Scan", Status: "completed"}, nil
}
func (s *MockScannerService) RunScan(ctx context.Context, id string) error { return nil }
func (s *MockScannerService) DeleteScan(ctx context.Context, id string) error { return nil }
func (s *MockScannerService) ListFindings(ctx context.Context, filter FindingsFilter) ([]models.Finding, error) {
	return []models.Finding{}, nil
}
func (s *MockScannerService) GetFinding(ctx context.Context, id string) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding"}, nil
}
func (s *MockScannerService) UpdateFinding(ctx context.Context, id string, req UpdateFindingRequest) (*models.Finding, error) {
	return &models.Finding{ID: id, Title: "Finding", Status: models.Status(req.Status)}, nil
}
func (s *MockScannerService) ExportFindings(ctx context.Context, format string) ([]byte, error) {
	return []byte{}, nil
}
func (s *MockScannerService) GetFindingsByProvider(ctx context.Context) (map[string][]models.Finding, error) {
	return map[string][]models.Finding{}, nil
}
func (s *MockScannerService) GetFindingsStats(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
		"providers": map[string]map[string]int{},
	}, nil
}
func (s *MockScannerService) GetFindingsByProviderAndType(ctx context.Context, provider, findingType string) ([]models.Finding, error) {
	return []models.Finding{}, nil
}
func (s *MockScannerService) StoreCredentials(provider string, creds map[string]string) {}
func (s *MockScannerService) HasCredentials(provider string) bool { return false }

// MockInventoryService for development.
type MockInventoryService struct{}

func NewMockInventoryService() *MockInventoryService { return &MockInventoryService{} }

func (s *MockInventoryService) ListResources(ctx context.Context, provider, service string, filter inventory.Filter) ([]inventory.Resource, error) {
	return []inventory.Resource{}, nil
}
func (s *MockInventoryService) GetResource(ctx context.Context, provider, service, id string) (inventory.Resource, error) {
	return inventory.Resource{ID: id, Type: service, Provider: provider}, nil
}
func (s *MockInventoryService) SyncResources(ctx context.Context, provider string) error { return nil }

// MockComplianceService for development.
type MockComplianceService struct{}

func NewMockComplianceService() *MockComplianceService { return &MockComplianceService{} }

func (s *MockComplianceService) ListFrameworks(ctx context.Context) []compliance.Framework {
	return []compliance.Framework{
		{ID: "cis_aws", Name: "CIS AWS"},
		{ID: "nist_800_53", Name: "NIST 800-53"},
	}
}
func (s *MockComplianceService) ListReports(ctx context.Context) ([]compliance.ComplianceReport, error) {
	return []compliance.ComplianceReport{}, nil
}
func (s *MockComplianceService) GenerateReport(ctx context.Context, frameworkID string, findings []models.Finding) (*compliance.ComplianceReport, error) {
	return &compliance.ComplianceReport{Framework: compliance.Framework{ID: frameworkID}}, nil
}
func (s *MockComplianceService) GetReport(ctx context.Context, id string) (*compliance.ComplianceReport, error) {
	return &compliance.ComplianceReport{Framework: compliance.Framework{ID: id}}, nil
}
func (s *MockComplianceService) ExportReport(ctx context.Context, id string, format string) ([]byte, error) {
	return []byte{}, nil
}
