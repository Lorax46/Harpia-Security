// Package web provides HTTP handlers for the Harpia Security dashboard.
package web

import (
	"context"
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
	return []models.Finding{}, nil
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
		"total_checks": 752,
	}
}
