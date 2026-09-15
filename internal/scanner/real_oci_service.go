// Package scanner provides real OCI scanning with vault credentials.
package scanner

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/oci"
	ocichecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci"
	"github.com/Lorax46/Harpia-Security/internal/scanner/registry"
)

// RealOCIService provides real OCI scanning with credentials
type RealOCIService struct {
	provider *oci.Provider
	registry *registry.Registry
	region   string
}

// NewRealOCIService creates a new real OCI scanning service
func NewRealOCIService(ctx context.Context, region, tenancyId, userId, fingerprint, privateKey string) (*RealOCIService, error) {
	provider, err := oci.NewProvider(ctx, region, tenancyId, userId, fingerprint, privateKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI provider: %w", err)
	}

	reg := registry.New()
	for _, checks := range ocichecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}

	return &RealOCIService{
		provider: provider,
		registry: reg,
		region:   region,
	}, nil
}

// RunScan executes all registered checks for OCI
func (s *RealOCIService) RunScan(ctx context.Context) (*models.ScanResult, error) {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		if check.Metadata().Provider == "oci" {
			checks = append(checks, check)
		}
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered for OCI")
	}

	exec := executor.New(s.provider, checks...)
	result := exec.Run(ctx)

	result.Provider = "oci"
	result.Region = s.region

	return &result, nil
}

// RunScanByService executes checks for a specific service
func (s *RealOCIService) RunScanByService(ctx context.Context, service string) (*models.ScanResult, error) {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		meta := check.Metadata()
		if meta.Provider == "oci" && meta.ServiceName == service {
			checks = append(checks, check)
		}
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered for OCI service: %s", service)
	}

	exec := executor.New(s.provider, checks...)
	result := exec.Run(ctx)

	result.Provider = "oci"
	result.Region = s.region

	return &result, nil
}

// GetProvider returns the OCI provider
func (s *RealOCIService) GetProvider() *oci.Provider {
	return s.provider
}

// GetRegistry returns the check registry
func (s *RealOCIService) GetRegistry() *registry.Registry {
	return s.registry
}

// GetChecks returns all registered checks
func (s *RealOCIService) GetChecks() []executor.Check {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		if check.Metadata().Provider == "oci" {
			checks = append(checks, check)
		}
	}
	return checks
}

// GetChecksByService returns checks for a specific service
func (s *RealOCIService) GetChecksByService(service string) []executor.Check {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		meta := check.Metadata()
		if meta.Provider == "oci" && meta.ServiceName == service {
			checks = append(checks, check)
		}
	}
	return checks
}
