package scanner

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/aws"
	"github.com/Lorax46/Harpia-Security/internal/scanner/registry"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	awschecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/aws"
)

// Service orchestrates security scans
type Service struct {
	provider *aws.Provider
	registry *registry.Registry
}

// NewService creates a new scanner service with real AWS provider
func NewService(ctx context.Context, region, accessKey, secretKey string) (*Service, error) {
	provider, err := aws.NewProvider(ctx, region, accessKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS provider: %w", err)
	}

	reg := registry.New()
	loadAWSChecks(reg)

	return &Service{
		provider: provider,
		registry: reg,
	}, nil
}

// NewServiceWithProvider creates a service with a custom provider (for testing)
func NewServiceWithProvider(provider *aws.Provider) *Service {
	reg := registry.New()
	loadAWSChecks(reg)
	return &Service{
		provider: provider,
		registry: reg,
	}
}

// RunScan executes all registered checks for a provider
func (s *Service) RunScan(ctx context.Context, provider string) (*models.ScanResult, error) {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		if check.Metadata().Provider == provider {
			checks = append(checks, check)
		}
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered for provider: %s", provider)
	}

	exec := executor.New(s.provider, checks...)
	result := exec.Run(ctx)
	result.Region = s.provider.Region()
	return &result, nil
}

// RunScanByService executes checks for a specific service
func (s *Service) RunScanByService(ctx context.Context, provider, service string) (*models.ScanResult, error) {
	var checks []executor.Check
	for _, check := range s.registry.All() {
		meta := check.Metadata()
		if meta.Provider == provider && meta.ServiceName == service {
			checks = append(checks, check)
		}
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered for provider: %s, service: %s", provider, service)
	}

	exec := executor.New(s.provider, checks...)
	result := exec.Run(ctx)
	result.Region = s.provider.Region()
	return &result, nil
}

// GetRegistry returns the check registry
func (s *Service) GetRegistry() *registry.Registry {
	return s.registry
}

// loadAWSChecks loads all AWS checks from the aws checks registry
func loadAWSChecks(reg *registry.Registry) {
	for _, checks := range awschecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}
}
