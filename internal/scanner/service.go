package scanner

import (
	"context"
	"fmt"

	"github.com/Lorax46/Harpia-Security/internal/scanner/executor"
	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/aws"
	"github.com/Lorax46/Harpia-Security/internal/scanner/registry"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	awschecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/aws"
	ocichecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/oci"
	cfchecks "github.com/Lorax46/Harpia-Security/internal/scanner/checks/cloudflare"
)

// Service orchestrates security scans
type Service struct {
	providers map[string]interface{}
	registry  *registry.Registry
}

// NewService creates a new scanner service with real providers
func NewService(ctx context.Context, region, accessKey, secretKey string) (*Service, error) {
	awsProvider, err := aws.NewProvider(ctx, region, accessKey, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS provider: %w", err)
	}

	reg := registry.New()
	loadAWSChecks(reg)
	loadOCIChecks(reg)
	loadCloudflareChecks(reg)

	return &Service{
		providers: map[string]interface{}{
			"aws":         awsProvider,
			"oci":         awsProvider,  // OCI uses same interface for now
			"cloudflare":  awsProvider,  // Cloudflare uses same interface for now
			"gcp":         awsProvider,  // GCP uses same interface for now
			"azure":       awsProvider,  // Azure uses same interface for now
		},
		registry: reg,
	}, nil
}

// NewServiceWithProviders creates a service with custom providers (for testing)
func NewServiceWithProviders(providers map[string]interface{}) *Service {
	reg := registry.New()
	loadAWSChecks(reg)
	loadOCIChecks(reg)
	loadCloudflareChecks(reg)
	return &Service{
		providers: providers,
		registry:  reg,
	}
}

// RunScan executes all registered checks for a provider
func (s *Service) RunScan(ctx context.Context, provider string) (*models.ScanResult, error) {
	providerImpl, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("no provider registered for: %s", provider)
	}

	var checks []executor.Check
	for _, check := range s.registry.All() {
		if check.Metadata().Provider == provider {
			checks = append(checks, check)
		}
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("no checks registered for provider: %s", provider)
	}

	exec := executor.New(providerImpl, checks...)
	result := exec.Run(ctx)

	// Set region from AWS provider
	if awsProv, ok := providerImpl.(*aws.Provider); ok {
		result.Region = awsProv.Region()
	}

	return &result, nil
}

// RunScanByService executes checks for a specific service
func (s *Service) RunScanByService(ctx context.Context, provider, service string) (*models.ScanResult, error) {
	providerImpl, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("no provider registered for: %s", provider)
	}

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

	exec := executor.New(providerImpl, checks...)
	result := exec.Run(ctx)

	if awsProv, ok := providerImpl.(*aws.Provider); ok {
		result.Region = awsProv.Region()
	}

	return &result, nil
}

// GetRegistry returns the check registry
func (s *Service) GetRegistry() *registry.Registry {
	return s.registry
}

// GetProviders returns available providers
func (s *Service) GetProviders() []string {
	providers := []string{}
	for name := range s.providers {
		providers = append(providers, name)
	}
	return providers
}

// loadAWSChecks loads all AWS checks from the aws checks registry
func loadAWSChecks(reg *registry.Registry) {
	for _, checks := range awschecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}
}

// loadOCIChecks loads all OCI checks from the oci checks registry
func loadOCIChecks(reg *registry.Registry) {
	for _, checks := range ocichecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}
}

// loadCloudflareChecks loads all Cloudflare checks from the cloudflare checks registry
func loadCloudflareChecks(reg *registry.Registry) {
	for _, checks := range cfchecks.Registry {
		for _, check := range checks {
			reg.Register(check)
		}
	}
}
