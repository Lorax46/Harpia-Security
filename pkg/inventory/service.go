package inventory

import (
	"fmt"
	"sync"
)

// Service provides inventory operations for the web layer
type Service struct {
	registry *Registry
	mu       sync.RWMutex
}

// NewService creates a new inventory service
func NewService() *Service {
	return &Service{
		registry: GetRegistry(),
	}
}

// ListResources lists resources with optional filter
func (s *Service) ListResources(provider, service string, filter Filter) ([]Resource, error) {
	if provider != "" {
		filter.Provider = provider
	}
	if service != "" {
		filter.Service = service
	}
	return s.registry.ListResources(filter)
}

// GetResource gets a resource by ID
func (s *Service) GetResource(provider, service, id string) (*Resource, error) {
	resources, err := s.ListResources(provider, service, Filter{})
	if err != nil {
		return nil, err
	}
	for _, r := range resources {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("resource not found: %s", id)
}

// SyncResources syncs resources for a provider
func (s *Service) SyncResources(provider string) error {
	// TODO: Trigger actual sync with cloud SDK
	return nil
}

// ListProviders returns available providers
func (s *Service) ListProviders() []string {
	return s.registry.ListPlugins()
}

// ListTables returns tables for a provider
func (s *Service) ListTables(provider string) []string {
	plugin, ok := s.registry.GetPlugin(provider)
	if !ok {
		return []string{}
	}
	return plugin.ListTables()
}

// ListAllTables returns all tables across all providers
func (s *Service) ListAllTables() map[string][]string {
	return s.registry.ListTables()
}
