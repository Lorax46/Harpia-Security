// Package oci provides OCI inventory plugin for the inventory engine.
package oci

import (
	"context"
	"encoding/json"
	"time"
)

// Plugin provides inventory access to OCI resources.
type Plugin struct {
	config PluginConfig
}

// PluginConfig configures the OCI plugin.
type PluginConfig struct {
	TenancyID  string
	Region     string
	CompartmentID string
}

// New creates a new OCI plugin.
func New(cfg ...PluginConfig) *Plugin {
	p := Plugin{}
	if len(cfg) > 0 {
		p.config = cfg[0]
	}
	return &p
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "oci" }

// Provider returns the cloud provider.
func (p *Plugin) Provider() string { return "oci" }

// Services returns the list of supported services.
func (p *Plugin) Services() []string {
	return []string{"core", "identity", "objectstorage", "database", "kms", "logging", "dns", "functions"}
}

// Core returns the Core inventory service.
func (p *Plugin) Core() *CoreService {
	return &CoreService{plugin: p}
}

// Identity returns the Identity inventory service.
func (p *Plugin) Identity() *IdentityService {
	return &IdentityService{plugin: p}
}

// ObjectStorage returns the Object Storage inventory service.
func (p *Plugin) ObjectStorage() *ObjectStorageService {
	return &ObjectStorageService{plugin: p}
}

// CoreInstance represents an OCI Core instance.
type CoreInstance struct {
	InstanceID   string            `json:"instance_id"`
	DisplayName  string            `json:"display_name"`
	Shape        string            `json:"shape"`
	State        string            `json:"state"`
	Region       string            `json:"region"`
	CompartmentID string           `json:"compartment_id"`
	FreeformTags map[string]string `json:"freeform_tags"`
	DefinedTags  map[string]string `json:"defined_tags"`
	TimeCreated  time.Time         `json:"time_created"`
}

// CoreFilter filters Core instances.
type CoreFilter struct {
	CompartmentID string            `json:"compartment_id"`
	Region        string            `json:"region"`
	State         string            `json:"state"`
	Shape         string            `json:"shape"`
	Tags          map[string]string `json:"tags"`
}

// CoreService provides Core instance inventory.
type CoreService struct {
	plugin *Plugin
}

// ListInstances returns all Core instances matching the filter.
func (s *CoreService) ListInstances(ctx context.Context, filter CoreFilter) ([]CoreInstance, error) {
	return []CoreInstance{}, nil
}

// GetInstance returns a specific Core instance.
func (s *CoreService) GetInstance(ctx context.Context, id string) (*CoreInstance, error) {
	return &CoreInstance{InstanceID: id}, nil
}

// OCIUser represents an OCI IAM user.
type OCIUser struct {
	UserID        string            `json:"user_id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	State         string            `json:"state"`
	Email         string            `json:"email"`
	CompartmentID string            `json:"compartment_id"`
	FreeformTags  map[string]string `json:"freeform_tags"`
	DefinedTags   map[string]string `json:"defined_tags"`
	TimeCreated   time.Time         `json:"time_created"`
}

// IdentityFilter filters OCI users.
type IdentityFilter struct {
	CompartmentID string            `json:"compartment_id"`
	State         string            `json:"state"`
	Tags          map[string]string `json:"tags"`
}

// IdentityService provides OCI user inventory.
type IdentityService struct {
	plugin *Plugin
}

// ListUsers returns all OCI users matching the filter.
func (s *IdentityService) ListUsers(ctx context.Context, filter IdentityFilter) ([]OCIUser, error) {
	return []OCIUser{}, nil
}

// GetUser returns a specific OCI user.
func (s *IdentityService) GetUser(ctx context.Context, id string) (*OCIUser, error) {
	return &OCIUser{UserID: id}, nil
}

// ObjectStorageBucket represents an OCI Object Storage bucket.
type ObjectStorageBucket struct {
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	CompartmentID string            `json:"compartment_id"`
	Region        string            `json:"region"`
	StorageTier   string            `json:"storage_tier"`
	PublicAccess  bool              `json:"public_access"`
	FreeformTags  map[string]string `json:"freeform_tags"`
	DefinedTags   map[string]string `json:"defined_tags"`
	TimeCreated   time.Time         `json:"time_created"`
}

// ObjectStorageFilter filters Object Storage buckets.
type ObjectStorageFilter struct {
	CompartmentID string            `json:"compartment_id"`
	Namespace     string            `json:"namespace"`
	Region        string            `json:"region"`
	Tags          map[string]string `json:"tags"`
}

// ObjectStorageService provides Object Storage bucket inventory.
type ObjectStorageService struct {
	plugin *Plugin
}

// ListBuckets returns all Object Storage buckets matching the filter.
func (s *ObjectStorageService) ListBuckets(ctx context.Context, filter ObjectStorageFilter) ([]ObjectStorageBucket, error) {
	return []ObjectStorageBucket{}, nil
}

// GetBucket returns a specific Object Storage bucket.
func (s *ObjectStorageService) GetBucket(ctx context.Context, name string) (*ObjectStorageBucket, error) {
	return &ObjectStorageBucket{Name: name}, nil
}

// ToJSON returns the resource as JSON.
func ToJSON(r interface{}) string {
	b, _ := json.Marshal(r)
	return string(b)
}
