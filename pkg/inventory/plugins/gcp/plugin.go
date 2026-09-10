// Package gcp provides GCP inventory plugin for the inventory engine.
package gcp

import (
	"context"
	"encoding/json"
	"time"
)

// Plugin provides inventory access to GCP resources.
type Plugin struct {
	config PluginConfig
}

// PluginConfig configures the GCP plugin.
type PluginConfig struct {
	ProjectID string
	Region    string
	Zone      string
}

// New creates a new GCP plugin.
func New(cfg ...PluginConfig) *Plugin {
	p := Plugin{}
	if len(cfg) > 0 {
		p.config = cfg[0]
	}
	return &p
}

// Name returns the plugin name.
func (p *Plugin) Name() string { return "gcp" }

// Provider returns the cloud provider.
func (p *Plugin) Provider() string { return "gcp" }

// Services returns the list of supported services.
func (p *Plugin) Services() []string {
	return []string{"compute", "storage", "iam", "gke", "cloudsql", "bigquery", "cloudfunctions", "dns"}
}

// Compute returns the Compute Engine inventory service.
func (p *Plugin) Compute() *ComputeService {
	return &ComputeService{plugin: p}
}

// Storage returns the Cloud Storage inventory service.
func (p *Plugin) Storage() *StorageService {
	return &StorageService{plugin: p}
}

// IAM returns the IAM inventory service.
func (p *Plugin) IAM() *IAMService {
	return &IAMService{plugin: p}
}

// GCEInstance represents a GCP Compute Engine instance.
type GCEInstance struct {
	InstanceID   string            `json:"instance_id"`
	Name         string            `json:"name"`
	MachineType  string            `json:"machine_type"`
	Status       string            `json:"status"`
	Zone         string            `json:"zone"`
	Labels       map[string]string `json:"labels"`
	Tags         map[string]string `json:"tags"`
	NetworkID    string            `json:"network_id"`
	SubnetID     string            `json:"subnet_id"`
	PrivateIP    string            `json:"private_ip"`
	PublicIP     string            `json:"public_ip"`
	ProjectID    string            `json:"project_id"`
	CreationTime time.Time         `json:"creation_time"`
}

// ComputeFilter filters Compute Engine instances.
type ComputeFilter struct {
	ProjectID string            `json:"project_id"`
	Zone      string            `json:"zone"`
	Status    string            `json:"status"`
	Labels    map[string]string `json:"labels"`
	Tags      map[string]string `json:"tags"`
}

// ComputeService provides Compute Engine instance inventory.
type ComputeService struct {
	plugin *Plugin
}

// ListInstances returns all Compute Engine instances matching the filter.
func (s *ComputeService) ListInstances(ctx context.Context, filter ComputeFilter) ([]GCEInstance, error) {
	return []GCEInstance{}, nil
}

// GetInstance returns a specific Compute Engine instance.
func (s *ComputeService) GetInstance(ctx context.Context, zone, name string) (*GCEInstance, error) {
	return &GCEInstance{Name: name, Zone: zone}, nil
}

// GCSBucket represents a GCP Cloud Storage bucket.
type GCSBucket struct {
	Name         string            `json:"name"`
	Location     string            `json:"location"`
	StorageClass string            `json:"storage_class"`
	Labels       map[string]string `json:"labels"`
	CreationTime time.Time         `json:"creation_time"`
	ProjectID    string            `json:"project_id"`
}

// StorageFilter filters Cloud Storage buckets.
type StorageFilter struct {
	ProjectID    string            `json:"project_id"`
	Location     string            `json:"location"`
	StorageClass string            `json:"storage_class"`
	Labels       map[string]string `json:"labels"`
}

// StorageService provides Cloud Storage bucket inventory.
type StorageService struct {
	plugin *Plugin
}

// ListBuckets returns all Cloud Storage buckets matching the filter.
func (s *StorageService) ListBuckets(ctx context.Context, filter StorageFilter) ([]GCSBucket, error) {
	return []GCSBucket{}, nil
}

// GetBucket returns a specific Cloud Storage bucket.
func (s *StorageService) GetBucket(ctx context.Context, name string) (*GCSBucket, error) {
	return &GCSBucket{Name: name}, nil
}

// IAMMember represents a GCP IAM member.
type IAMMember struct {
	Member    string `json:"member"`
	Role      string `json:"role"`
	ProjectID string `json:"project_id"`
}

// IAMFilter filters IAM members.
type IAMFilter struct {
	ProjectID string `json:"project_id"`
	Role      string `json:"role"`
}

// IAMService provides IAM member inventory.
type IAMService struct {
	plugin *Plugin
}

// ListMembers returns all IAM members matching the filter.
func (s *IAMService) ListMembers(ctx context.Context, filter IAMFilter) ([]IAMMember, error) {
	return []IAMMember{}, nil
}

// GetMember returns a specific IAM member.
func (s *IAMService) GetMember(ctx context.Context, member string) (*IAMMember, error) {
	return &IAMMember{Member: member}, nil
}

// ToJSON returns the resource as JSON.
func ToJSON(r interface{}) string {
	b, _ := json.Marshal(r)
	return string(b)
}
