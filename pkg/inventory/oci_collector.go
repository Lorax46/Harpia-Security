// Package inventory implements OCI Collector based on Steampipe architecture.
// All data comes from real OCI API calls - NO MOCK DATA.
// Reference: https://hub.steampipe.io/plugins/turbot/oci/tables
package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// OCIProvider interface wraps the OCI SDK clients needed for inventory.
type OCIProvider interface {
	Identity() (identity.IdentityClient, error)
	Compute() (core.ComputeClient, error)
	Network() (core.VirtualNetworkClient, error)
	ObjectStore() (objectstorage.ObjectStorageClient, error)
	Storage() (core.BlockstorageClient, error)
	Region() string
	TenancyId() string
}

// OCICollector implements the Collector interface for OCI.
type OCICollector struct {
	provider OCIProvider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewOCICollector creates a new OCI collector.
func NewOCICollector(provider OCIProvider) *OCICollector {
	return &OCICollector{
		provider: provider,
		cache:    make(map[string]*InventoryResult),
	}
}

// Collect collects resources of the specified type from OCI.
func (c *OCICollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "oci",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	case "oci_identity_user":
		result.Resources, err = c.collectUsers(ctx)
	case "oci_identity_group":
		result.Resources, err = c.collectGroups(ctx)
	case "oci_identity_policy":
		result.Resources, err = c.collectPolicies(ctx)
	case "oci_identity_compartment":
		result.Resources, err = c.collectCompartments(ctx)
	case "oci_core_instance":
		result.Resources, err = c.collectInstances(ctx)
	case "oci_core_vcn":
		result.Resources, err = c.collectVCNs(ctx)
	case "oci_core_subnet":
		result.Resources, err = c.collectSubnets(ctx)
	case "oci_core_security_list":
		result.Resources, err = c.collectSecurityLists(ctx)
	case "oci_objectstorage_bucket":
		result.Resources, err = c.collectBuckets(ctx)
	case "oci_core_volume":
		result.Resources, err = c.collectVolumes(ctx)
	case "oci_core_boot_volume":
		result.Resources, err = c.collectBootVolumes(ctx)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	if err != nil {
		return nil, err
	}

	result.Total = len(result.Resources)
	c.mu.Lock()
	c.cache[resourceType] = result
	c.mu.Unlock()
	return result, nil
}

// ListResourceTypes returns all OCI resource types (Steampipe-compatible).
func (c *OCICollector) ListResourceTypes() []ResourceType {
	return ociResourceTypes
}

// ociResourceTypes mirrors the Steampipe OCI tables: https://hub.steampipe.io/plugins/turbot/oci/tables
var ociResourceTypes = []ResourceType{
	{Name: "oci_identity_user", Provider: "oci", Service: "identity", Description: "IAM users in the tenancy"},
	{Name: "oci_identity_group", Provider: "oci", Service: "identity", Description: "IAM groups in the tenancy"},
	{Name: "oci_identity_policy", Provider: "oci", Service: "identity", Description: "IAM policies in the tenancy"},
	{Name: "oci_identity_compartment", Provider: "oci", Service: "identity", Description: "Compartments in the tenancy"},
	{Name: "oci_core_instance", Provider: "oci", Service: "compute", Description: "Compute instances"},
	{Name: "oci_core_vcn", Provider: "oci", Service: "network", Description: "Virtual Cloud Networks"},
	{Name: "oci_core_subnet", Provider: "oci", Service: "network", Description: "VCN subnets"},
	{Name: "oci_core_security_list", Provider: "oci", Service: "network", Description: "Security lists"},
	{Name: "oci_objectstorage_bucket", Provider: "oci", Service: "objectstorage", Description: "Object Storage buckets"},
	{Name: "oci_core_volume", Provider: "oci", Service: "blockstorage", Description: "Block volumes"},
	{Name: "oci_core_boot_volume", Provider: "oci", Service: "blockstorage", Description: "Boot volumes"},
}

// =============================================================================
// Identity Service Collectors
// =============================================================================

func (c *OCICollector) collectUsers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := identity.ListUsersRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListUsers(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListUsers failed: %w", err)
		}
		for _, u := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(u.Id),
				Name:       safeStr(u.Name),
				Type:       "oci_identity_user",
				Provider:   "oci",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"lifecycle_state": string(u.LifecycleState),
					"description":     safeStr(u.Description),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectGroups(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := identity.ListGroupsRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListGroups(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListGroups failed: %w", err)
		}
		for _, g := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(g.Id),
				Name:       safeStr(g.Name),
				Type:       "oci_identity_group",
				Provider:   "oci",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"lifecycle_state": string(g.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectPolicies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := identity.ListPoliciesRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListPolicies(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListPolicies failed: %w", err)
		}
		for _, p := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(p.Id),
				Name:       safeStr(p.Name),
				Type:       "oci_identity_policy",
				Provider:   "oci",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"lifecycle_state": string(p.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectCompartments(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := identity.ListCompartmentsRequest{
		CompartmentId:          &tenancyID,
		CompartmentIdInSubtree: common.Bool(true),
		LifecycleState:         identity.CompartmentLifecycleStateActive,
	}
	var resources []Resource

	for {
		resp, err := client.ListCompartments(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListCompartments failed: %w", err)
		}
		for _, comp := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(comp.Id),
				Name:       safeStr(comp.Name),
				Type:       "oci_identity_compartment",
				Provider:   "oci",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"lifecycle_state": string(comp.LifecycleState),
					"description":     safeStr(comp.Description),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

// =============================================================================
// Compute Service Collectors
// =============================================================================

func (c *OCICollector) collectInstances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute()
	if err != nil {
		return nil, fmt.Errorf("failed to get compute client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListInstancesRequest{
		CompartmentId: &tenancyID,
		Limit:         common.Int(1000),
	}
	var resources []Resource

	for {
		resp, err := client.ListInstances(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListInstances failed: %w", err)
		}
		for _, inst := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(inst.Id),
				Name:       safeStr(inst.DisplayName),
				Type:       "oci_core_instance",
				Provider:   "oci",
				Region:     c.provider.Region(),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"lifecycle_state": string(inst.LifecycleState),
					"shape":           safeStr(inst.Shape),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

// =============================================================================
// Network Service Collectors
// =============================================================================

func (c *OCICollector) collectVCNs(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Network()
	if err != nil {
		return nil, fmt.Errorf("failed to get network client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListVcnsRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListVcns(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListVcns failed: %w", err)
		}
		for _, vcn := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(vcn.Id),
				Name:       safeStr(vcn.DisplayName),
				Type:       "oci_core_vcn",
				Provider:   "oci",
				Region:     c.provider.Region(),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"cidr_block":      safeStr(vcn.CidrBlock),
					"lifecycle_state": string(vcn.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectSubnets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Network()
	if err != nil {
		return nil, fmt.Errorf("failed to get network client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListSubnetsRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListSubnets(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListSubnets failed: %w", err)
		}
		for _, s := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(s.Id),
				Name:       safeStr(s.DisplayName),
				Type:       "oci_core_subnet",
				Provider:   "oci",
				Region:     safeStr(s.AvailabilityDomain),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"cidr_block":      safeStr(s.CidrBlock),
					"vcn_id":          safeStr(s.VcnId),
					"lifecycle_state": string(s.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectSecurityLists(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Network()
	if err != nil {
		return nil, fmt.Errorf("failed to get network client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListSecurityListsRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListSecurityLists(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListSecurityLists failed: %w", err)
		}
		for _, sl := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(sl.Id),
				Name:       safeStr(sl.DisplayName),
				Type:       "oci_core_security_list",
				Provider:   "oci",
				Region:     c.provider.Region(),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"vcn_id":          safeStr(sl.VcnId),
					"lifecycle_state": string(sl.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

// =============================================================================
// Object Storage Collectors
// =============================================================================

func (c *OCICollector) collectBuckets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.ObjectStore()
	if err != nil {
		return nil, fmt.Errorf("failed to get object storage client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	nsReq := objectstorage.GetNamespaceRequest{CompartmentId: &tenancyID}
	nsResp, err := client.GetNamespace(ctx, nsReq)
	if err != nil {
		return nil, fmt.Errorf("GetNamespace failed: %w", err)
	}

	namespace := safeStr(nsResp.Value)
	req := objectstorage.ListBucketsRequest{
		NamespaceName: common.String(namespace),
		CompartmentId: &tenancyID,
	}
	var resources []Resource

	for {
		resp, err := client.ListBuckets(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListBuckets failed: %w", err)
		}
		for _, b := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(b.Name),
				Name:       safeStr(b.Name),
				Type:       "oci_objectstorage_bucket",
				Provider:   "oci",
				Region:     c.provider.Region(),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"namespace": namespace,
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

// =============================================================================
// Block Storage Collectors
// =============================================================================

func (c *OCICollector) collectVolumes(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Storage()
	if err != nil {
		return nil, fmt.Errorf("failed to get block storage client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListVolumesRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListVolumes(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListVolumes failed: %w", err)
		}
		for _, v := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(v.Id),
				Name:       safeStr(v.DisplayName),
				Type:       "oci_core_volume",
				Provider:   "oci",
				Region:     safeStr(v.AvailabilityDomain),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"size_in_gbs":     v.SizeInGBs,
					"lifecycle_state": string(v.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

func (c *OCICollector) collectBootVolumes(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Storage()
	if err != nil {
		return nil, fmt.Errorf("failed to get block storage client: %w", err)
	}

	tenancyID := c.provider.TenancyId()
	req := core.ListBootVolumesRequest{CompartmentId: &tenancyID}
	var resources []Resource

	for {
		resp, err := client.ListBootVolumes(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("ListBootVolumes failed: %w", err)
		}
		for _, v := range resp.Items {
			resources = append(resources, Resource{
				ID:         safeStr(v.Id),
				Name:       safeStr(v.DisplayName),
				Type:       "oci_core_boot_volume",
				Provider:   "oci",
				Region:     safeStr(v.AvailabilityDomain),
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"size_in_gbs":     v.SizeInGBs,
					"lifecycle_state": string(v.LifecycleState),
				},
			})
		}
		if resp.OpcNextPage == nil {
			break
		}
		req.Page = resp.OpcNextPage
	}
	return resources, nil
}

// Helper functions

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

func regionFromAD(ad string) string {
	// OCI availability domain format: "AD-1" -> region is inferred from tenancy
	if strings.HasPrefix(ad, "AD-") {
		return ad
	}
	return ad
}
