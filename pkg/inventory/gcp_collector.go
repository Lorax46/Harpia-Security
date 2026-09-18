package inventory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/providers/gcp"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudbuild/v1"
	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/cloudscheduler/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/logging/v2"
	"google.golang.org/api/monitoring/v3"
	"google.golang.org/api/pubsub/v1"
	"google.golang.org/api/redis/v1"
	"google.golang.org/api/run/v1"
	runv2 "google.golang.org/api/run/v2"
	"google.golang.org/api/secretmanager/v1"
	"google.golang.org/api/sourcerepo/v1"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/sqladmin/v1"
	"google.golang.org/api/storage/v1"
)

// GCPCollector implementa a interface Collector para GCP.
type GCPCollector struct {
	provider *gcp.Provider
	cache    map[string]*InventoryResult
	mu       sync.RWMutex
}

// NewGCPCollector cria um novo coletor GCP.
func NewGCPCollector(provider *gcp.Provider) *GCPCollector {
	return &GCPCollector{
		provider: provider,
		cache:    make(map[string]*InventoryResult),
	}
}

// Collect coleta recursos do tipo especificado.
func (c *GCPCollector) Collect(ctx context.Context, resourceType string) (*InventoryResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[resourceType]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	result := &InventoryResult{
		ResourceType: resourceType,
		Provider:     "gcp",
		Resources:    []Resource{},
		CollectedAt:  time.Now(),
	}

	var err error
	switch resourceType {
	case "gcp_compute_instance":
		result.Resources, err = c.collectComputeInstances(ctx)
	case "gcp_compute_disk":
		result.Resources, err = c.collectComputeDisks(ctx)
	case "gcp_compute_region":
		result.Resources, err = c.collectComputeRegions(ctx)
	case "gcp_compute_zone":
		result.Resources, err = c.collectComputeZones(ctx)
	case "gcp_compute_network":
		result.Resources, err = c.collectNetworks(ctx)
	case "gcp_compute_subnetwork":
		result.Resources, err = c.collectSubnetworks(ctx)
	case "gcp_compute_firewall":
		result.Resources, err = c.collectFirewalls(ctx)
	case "gcp_compute_address":
		result.Resources, err = c.collectAddresses(ctx)
	case "gcp_compute_global_address":
		result.Resources, err = c.collectGlobalAddresses(ctx)
	case "gcp_compute_health_check":
		result.Resources, err = c.collectHealthChecks(ctx)
	case "gcp_compute_instance_group":
		result.Resources, err = c.collectInstanceGroups(ctx)
	case "gcp_compute_ssl_certificate":
		result.Resources, err = c.collectSSLCertificates(ctx)
	case "gcp_compute_target_pool":
		result.Resources, err = c.collectTargetPools(ctx)
	case "gcp_compute_url_map":
		result.Resources, err = c.collectURLMaps(ctx)
	case "gcp_compute_backend_service":
		result.Resources, err = c.collectBackendServices(ctx)
	case "gcp_compute_forwarding_rule":
		result.Resources, err = c.collectForwardingRules(ctx)
	case "gcp_compute_global_forwarding_rule":
		result.Resources, err = c.collectGlobalForwardingRules(ctx)
	case "gcp_compute_backend_bucket":
		result.Resources, err = c.collectBackendBuckets(ctx)
	case "gcp_compute_target_http_proxy":
		result.Resources, err = c.collectTargetHTTPProxies(ctx)
	case "gcp_compute_target_ssl_proxy":
		result.Resources, err = c.collectTargetSSLProxies(ctx)
	case "gcp_compute_snapshot":
		result.Resources, err = c.collectSnapshots(ctx)
	case "gcp_compute_image":
		result.Resources, err = c.collectImages(ctx)
	case "gcp_compute_machine_image":
		result.Resources, err = c.collectMachineImages(ctx)
	case "gcp_compute_router":
		result.Resources, err = c.collectRouters(ctx)
	case "gcp_compute_interconnect_attachment":
		result.Resources, err = c.collectInterconnectAttachments(ctx)
	case "gcp_compute_vpn_tunnel":
		result.Resources, err = c.collectVPNTunnels(ctx)
	case "gcp_storage_bucket":
		result.Resources, err = c.collectStorageBuckets(ctx)
	case "gcp_storage_object":
		result.Resources, err = c.collectStorageObjects(ctx)
	case "gcp_sql_database_instance":
		result.Resources, err = c.collectSQLInstances(ctx)
	case "gcp_sql_database":
		result.Resources, err = c.collectSQLDatabases(ctx)
	case "gcp_sql_user":
		result.Resources, err = c.collectSQLUsers(ctx)
	case "gcp_bigquery_dataset":
		result.Resources, err = c.collectBigQueryDatasets(ctx)
	case "gcp_bigquery_table":
		result.Resources, err = c.collectBigQueryTables(ctx)
	case "gcp_bigquery_job":
		result.Resources, err = c.collectBigQueryJobs(ctx)
	case "gcp_iam_service_account":
		result.Resources, err = c.collectServiceAccounts(ctx)
	case "gcp_iam_role":
		result.Resources, err = c.collectRoles(ctx)
	case "gcp_iam_policy":
		result.Resources, err = c.collectPolicies(ctx)
	case "gcp_kms_crypto_key":
		result.Resources, err = c.collectCryptoKeys(ctx)
	case "gcp_kms_key_ring":
		result.Resources, err = c.collectKeyRings(ctx)
	case "gcp_secretmanager_secret":
		result.Resources, err = c.collectSecretManagerSecrets(ctx)
	case "gcp_container_cluster":
		result.Resources, err = c.collectGKEClusters(ctx)
	case "gcp_container_node_pool":
		result.Resources, err = c.collectGKENodePools(ctx)
	case "gcp_dns_managed_zone":
		result.Resources, err = c.collectDNSZones(ctx)
	case "gcp_dns_record_set":
		result.Resources, err = c.collectDNSRecordSets(ctx)
	case "gcp_dns_policy":
		result.Resources, err = c.collectDNSPolicies(ctx)
	case "gcp_monitoring_alert_policy":
		result.Resources, err = c.collectMonitoringAlertPolicies(ctx)
	case "gcp_monitoring_notification_channel":
		result.Resources, err = c.collectNotificationChannels(ctx)
	case "gcp_logging_sink":
		result.Resources, err = c.collectLoggingSinks(ctx)
	case "gcp_logging_metric":
		result.Resources, err = c.collectLoggingMetrics(ctx)
	case "gcp_pubsub_topic":
		result.Resources, err = c.collectPubSubTopics(ctx)
	case "gcp_pubsub_subscription":
		result.Resources, err = c.collectPubSubSubscriptions(ctx)
	case "gcp_cloudfunctions_function":
		result.Resources, err = c.collectCloudFunctions(ctx)
	case "gcp_cloud_run_service":
		result.Resources, err = c.collectCloudRunServices(ctx)
	case "gcp_cloud_run_job":
		result.Resources, err = c.collectCloudRunJobs(ctx)
	case "gcp_spanner_instance":
		result.Resources, err = c.collectSpannerInstances(ctx)
	case "gcp_spanner_database":
		result.Resources, err = c.collectSpannerDatabases(ctx)
	case "gcp_redis_instance":
		result.Resources, err = c.collectRedisInstances(ctx)
	case "gcp_artifact_registry_repository":
		result.Resources, err = c.collectArtifactRegistryRepos(ctx)
	case "gcp_cloudbuild_trigger":
		result.Resources, err = c.collectCloudBuildTriggers(ctx)
	case "gcp_source_repository":
		result.Resources, err = c.collectSourceRepos(ctx)
	case "gcp_cloudscheduler_job":
		result.Resources, err = c.collectCloudSchedulerJobs(ctx)
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

// ListResourceTypes lista todos os tipos de recursos GCP suportados.
func (c *GCPCollector) ListResourceTypes() []ResourceType {
	var resourceTypes []ResourceType
	for _, rt := range steampipeResourceTypes {
		if rt.Provider == "gcp" {
			resourceTypes = append(resourceTypes, rt)
		}
	}
	return resourceTypes
}

// =============================================================================
// Compute Engine - Instances and Disks
// =============================================================================

func (c *GCPCollector) collectComputeInstances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Instances.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, zoneList := range page.Items {
			for _, inst := range zoneList.Instances {
				region := c.zoneToRegion(inst.Zone)
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", inst.Id),
					Name:       inst.Name,
					Type:       "gcp_compute_instance",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Tags:       inst.Labels,
					Metadata: map[string]interface{}{
						"machine_type":  inst.MachineType,
						"status":        inst.Status,
						"zone":          inst.Zone,
						"cpu_platform":  inst.CpuPlatform,
						"creation_time": inst.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectComputeDisks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Disks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.DiskAggregatedList) error {
		for _, zoneList := range page.Items {
			for _, disk := range zoneList.Disks {
				region := c.zoneToRegion(disk.Zone)
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", disk.Id),
					Name:       disk.Name,
					Type:       "gcp_compute_disk",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Tags:       disk.Labels,
					Metadata: map[string]interface{}{
						"size_gb":       disk.SizeGb,
						"status":        disk.Status,
						"zone":          disk.Zone,
						"type":          disk.Type,
						"creation_time": disk.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectComputeRegions(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Regions.List(projectID)
	err = req.Pages(ctx, func(page *compute.RegionList) error {
		for _, region := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", region.Id),
				Name:       region.Name,
				Type:       "gcp_compute_region",
				Provider:   "gcp",
				Region:     region.Name,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"status":      region.Status,
					"description": region.Description,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectComputeZones(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Zones.List(projectID)
	err = req.Pages(ctx, func(page *compute.ZoneList) error {
		for _, zone := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", zone.Id),
				Name:       zone.Name,
				Type:       "gcp_compute_zone",
				Provider:   "gcp",
				Region:     zone.Name,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"status":      zone.Status,
					"description": zone.Description,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - Networks and Firewalls
// =============================================================================

func (c *GCPCollector) collectNetworks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Networks.List(projectID)
	err = req.Pages(ctx, func(page *compute.NetworkList) error {
		for _, net := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", net.Id),
				Name:       net.Name,
				Type:       "gcp_compute_network",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"description":             net.Description,
					"auto_create_subnetworks": net.AutoCreateSubnetworks,
					"creation_time":           net.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectSubnetworks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Subnetworks.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.SubnetworkAggregatedList) error {
		for region, regionList := range page.Items {
			for _, subnet := range regionList.Subnetworks {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", subnet.Id),
					Name:       subnet.Name,
					Type:       "gcp_compute_subnetwork",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"cidr_range":    subnet.IpCidrRange,
						"gateway":       subnet.GatewayAddress,
						"network":       subnet.Network,
						"region":        subnet.Region,
						"creation_time": subnet.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectFirewalls(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Firewalls.List(projectID)
	err = req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, fw := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", fw.Id),
				Name:       fw.Name,
				Type:       "gcp_compute_firewall",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"direction":     fw.Direction,
					"priority":      fw.Priority,
					"source_ranges": fw.SourceRanges,
					"network":       fw.Network,
					"creation_time": fw.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - Addresses, Health Checks, Instance Groups
// =============================================================================

func (c *GCPCollector) collectAddresses(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Addresses.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.AddressAggregatedList) error {
		for region, regionList := range page.Items {
			for _, addr := range regionList.Addresses {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", addr.Id),
					Name:       addr.Name,
					Type:       "gcp_compute_address",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"address":       addr.Address,
						"status":        addr.Status,
						"address_type":  addr.AddressType,
						"region":        addr.Region,
						"creation_time": addr.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectGlobalAddresses(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.GlobalAddresses.List(projectID)
	err = req.Pages(ctx, func(page *compute.AddressList) error {
		for _, addr := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", addr.Id),
				Name:       addr.Name,
				Type:       "gcp_compute_global_address",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"address":       addr.Address,
					"status":        addr.Status,
					"address_type":  addr.AddressType,
					"creation_time": addr.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectHealthChecks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.HealthChecks.List(projectID)
	err = req.Pages(ctx, func(page *compute.HealthCheckList) error {
		for _, hc := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", hc.Id),
				Name:       hc.Name,
				Type:       "gcp_compute_health_check",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"type":              hc.Type,
					"check_interval_sec": hc.CheckIntervalSec,
					"timeout_sec":       hc.TimeoutSec,
					"creation_time":     hc.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectInstanceGroups(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.InstanceGroups.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InstanceGroupAggregatedList) error {
		for zone, zoneList := range page.Items {
			for _, ig := range zoneList.InstanceGroups {
				region := c.zoneToRegion(zone)
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", ig.Id),
					Name:       ig.Name,
					Type:       "gcp_compute_instance_group",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"zone":          zone,
						"network":       ig.Network,
						"subnetwork":    ig.Subnetwork,
						"creation_time": ig.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - SSL Certs, Target Pools, URL Maps, Backend Services
// =============================================================================

func (c *GCPCollector) collectSSLCertificates(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.SslCertificates.List(projectID)
	err = req.Pages(ctx, func(page *compute.SslCertificateList) error {
		for _, cert := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", cert.Id),
				Name:       cert.Name,
				Type:       "gcp_compute_ssl_certificate",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"type":          cert.Type,
					"creation_time": cert.CreationTimestamp,
					"expires":       cert.ExpireTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectTargetPools(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.TargetPools.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.TargetPoolAggregatedList) error {
		for region, regionList := range page.Items {
			for _, tp := range regionList.TargetPools {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", tp.Id),
					Name:       tp.Name,
					Type:       "gcp_compute_target_pool",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"region":           tp.Region,
						"session_affinity": tp.SessionAffinity,
						"creation_time":    tp.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectURLMaps(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.UrlMaps.List(projectID)
	err = req.Pages(ctx, func(page *compute.UrlMapList) error {
		for _, um := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", um.Id),
				Name:       um.Name,
				Type:       "gcp_compute_url_map",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"default_service": um.DefaultService,
					"creation_time":   um.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectBackendServices(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.BackendServices.List(projectID)
	err = req.Pages(ctx, func(page *compute.BackendServiceList) error {
		for _, bs := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", bs.Id),
				Name:       bs.Name,
				Type:       "gcp_compute_backend_service",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"protocol":      bs.Protocol,
					"self_link":     bs.SelfLink,
					"creation_time": bs.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - Forwarding Rules
// =============================================================================

func (c *GCPCollector) collectForwardingRules(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.ForwardingRules.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for region, regionList := range page.Items {
			for _, fr := range regionList.ForwardingRules {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", fr.Id),
					Name:       fr.Name,
					Type:       "gcp_compute_forwarding_rule",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"ip_address":            fr.IPAddress,
						"ip_protocol":           fr.IPProtocol,
						"load_balancing_scheme": fr.LoadBalancingScheme,
						"creation_time":         fr.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectGlobalForwardingRules(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.GlobalForwardingRules.List(projectID)
	err = req.Pages(ctx, func(page *compute.ForwardingRuleList) error {
		for _, fr := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", fr.Id),
				Name:       fr.Name,
				Type:       "gcp_compute_global_forwarding_rule",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"ip_address":            fr.IPAddress,
					"ip_protocol":           fr.IPProtocol,
					"load_balancing_scheme": fr.LoadBalancingScheme,
					"creation_time":         fr.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectBackendBuckets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.BackendBuckets.List(projectID)
	err = req.Pages(ctx, func(page *compute.BackendBucketList) error {
		for _, bb := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", bb.Id),
				Name:       bb.Name,
				Type:       "gcp_compute_backend_bucket",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"bucket_name":   bb.BucketName,
					"enable_cdn":    bb.EnableCdn,
					"creation_time": bb.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectTargetHTTPProxies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.TargetHttpProxies.List(projectID)
	err = req.Pages(ctx, func(page *compute.TargetHttpProxyList) error {
		for _, thp := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", thp.Id),
				Name:       thp.Name,
				Type:       "gcp_compute_target_http_proxy",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"url_map":       thp.UrlMap,
					"creation_time": thp.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectTargetSSLProxies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.TargetSslProxies.List(projectID)
	err = req.Pages(ctx, func(page *compute.TargetSslProxyList) error {
		for _, tsp := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", tsp.Id),
				Name:       tsp.Name,
				Type:       "gcp_compute_target_ssl_proxy",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"service":          tsp.Service,
					"ssl_certificates": tsp.SslCertificates,
					"creation_time":    tsp.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - Snapshots and Images
// =============================================================================

func (c *GCPCollector) collectSnapshots(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Snapshots.List(projectID)
	err = req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snap := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", snap.Id),
				Name:       snap.Name,
				Type:       "gcp_compute_snapshot",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       snap.Labels,
				Metadata: map[string]interface{}{
					"source_disk":   snap.SourceDisk,
					"status":        snap.Status,
					"disk_size_gb":  snap.DiskSizeGb,
					"creation_time": snap.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectImages(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Images.List(projectID)
	err = req.Pages(ctx, func(page *compute.ImageList) error {
		for _, img := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", img.Id),
				Name:       img.Name,
				Type:       "gcp_compute_image",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       img.Labels,
				Metadata: map[string]interface{}{
					"status":        img.Status,
					"disk_size_gb":  img.DiskSizeGb,
					"family":        img.Family,
					"creation_time": img.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectMachineImages(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.MachineImages.List(projectID)
	err = req.Pages(ctx, func(page *compute.MachineImageList) error {
		for _, mi := range page.Items {
			resources = append(resources, Resource{
				ID:         fmt.Sprintf("%d", mi.Id),
				Name:       mi.Name,
				Type:       "gcp_compute_machine_image",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"status":          mi.Status,
					"source_instance": mi.SourceInstance,
					"creation_time":   mi.CreationTimestamp,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Compute Engine - Routers, Interconnect, VPN
// =============================================================================

func (c *GCPCollector) collectRouters(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Routers.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.RouterAggregatedList) error {
		for region, regionList := range page.Items {
			for _, router := range regionList.Routers {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", router.Id),
					Name:       router.Name,
					Type:       "gcp_compute_router",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"network":       router.Network,
						"region":        router.Region,
						"creation_time": router.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectInterconnectAttachments(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.InterconnectAttachments.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.InterconnectAttachmentAggregatedList) error {
		for region, regionList := range page.Items {
			for _, ia := range regionList.InterconnectAttachments {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", ia.Id),
					Name:       ia.Name,
					Type:       "gcp_compute_interconnect_attachment",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"interconnect":  ia.Interconnect,
						"router":        ia.Router,
						"status":        ia.OperationalStatus,
						"creation_time": ia.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectVPNTunnels(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Compute(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.VpnTunnels.AggregatedList(projectID)
	err = req.Pages(ctx, func(page *compute.VpnTunnelAggregatedList) error {
		for region, regionList := range page.Items {
			for _, tunnel := range regionList.VpnTunnels {
				resources = append(resources, Resource{
					ID:         fmt.Sprintf("%d", tunnel.Id),
					Name:       tunnel.Name,
					Type:       "gcp_compute_vpn_tunnel",
					Provider:   "gcp",
					Region:     region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"peer_ip":         tunnel.PeerIp,
						"status":          tunnel.Status,
						"detailed_status": tunnel.DetailedStatus,
						"creation_time":   tunnel.CreationTimestamp,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Cloud Storage
// =============================================================================

func (c *GCPCollector) collectStorageBuckets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Storage(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Buckets.List(projectID)
	err = req.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			resources = append(resources, Resource{
				ID:         bucket.Name,
				Name:       bucket.Name,
				Type:       "gcp_storage_bucket",
				Provider:   "gcp",
				Region:     bucket.Location,
				Discovered: time.Now(),
				Tags:       bucket.Labels,
				Metadata: map[string]interface{}{
					"location_type": bucket.LocationType,
					"storage_class": bucket.StorageClass,
					"created":       bucket.TimeCreated,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectStorageObjects(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Storage(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	bucketReq := client.Buckets.List(projectID)
	var resources []Resource

	err = bucketReq.Pages(ctx, func(page *storage.Buckets) error {
		for _, bucket := range page.Items {
			objReq := client.Objects.List(bucket.Name)
			objReq.MaxResults(100)
			err := objReq.Pages(ctx, func(objPage *storage.Objects) error {
				for _, obj := range objPage.Items {
					resources = append(resources, Resource{
						ID:         obj.Name,
						Name:       obj.Name,
						Type:       "gcp_storage_object",
						Provider:   "gcp",
						Region:     bucket.Location,
						Discovered: time.Now(),
						Metadata: map[string]interface{}{
							"bucket":       bucket.Name,
							"size":         obj.Size,
							"content_type": obj.ContentType,
							"updated":      obj.Updated,
						},
					})
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Cloud SQL
// =============================================================================

func (c *GCPCollector) collectSQLInstances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQL(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Instances.List(projectID)
	err = req.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, inst := range page.Items {
			resources = append(resources, Resource{
				ID:         inst.Name,
				Name:       inst.Name,
				Type:       "gcp_sql_database_instance",
				Provider:   "gcp",
				Region:     inst.Region,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"database_version": inst.DatabaseVersion,
					"state":            inst.State,
					"instance_type":    inst.InstanceType,
					"backend_type":     inst.BackendType,
					"connection_name":  inst.ConnectionName,
					"gce_zone":         inst.GceZone,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectSQLDatabases(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQL(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	instReq := client.Instances.List(projectID)
	var resources []Resource

	err = instReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, inst := range page.Items {
			dbResp, err := client.Databases.List(projectID, inst.Name).Context(ctx).Do()
			if err != nil {
				continue
			}
			for _, db := range dbResp.Items {
				resources = append(resources, Resource{
					ID:         db.Name,
					Name:       db.Name,
					Type:       "gcp_sql_database",
					Provider:   "gcp",
					Region:     inst.Region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"instance":  inst.Name,
						"charset":   db.Charset,
						"collation": db.Collation,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectSQLUsers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.SQL(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	instReq := client.Instances.List(projectID)
	var resources []Resource

	err = instReq.Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		for _, inst := range page.Items {
			userResp, err := client.Users.List(projectID, inst.Name).Context(ctx).Do()
			if err != nil {
				continue
			}
			for _, user := range userResp.Items {
				resources = append(resources, Resource{
					ID:         user.Name,
					Name:       user.Name,
					Type:       "gcp_sql_user",
					Provider:   "gcp",
					Region:     inst.Region,
					Discovered: time.Now(),
					Metadata: map[string]interface{}{
						"instance": inst.Name,
						"host":     user.Host,
						"etag":     user.Etag,
					},
				})
			}
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// BigQuery
// =============================================================================

func (c *GCPCollector) collectBigQueryDatasets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.BigQuery(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Datasets.List(projectID)
	err = req.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			resources = append(resources, Resource{
				ID:         ds.DatasetReference.DatasetId,
				Name:       ds.DatasetReference.DatasetId,
				Type:       "gcp_bigquery_dataset",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       ds.Labels,
				Metadata: map[string]interface{}{
					"project":       ds.DatasetReference.ProjectId,
					"friendly_name": ds.FriendlyName,
					"location":      ds.Location,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectBigQueryTables(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.BigQuery(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	dsReq := client.Datasets.List(projectID)
	var resources []Resource

	err = dsReq.Pages(ctx, func(page *bigquery.DatasetList) error {
		for _, ds := range page.Datasets {
			tblReq := client.Tables.List(projectID, ds.DatasetReference.DatasetId)
			err := tblReq.Pages(ctx, func(tblPage *bigquery.TableList) error {
				for _, tbl := range tblPage.Tables {
					resources = append(resources, Resource{
						ID:         tbl.TableReference.TableId,
						Name:       tbl.TableReference.TableId,
						Type:       "gcp_bigquery_table",
						Provider:   "gcp",
						Region:     "global",
						Discovered: time.Now(),
						Metadata: map[string]interface{}{
							"project":       tbl.TableReference.ProjectId,
							"dataset":       tbl.TableReference.DatasetId,
							"friendly_name": tbl.FriendlyName,
							"type":          tbl.Type,
						},
					})
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectBigQueryJobs(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.BigQuery(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Jobs.List(projectID)
	err = req.Pages(ctx, func(page *bigquery.JobList) error {
		for _, job := range page.Jobs {
			resources = append(resources, Resource{
				ID:         job.JobReference.JobId,
				Name:       job.JobReference.JobId,
				Type:       "gcp_bigquery_job",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"project":  job.JobReference.ProjectId,
					"state":    job.State,
					"job_type": job.Configuration.JobType,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// IAM - Service Accounts, Roles, Policies
// =============================================================================

func (c *GCPCollector) collectServiceAccounts(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	name := fmt.Sprintf("projects/%s", projectID)
	req := client.Projects.ServiceAccounts.List(name)
	err = req.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			resources = append(resources, Resource{
				ID:         sa.UniqueId,
				Name:       sa.Email,
				Type:       "gcp_iam_service_account",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"display_name":     sa.DisplayName,
					"project":          sa.ProjectId,
					"description":      sa.Description,
					"oauth2_client_id": sa.Oauth2ClientId,
					"disabled":         sa.Disabled,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectRoles(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	name := fmt.Sprintf("projects/%s", projectID)
	req := client.Projects.Roles.List(name)
	err = req.Pages(ctx, func(page *iam.ListRolesResponse) error {
		for _, role := range page.Roles {
			resources = append(resources, Resource{
				ID:         role.Name,
				Name:       role.Name,
				Type:       "gcp_iam_role",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"title":       role.Title,
					"description": role.Description,
					"deleted":     role.Deleted,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectPolicies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.IAM(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	name := fmt.Sprintf("projects/%s", projectID)
	saReq := client.Projects.ServiceAccounts.List(name)
	var resources []Resource

	err = saReq.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, sa := range page.Accounts {
			policyReq := client.Projects.ServiceAccounts.GetIamPolicy(sa.Name)
			policyReq.Context(ctx)
			policy, err := policyReq.Do()
			if err != nil {
				continue
			}
			resources = append(resources, Resource{
				ID:         sa.Name,
				Name:       sa.Name,
				Type:       "gcp_iam_policy",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"resource_type":  "service_account",
					"resource_id":    sa.Name,
					"etag":           policy.Etag,
					"version":        policy.Version,
					"bindings_count": len(policy.Bindings),
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// KMS - Key Rings and Crypto Keys
// =============================================================================

func (c *GCPCollector) collectKeyRings(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.KMS(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := client.Projects.Locations.KeyRings.List(parent)
	err = req.Pages(ctx, func(page *cloudkms.ListKeyRingsResponse) error {
		for _, kr := range page.KeyRings {
			resources = append(resources, Resource{
				ID:         kr.Name,
				Name:       kr.Name,
				Type:       "gcp_kms_key_ring",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"create_time": kr.CreateTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectCryptoKeys(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.KMS(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	krReq := client.Projects.Locations.KeyRings.List(parent)
	var resources []Resource

	err = krReq.Pages(ctx, func(page *cloudkms.ListKeyRingsResponse) error {
		for _, kr := range page.KeyRings {
			ckReq := client.Projects.Locations.KeyRings.CryptoKeys.List(kr.Name)
			err := ckReq.Pages(ctx, func(ckPage *cloudkms.ListCryptoKeysResponse) error {
				for _, ck := range ckPage.CryptoKeys {
					resources = append(resources, Resource{
						ID:         ck.Name,
						Name:       ck.Name,
						Type:       "gcp_kms_crypto_key",
						Provider:   "gcp",
						Region:     region,
						Discovered: time.Now(),
						Metadata: map[string]interface{}{
							"purpose":            ck.Purpose,
							"rotation_period":   ck.RotationPeriod,
							"next_rotation_time": ck.NextRotationTime,
							"create_time":        ck.CreateTime,
							"key_ring":           kr.Name,
						},
					})
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Secret Manager
// =============================================================================

func (c *GCPCollector) collectSecretManagerSecrets(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	parent := fmt.Sprintf("projects/%s", projectID)

	service, err := c.newSecretManagerService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	req := service.Projects.Secrets.List(parent)
	err = req.Pages(ctx, func(page *secretmanager.ListSecretsResponse) error {
		for _, secret := range page.Secrets {
			resources = append(resources, Resource{
				ID:         secret.Name,
				Name:       secret.Name,
				Type:       "gcp_secretmanager_secret",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       secret.Labels,
				Metadata: map[string]interface{}{
					"create_time": secret.CreateTime,
					"etag":        secret.Etag,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// GKE - Clusters and Node Pools
// =============================================================================

func (c *GCPCollector) collectGKEClusters(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.GKE(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	var resources []Resource
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	req := client.Projects.Locations.Clusters.List(parent)
	resp, err := req.Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, cluster := range resp.Clusters {
		resources = append(resources, Resource{
			ID:         cluster.Name,
			Name:       cluster.Name,
			Type:       "gcp_container_cluster",
			Provider:   "gcp",
			Region:     region,
			Discovered: time.Now(),
			Metadata: map[string]interface{}{
				"location":           cluster.Location,
				"status":             cluster.Status,
				"endpoint":           cluster.Endpoint,
				"initial_node_count": cluster.InitialNodeCount,
				"current_node_count": cluster.CurrentNodeCount,
				"cluster_ipv4_cidr":  cluster.ClusterIpv4Cidr,
				"network":            cluster.Network,
				"subnetwork":         cluster.Subnetwork,
				"create_time":        cluster.CreateTime,
			},
		})
	}
	return resources, nil
}

func (c *GCPCollector) collectGKENodePools(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.GKE(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	clusterReq := client.Projects.Locations.Clusters.List(parent)
	resp, err := clusterReq.Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	var resources []Resource
	for _, cluster := range resp.Clusters {
		for _, pool := range cluster.NodePools {
			resources = append(resources, Resource{
				ID:         pool.Name,
				Name:       pool.Name,
				Type:       "gcp_container_node_pool",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"cluster":            cluster.Name,
					"location":           cluster.Location,
					"initial_node_count": pool.InitialNodeCount,
					"status":             pool.Status,
					"version":            pool.Version,
					"auto_repair":        pool.Management.AutoRepair,
					"auto_upgrade":       pool.Management.AutoUpgrade,
				},
			})
		}
	}
	return resources, nil
}

// =============================================================================
// Cloud DNS
// =============================================================================

func (c *GCPCollector) collectDNSZones(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.DNS(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.ManagedZones.List(projectID)
	err = req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			resources = append(resources, Resource{
				ID:         zone.Name,
				Name:       zone.Name,
				Type:       "gcp_dns_managed_zone",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"dns_name":    zone.DnsName,
					"description": zone.Description,
					"visibility":  zone.Visibility,
					"create_time": zone.CreationTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectDNSRecordSets(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.DNS(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	zoneReq := client.ManagedZones.List(projectID)
	var resources []Resource

	err = zoneReq.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		for _, zone := range page.ManagedZones {
			rsReq := client.ResourceRecordSets.List(projectID, zone.Name)
			err := rsReq.Pages(ctx, func(rsPage *dns.ResourceRecordSetsListResponse) error {
				for _, rs := range rsPage.Rrsets {
					resources = append(resources, Resource{
						ID:         rs.Name,
						Name:       rs.Name,
						Type:       "gcp_dns_record_set",
						Provider:   "gcp",
						Region:     "global",
						Discovered: time.Now(),
						Metadata: map[string]interface{}{
							"zone":     zone.Name,
							"dns_name": zone.DnsName,
							"type":     rs.Type,
							"ttl":      rs.Ttl,
							"rrdatas":  rs.Rrdatas,
						},
					})
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectDNSPolicies(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.DNS(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Policies.List(projectID)
	err = req.Pages(ctx, func(page *dns.PoliciesListResponse) error {
		for _, policy := range page.Policies {
			resources = append(resources, Resource{
				ID:         policy.Name,
				Name:       policy.Name,
				Type:       "gcp_dns_policy",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"description":               policy.Description,
					"enable_inbound_forwarding": policy.EnableInboundForwarding,
					"enable_logging":            policy.EnableLogging,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Pub/Sub
// =============================================================================

func (c *GCPCollector) collectPubSubTopics(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	service, err := c.newPubSubService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	parent := fmt.Sprintf("projects/%s", projectID)
	req := service.Projects.Topics.List(parent)
	err = req.Pages(ctx, func(page *pubsub.ListTopicsResponse) error {
		for _, topic := range page.Topics {
			resources = append(resources, Resource{
				ID:         topic.Name,
				Name:       topic.Name,
				Type:       "gcp_pubsub_topic",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       topic.Labels,
				Metadata: map[string]interface{}{
					"message_storage_policy": topic.MessageStoragePolicy,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectPubSubSubscriptions(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	service, err := c.newPubSubService(ctx)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	parent := fmt.Sprintf("projects/%s", projectID)
	req := service.Projects.Subscriptions.List(parent)
	err = req.Pages(ctx, func(page *pubsub.ListSubscriptionsResponse) error {
		for _, sub := range page.Subscriptions {
			resources = append(resources, Resource{
				ID:         sub.Name,
				Name:       sub.Name,
				Type:       "gcp_pubsub_subscription",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       sub.Labels,
				Metadata: map[string]interface{}{
					"topic":                      sub.Topic,
					"ack_deadline_seconds":       sub.AckDeadlineSeconds,
					"retain_acked_messages":      sub.RetainAckedMessages,
					"message_retention_duration": sub.MessageRetentionDuration,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Cloud Functions
// =============================================================================

func (c *GCPCollector) collectCloudFunctions(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.CloudFunctions(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := client.Projects.Locations.Functions.List(parent)
	err = req.Pages(ctx, func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range page.Functions {
			resources = append(resources, Resource{
				ID:         fn.Name,
				Name:       fn.Name,
				Type:       "gcp_cloudfunctions_function",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"status":              fn.Status,
					"entry_point":         fn.EntryPoint,
					"runtime":             fn.Runtime,
					"timeout":             fn.Timeout,
					"available_memory_mb": fn.AvailableMemoryMb,
					"service_email":       fn.ServiceAccountEmail,
					"update_time":         fn.UpdateTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Cloud Run
// =============================================================================

func (c *GCPCollector) collectCloudRunServices(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	service, err := c.newCloudRunV1Service(ctx)
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("namespaces/%s", projectID)
	var resources []Resource

	resp, err := service.Namespaces.Services.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	for _, svc := range resp.Items {
		resources = append(resources, Resource{
			ID:         svc.Metadata.Name,
			Name:       svc.Metadata.Name,
			Type:       "gcp_cloud_run_service",
			Provider:   "gcp",
			Region:     region,
			Discovered: time.Now(),
			Tags:       svc.Metadata.Labels,
			Metadata: map[string]interface{}{
				"namespace":        svc.Metadata.Namespace,
				"resource_version": svc.Metadata.ResourceVersion,
				"generation":       svc.Metadata.Generation,
			},
		})
	}
	return resources, nil
}

func (c *GCPCollector) collectCloudRunJobs(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	service, err := c.newCloudRunV2Service(ctx)
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := service.Projects.Locations.Jobs.List(parent)
	err = req.Pages(ctx, func(page *runv2.GoogleCloudRunV2ListJobsResponse) error {
		for _, job := range page.Jobs {
			resources = append(resources, Resource{
				ID:         job.Name,
				Name:       job.Name,
				Type:       "gcp_cloud_run_job",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Tags:       job.Labels,
				Metadata: map[string]interface{}{
					"generation":  job.Generation,
					"create_time": job.CreateTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Spanner, Redis, Artifact Registry
// =============================================================================

func (c *GCPCollector) collectSpannerInstances(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Spanner(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	parent := fmt.Sprintf("projects/%s", projectID)
	var resources []Resource

	req := client.Projects.Instances.List(parent)
	err = req.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, inst := range page.Instances {
			resources = append(resources, Resource{
				ID:         inst.Name,
				Name:       inst.Name,
				Type:       "gcp_spanner_instance",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Tags:       inst.Labels,
				Metadata: map[string]interface{}{
					"display_name": inst.DisplayName,
					"config":       inst.Config,
					"node_count":   inst.NodeCount,
					"state":        inst.State,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectSpannerDatabases(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Spanner(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	parent := fmt.Sprintf("projects/%s", projectID)
	instReq := client.Projects.Instances.List(parent)
	var resources []Resource

	err = instReq.Pages(ctx, func(page *spanner.ListInstancesResponse) error {
		for _, inst := range page.Instances {
			dbReq := client.Projects.Instances.Databases.List(inst.Name)
			err := dbReq.Pages(ctx, func(dbPage *spanner.ListDatabasesResponse) error {
				for _, db := range dbPage.Databases {
					resources = append(resources, Resource{
						ID:         db.Name,
						Name:       db.Name,
						Type:       "gcp_spanner_database",
						Provider:   "gcp",
						Region:     "global",
						Discovered: time.Now(),
						Metadata: map[string]interface{}{
							"instance": inst.Name,
							"state":    db.State,
						},
					})
				}
				return nil
			})
			if err != nil {
				continue
			}
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectRedisInstances(ctx context.Context) ([]Resource, error) {
	service, err := c.newRedisService(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := service.Projects.Locations.Instances.List(parent)
	err = req.Pages(ctx, func(page *redis.ListInstancesResponse) error {
		for _, inst := range page.Instances {
			resources = append(resources, Resource{
				ID:         inst.Name,
				Name:       inst.Name,
				Type:       "gcp_redis_instance",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Tags:       inst.Labels,
				Metadata: map[string]interface{}{
					"display_name":   inst.DisplayName,
					"tier":           inst.Tier,
					"memory_size_gb": inst.MemorySizeGb,
					"host":           inst.Host,
					"port":           inst.Port,
					"status_message": inst.StatusMessage,
					"redis_version":  inst.RedisVersion,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectArtifactRegistryRepos(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.ArtifactRegistry(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := client.Projects.Locations.Repositories.List(parent)
	err = req.Pages(ctx, func(page *artifactregistry.ListRepositoriesResponse) error {
		for _, repo := range page.Repositories {
			resources = append(resources, Resource{
				ID:         repo.Name,
				Name:       repo.Name,
				Type:       "gcp_artifact_registry_repository",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Tags:       repo.Labels,
				Metadata: map[string]interface{}{
					"format":      repo.Format,
					"description": repo.Description,
					"create_time": repo.CreateTime,
					"update_time": repo.UpdateTime,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Cloud Build, Source Repositories, Cloud Scheduler
// =============================================================================

func (c *GCPCollector) collectCloudBuildTriggers(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.CloudBuild(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	req := client.Projects.Triggers.List(projectID)
	err = req.Pages(ctx, func(page *cloudbuild.ListBuildTriggersResponse) error {
		for _, trigger := range page.Triggers {
			resources = append(resources, Resource{
				ID:         trigger.Id,
				Name:       trigger.Id,
				Type:       "gcp_cloudbuild_trigger",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"description": trigger.Description,
					"disabled":    trigger.Disabled,
					"filename":    trigger.Filename,
					"create_time": trigger.CreateTime,
					"tags":        strings.Join(trigger.Tags, ","),
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectSourceRepos(ctx context.Context) ([]Resource, error) {
	service, err := c.newSourceRepoService(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	var resources []Resource
	parent := fmt.Sprintf("projects/%s", projectID)
	req := service.Projects.Repos.List(parent)
	err = req.Pages(ctx, func(page *sourcerepo.ListReposResponse) error {
		for _, repo := range page.Repos {
			resources = append(resources, Resource{
				ID:         repo.Name,
				Name:       repo.Name,
				Type:       "gcp_source_repository",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"size": repo.Size,
					"url":  repo.Url,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectCloudSchedulerJobs(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.CloudScheduler(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()
	region := c.provider.Region()

	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, region)
	var resources []Resource

	req := client.Projects.Locations.Jobs.List(parent)
	err = req.Pages(ctx, func(page *cloudscheduler.ListJobsResponse) error {
		for _, job := range page.Jobs {
			resources = append(resources, Resource{
				ID:         job.Name,
				Name:       job.Name,
				Type:       "gcp_cloudscheduler_job",
				Provider:   "gcp",
				Region:     region,
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"description": job.Description,
					"schedule":    job.Schedule,
					"time_zone":   job.TimeZone,
					"state":       job.State,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Monitoring and Logging
// =============================================================================

func (c *GCPCollector) collectMonitoringAlertPolicies(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	service, err := c.newMonitoringService(ctx)
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("projects/%s", projectID)
	var resources []Resource

	req := service.Projects.AlertPolicies.List(name)
	err = req.Pages(ctx, func(page *monitoring.ListAlertPoliciesResponse) error {
		for _, policy := range page.AlertPolicies {
			resources = append(resources, Resource{
				ID:         policy.Name,
				Name:       policy.Name,
				Type:       "gcp_monitoring_alert_policy",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"display_name": policy.DisplayName,
					"enabled":      policy.Enabled,
					"combiner":     policy.Combiner,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectNotificationChannels(ctx context.Context) ([]Resource, error) {
	projectID := c.provider.ProjectID()
	service, err := c.newMonitoringService(ctx)
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("projects/%s", projectID)
	var resources []Resource

	req := service.Projects.NotificationChannels.List(name)
	err = req.Pages(ctx, func(page *monitoring.ListNotificationChannelsResponse) error {
		for _, ch := range page.NotificationChannels {
			resources = append(resources, Resource{
				ID:         ch.Name,
				Name:       ch.Name,
				Type:       "gcp_monitoring_notification_channel",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"display_name": ch.DisplayName,
					"type":         ch.Type,
					"enabled":      ch.Enabled,
					"description":  ch.Description,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectLoggingSinks(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Logging(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	parent := fmt.Sprintf("projects/%s", projectID)
	var resources []Resource

	sinksReq := client.Projects.Sinks.List(parent)
	err = sinksReq.Pages(ctx, func(page *logging.ListSinksResponse) error {
		for _, sink := range page.Sinks {
			resources = append(resources, Resource{
				ID:         sink.Name,
				Name:       sink.Name,
				Type:       "gcp_logging_sink",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"destination":     sink.Destination,
					"filter":          sink.Filter,
					"writer_identity": sink.WriterIdentity,
				},
			})
		}
		return nil
	})
	return resources, err
}

func (c *GCPCollector) collectLoggingMetrics(ctx context.Context) ([]Resource, error) {
	client, err := c.provider.Logging(ctx)
	if err != nil {
		return nil, err
	}
	projectID := c.provider.ProjectID()

	parent := fmt.Sprintf("projects/%s", projectID)
	var resources []Resource

	metricsReq := client.Projects.Metrics.List(parent)
	err = metricsReq.Pages(ctx, func(page *logging.ListLogMetricsResponse) error {
		for _, metric := range page.Metrics {
			resources = append(resources, Resource{
				ID:         metric.Name,
				Name:       metric.Name,
				Type:       "gcp_logging_metric",
				Provider:   "gcp",
				Region:     "global",
				Discovered: time.Now(),
				Metadata: map[string]interface{}{
					"description": metric.Description,
					"filter":      metric.Filter,
				},
			})
		}
		return nil
	})
	return resources, err
}

// =============================================================================
// Helpers
// =============================================================================

func (c *GCPCollector) zoneToRegion(zone string) string {
	parts := strings.Split(zone, "/")
	name := parts[len(parts)-1]
	idx := strings.LastIndex(name, "-")
	if idx > 0 {
		return name[:idx]
	}
	return name
}

func (c *GCPCollector) newSecretManagerService(ctx context.Context) (*secretmanager.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return secretmanager.NewService(ctx, opts...)
}

func (c *GCPCollector) newPubSubService(ctx context.Context) (*pubsub.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return pubsub.NewService(ctx, opts...)
}

func (c *GCPCollector) newCloudRunV1Service(ctx context.Context) (*run.APIService, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return run.NewService(ctx, opts...)
}

func (c *GCPCollector) newCloudRunV2Service(ctx context.Context) (*runv2.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return runv2.NewService(ctx, opts...)
}

func (c *GCPCollector) newRedisService(ctx context.Context) (*redis.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return redis.NewService(ctx, opts...)
}

func (c *GCPCollector) newSourceRepoService(ctx context.Context) (*sourcerepo.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return sourcerepo.NewService(ctx, opts...)
}

func (c *GCPCollector) newMonitoringService(ctx context.Context) (*monitoring.Service, error) {
	opts, err := c.provider.ClientOptions(ctx)
	if err != nil {
		return nil, err
	}
	return monitoring.NewService(ctx, opts...)
}
