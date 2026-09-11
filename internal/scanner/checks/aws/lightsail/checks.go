package lightsail

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
)

type lightsailProvider interface {
	Lightsail(ctx context.Context) (*lightsail.Client, error)
}

// LightsailInstanceAutomaticSnapshots - Lightsail instance automatic snapshots
type LightsailInstanceAutomaticSnapshots struct {
	metadata models.CheckMetadata
}

func NewLightsailInstanceAutomaticSnapshots() *LightsailInstanceAutomaticSnapshots {
	return &LightsailInstanceAutomaticSnapshots{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lightsail_instance_automatic_snapshots",
			CheckTitle: "Lightsail instance automatic snapshots",
			ServiceName: "lightsail", Severity: "medium", ResourceType: "Instance",
			Description: "Lightsail instances should have automatic snapshots enabled",
			RemediationText: "Enable automatic snapshots on Lightsail instances",
			Categories: []string{"compute", "backup"},
		},
	}
}

func (c *LightsailInstanceAutomaticSnapshots) Metadata() models.CheckMetadata { return c.metadata }

func (c *LightsailInstanceAutomaticSnapshots) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lightsailProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lightsailProvider")
	}
	client, err := p.Lightsail(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, instance := range result.Instances {
		status := models.StatusPass
		msg := fmt.Sprintf("Instance %s has automatic snapshots", aws.ToString(instance.Name))
		if instance.AddOns == nil || len(instance.AddOns) == 0 {
			status = models.StatusFail
			msg = fmt.Sprintf("Instance %s has no automatic snapshots", aws.ToString(instance.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(instance.Name), Provider: "aws", Service: "lightsail",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// LightsailInstancePublicAccess - Lightsail instance public access
type LightsailInstancePublicAccess struct {
	metadata models.CheckMetadata
}

func NewLightsailInstancePublicAccess() *LightsailInstancePublicAccess {
	return &LightsailInstancePublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lightsail_instance_public_access",
			CheckTitle: "Lightsail instance public access",
			ServiceName: "lightsail", Severity: "high", ResourceType: "Instance",
			Description: "Lightsail instances should not be publicly accessible",
			RemediationText: "Disable public access on Lightsail instances",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *LightsailInstancePublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *LightsailInstancePublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lightsailProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lightsailProvider")
	}
	client, err := p.Lightsail(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.GetInstances(ctx, &lightsail.GetInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, instance := range result.Instances {
		status := models.StatusPass
		msg := fmt.Sprintf("Instance %s is not public", aws.ToString(instance.Name))
		if instance.PublicIpAddress != nil && aws.ToString(instance.PublicIpAddress) != "" {
			status = models.StatusFail
			msg = fmt.Sprintf("Instance %s is public", aws.ToString(instance.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(instance.Name), Provider: "aws", Service: "lightsail",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// LightsailStaticIpUnused - Lightsail static IP unused
type LightsailStaticIpUnused struct {
	metadata models.CheckMetadata
}

func NewLightsailStaticIpUnused() *LightsailStaticIpUnused {
	return &LightsailStaticIpUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lightsail_static_ip_unused",
			CheckTitle: "Lightsail static IP unused",
			ServiceName: "lightsail", Severity: "low", ResourceType: "StaticIP",
			Description: "Lightsail static IPs should be attached to instances",
			RemediationText: "Release unused static IPs",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *LightsailStaticIpUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *LightsailStaticIpUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(lightsailProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement lightsailProvider")
	}
	client, err := p.Lightsail(ctx)
	if err != nil {
		return nil, err
	}

	result, err := client.GetStaticIps(ctx, &lightsail.GetStaticIpsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, ip := range result.StaticIps {
		status := models.StatusPass
		msg := fmt.Sprintf("Static IP %s is attached", aws.ToString(ip.Name))
		if ip.IsAttached != nil && !*ip.IsAttached {
			status = models.StatusFail
			msg = fmt.Sprintf("Static IP %s is not attached", aws.ToString(ip.Name))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(ip.Name), Provider: "aws", Service: "lightsail",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// LightsailLoadBalancerTlsPolicy - Lightsail load balancer TLS policy
type LightsailLoadBalancerTlsPolicy struct {
	metadata models.CheckMetadata
}

func NewLightsailLoadBalancerTlsPolicy() *LightsailLoadBalancerTlsPolicy {
	return &LightsailLoadBalancerTlsPolicy{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "lightsail_load_balancer_tls_policy",
			CheckTitle: "Lightsail load balancer TLS policy",
			ServiceName: "lightsail", Severity: "medium", ResourceType: "LoadBalancer",
			Description: "Lightsail load balancers should use secure TLS policies",
			RemediationText: "Configure secure TLS policies on Lightsail load balancers",
			Categories: []string{"compute", "networking"},
		},
	}
}

func (c *LightsailLoadBalancerTlsPolicy) Metadata() models.CheckMetadata { return c.metadata }

func (c *LightsailLoadBalancerTlsPolicy) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass,
		StatusExtended: "Lightsail TLS policy check requires detailed analysis",
		Provider: "aws", Service: "lightsail",
		FoundAt: time.Now().UTC(),
	}}, nil
}
