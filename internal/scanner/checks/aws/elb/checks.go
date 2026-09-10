package elb

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type elbProvider interface {
	ELB(ctx context.Context) (*elasticloadbalancing.Client, error)
}

// ElbConnectionDrainingEnabled - ELB connection draining is enabled
type ElbConnectionDrainingEnabled struct {
	metadata models.CheckMetadata
}

func NewElbConnectionDrainingEnabled() *ElbConnectionDrainingEnabled {
	return &ElbConnectionDrainingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_connection_draining_enabled",
			CheckTitle:   "ELB connection draining is enabled",
			ServiceName:  "elb",
			Severity:     "low",
			ResourceType: "LoadBalancer",
			Description:  "ELB connection draining should be enabled to allow in-flight requests to complete",
			RemediationText: "Enable connection draining on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbConnectionDrainingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbConnectionDrainingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ELB %s has connection draining enabled.", lbName)

		attrs, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: lb.LoadBalancerName,
		})
		if err == nil {
			if attrs.LoadBalancerAttributes == nil || !attrs.LoadBalancerAttributes.ConnectionDraining.Enabled {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("ELB %s does not have connection draining enabled.", lbName)
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbCrossZoneLoadBalancingEnabled - ELB cross-zone load balancing is enabled
type ElbCrossZoneLoadBalancingEnabled struct {
	metadata models.CheckMetadata
}

func NewElbCrossZoneLoadBalancingEnabled() *ElbCrossZoneLoadBalancingEnabled {
	return &ElbCrossZoneLoadBalancingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_cross_zone_load_balancing_enabled",
			CheckTitle:   "ELB cross-zone load balancing is enabled",
			ServiceName:  "elb",
			Severity:     "low",
			ResourceType: "LoadBalancer",
			Description:  "ELB cross-zone load balancing should be enabled for better distribution",
			RemediationText: "Enable cross-zone load balancing on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbCrossZoneLoadBalancingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbCrossZoneLoadBalancingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ELB %s does not have cross-zone load balancing enabled.", lbName)

		attrs, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: lb.LoadBalancerName,
		})
		if err == nil {
			if attrs.LoadBalancerAttributes != nil && attrs.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("ELB %s has cross-zone load balancing enabled.", lbName)
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbDesyncMitigationMode - ELB desync mitigation mode is defensive or strictest
type ElbDesyncMitigationMode struct {
	metadata models.CheckMetadata
}

func NewElbDesyncMitigationMode() *ElbDesyncMitigationMode {
	return &ElbDesyncMitigationMode{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_desync_mitigation_mode",
			CheckTitle:   "ELB desync mitigation mode is defensive or strictest",
			ServiceName:  "elb",
			Severity:     "medium",
			ResourceType: "LoadBalancer",
			Description:  "ELB desync mitigation mode should be set to defensive or strictest",
			RemediationText: "Set desync mitigation mode to defensive or strictest on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbDesyncMitigationMode) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbDesyncMitigationMode) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ELB %s has desync mitigation mode set to monitor.", lbName)

		attrs, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: lb.LoadBalancerName,
		})
		if err == nil {
			if attrs.LoadBalancerAttributes != nil && attrs.LoadBalancerAttributes.AdditionalAttributes != nil {
				for _, attr := range attrs.LoadBalancerAttributes.AdditionalAttributes {
					if aws.ToString(attr.Key) == "elb.http.desyncmitigationmode" {
						mode := aws.ToString(attr.Value)
						if mode == "defensive" || mode == "strictest" {
							status = models.StatusPass
							statusExtended = fmt.Sprintf("ELB %s has desync mitigation mode set to %s.", lbName, mode)
						}
					}
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbInsecureSslCiphers - ELB does not have insecure SSL ciphers
type ElbInsecureSslCiphers struct {
	metadata models.CheckMetadata
}

func NewElbInsecureSslCiphers() *ElbInsecureSslCiphers {
	return &ElbInsecureSslCiphers{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_insecure_ssl_ciphers",
			CheckTitle:   "ELB does not have insecure SSL ciphers",
			ServiceName:  "elb",
			Severity:     "high",
			ResourceType: "LoadBalancer",
			Description:  "ELBs should not use insecure SSL ciphers and protocols",
			RemediationText: "Use a security policy that disables insecure SSL ciphers",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbInsecureSslCiphers) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbInsecureSslCiphers) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ELB %s does not have insecure SSL ciphers.", lbName)

		for _, listener := range lb.ListenerDescriptions {
			if listener.Listener.Protocol == nil {
				continue
			}
			proto := aws.ToString(listener.Listener.Protocol)
			if proto == "HTTPS" || proto == "SSL" {
				// Check for known insecure policies
				for _, policy := range listener.PolicyNames {
					if policy == "ELBSecurityPolicy-2016-08" {
						status = models.StatusFail
						statusExtended = fmt.Sprintf("ELB %s uses a permissive default security policy.", lbName)
						break
					}
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbInternetFacing - ELB is not internet-facing
type ElbInternetFacing struct {
	metadata models.CheckMetadata
}

func NewElbInternetFacing() *ElbInternetFacing {
	return &ElbInternetFacing{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_internet_facing",
			CheckTitle:   "ELB is not internet-facing",
			ServiceName:  "elb",
			Severity:     "high",
			ResourceType: "LoadBalancer",
			Description:  "ELBs should not be internet-facing unless required",
			RemediationText: "Change your ELB scheme to internal",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbInternetFacing) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbInternetFacing) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ELB %s is internal.", lbName)

		if lb.Scheme != nil && aws.ToString(lb.Scheme) == "internet-facing" {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("ELB %s is internet-facing.", lbName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbIsInMultipleAz - ELB is in multiple availability zones
type ElbIsInMultipleAz struct {
	metadata models.CheckMetadata
}

func NewElbIsInMultipleAz() *ElbIsInMultipleAz {
	return &ElbIsInMultipleAz{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_is_in_multiple_az",
			CheckTitle:   "ELB is in multiple availability zones",
			ServiceName:  "elb",
			Severity:     "medium",
			ResourceType: "LoadBalancer",
			Description:  "ELBs should be in multiple availability zones for high availability",
			RemediationText: "Enable multiple availability zones on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbIsInMultipleAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbIsInMultipleAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ELB %s is not in multiple availability zones.", lbName)

		if len(lb.AvailabilityZones) > 1 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("ELB %s is in multiple availability zones.", lbName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbLoggingEnabled - ELB access logging is enabled
type ElbLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewElbLoggingEnabled() *ElbLoggingEnabled {
	return &ElbLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_logging_enabled",
			CheckTitle:   "ELB access logging is enabled",
			ServiceName:  "elb",
			Severity:     "medium",
			ResourceType: "LoadBalancer",
			Description:  "ELB access logging should be enabled for security analysis",
			RemediationText: "Enable access logging on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ELB %s does not have access logging enabled.", lbName)

		attrs, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: lb.LoadBalancerName,
		})
		if err == nil {
			if attrs.LoadBalancerAttributes != nil && attrs.LoadBalancerAttributes.AccessLog != nil {
				if attrs.LoadBalancerAttributes.AccessLog.Enabled {
					status = models.StatusPass
					statusExtended = fmt.Sprintf("ELB %s has access logging enabled.", lbName)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbSslListeners - ELB has SSL listeners
type ElbSslListeners struct {
	metadata models.CheckMetadata
}

func NewElbSslListeners() *ElbSslListeners {
	return &ElbSslListeners{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_ssl_listeners",
			CheckTitle:   "ELB has SSL listeners",
			ServiceName:  "elb",
			Severity:     "medium",
			ResourceType: "LoadBalancer",
			Description:  "ELBs should have SSL/TLS listeners for secure communication",
			RemediationText: "Configure SSL/TLS listeners on your ELBs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbSslListeners) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbSslListeners) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("ELB %s does not have SSL listeners.", lbName)

		hasSSL := false
		for _, listener := range lb.ListenerDescriptions {
			if listener.Listener.Protocol == nil {
				continue
			}
			proto := aws.ToString(listener.Listener.Protocol)
			if proto == "HTTPS" || proto == "SSL" {
				hasSSL = true
				break
			}
		}

		if hasSSL {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("ELB %s has SSL listeners.", lbName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// ElbSslListenersUseAcmCertificate - ELB SSL listeners use ACM certificates
type ElbSslListenersUseAcmCertificate struct {
	metadata models.CheckMetadata
}

func NewElbSslListenersUseAcmCertificate() *ElbSslListenersUseAcmCertificate {
	return &ElbSslListenersUseAcmCertificate{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "elb_ssl_listeners_use_acm_certificate",
			CheckTitle:   "ELB SSL listeners use ACM certificates",
			ServiceName:  "elb",
			Severity:     "low",
			ResourceType: "LoadBalancer",
			Description:  "ELB SSL listeners should use ACM certificates for easier management",
			RemediationText: "Use ACM certificates for your ELB SSL listeners",
			Categories:   []string{"networking"},
		},
	}
}

func (c *ElbSslListenersUseAcmCertificate) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElbSslListenersUseAcmCertificate) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(elbProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement elbProvider")
	}
	client, err := p.ELB(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	lbs, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe ELBs: %w", err)
	}

	for _, lb := range lbs.LoadBalancerDescriptions {
		lbName := aws.ToString(lb.LoadBalancerName)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("ELB %s SSL listeners use ACM certificates or no SSL listeners.", lbName)

		for _, listener := range lb.ListenerDescriptions {
			if listener.Listener.Protocol == nil {
				continue
			}
			proto := aws.ToString(listener.Listener.Protocol)
			if proto == "HTTPS" || proto == "SSL" {
				// Check if using ACM certificate via SSLCertificateId
				if listener.Listener.SSLCertificateId == nil || aws.ToString(listener.Listener.SSLCertificateId) == "" {
					status = models.StatusFail
					statusExtended = fmt.Sprintf("ELB %s SSL listeners do not use ACM certificates.", lbName)
				}
			}
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "elb",
			ResourceID:     lbName,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}