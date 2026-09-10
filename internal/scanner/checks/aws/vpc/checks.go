package vpc

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type vpcProvider interface {
	EC2(ctx context.Context) (*ec2.Client, error)
}

// VpcPeeringRoutingTablesWithLeastPrivilege - VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes
type VpcPeeringRoutingTablesWithLeastPrivilege struct {
	metadata models.CheckMetadata
}

func NewVpcPeeringRoutingTablesWithLeastPrivilege() *VpcPeeringRoutingTablesWithLeastPrivilege {
	return &VpcPeeringRoutingTablesWithLeastPrivilege{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_peering_routing_tables_with_least_privilege",
			CheckTitle:   "VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPCPeeringConnection",
			Description:  "VPC peering connection route tables do not include 0.0.0.0/0 or entire requester/accepter VPC CIDR routes",
			RemediationText: "Update route tables to use more specific CIDR ranges instead of 0.0.0.0/0 or the entire peer VPC CIDR",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcPeeringRoutingTablesWithLeastPrivilege) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcPeeringRoutingTablesWithLeastPrivilege) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	peers, err := ec2Client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC peering connections: %w", err)
	}

	for _, peer := range peers.VpcPeeringConnections {
		peerID := aws.ToString(peer.VpcPeeringConnectionId)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("VPC Peering Connection %s comply with least privilege access.", peerID)

		accepterCidr := ""
		if peer.AccepterVpcInfo != nil && peer.AccepterVpcInfo.CidrBlock != nil {
			accepterCidr = aws.ToString(peer.AccepterVpcInfo.CidrBlock)
		}
		requesterCidr := ""
		if peer.RequesterVpcInfo != nil && peer.RequesterVpcInfo.CidrBlock != nil {
			requesterCidr = aws.ToString(peer.RequesterVpcInfo.CidrBlock)
		}

		comply := true
		// Check route tables for routes through this peering connection
		rtOutput, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			Filters: []types.Filter{
				{Name: aws.String("route.vpc-peering-connection-id"), Values: []string{peerID}},
			},
		})
		if err == nil {
			for _, rt := range rtOutput.RouteTables {
				for _, route := range rt.Routes {
					if route.DestinationCidrBlock != nil {
						cidr := aws.ToString(route.DestinationCidrBlock)
						if cidr == "0.0.0.0/0" || cidr == accepterCidr || cidr == requesterCidr {
							comply = false
							break
						}
					}
				}
				if !comply {
					break
				}
			}
		}

		if !comply {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("VPC Peering Connection %s does not comply with least privilege access since it accepts whole VPCs CIDR in its route tables.", peerID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "vpc",
			ResourceID:     peerID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcSubnetSeparatePrivatePublic - VPC has both public and private subnets
type VpcSubnetSeparatePrivatePublic struct {
	metadata models.CheckMetadata
}

func NewVpcSubnetSeparatePrivatePublic() *VpcSubnetSeparatePrivatePublic {
	return &VpcSubnetSeparatePrivatePublic{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_subnet_separate_private_public",
			CheckTitle:   "VPC has both public and private subnets",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPC",
			Description:  "VPC should have both public and private subnets for proper network segmentation",
			RemediationText: "Create both public and private subnets in your VPC",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcSubnetSeparatePrivatePublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcSubnetSeparatePrivatePublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("VPC %s has no subnets.", vpcID)

		subnets, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: []types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			},
		})
		if err == nil && len(subnets.Subnets) > 0 {
			public := false
			private := false
			for _, subnet := range subnets.Subnets {
				// Check if subnet is public by looking at route tables
				isPublic := false
				subnetID := aws.ToString(subnet.SubnetId)
				rtOutput, err := ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
					Filters: []types.Filter{
						{Name: aws.String("association.subnet-id"), Values: []string{subnetID}},
					},
				})
				if err == nil {
					for _, rt := range rtOutput.RouteTables {
						for _, route := range rt.Routes {
							if route.GatewayId != nil && aws.ToString(route.GatewayId) != "local" &&
								(len(aws.ToString(route.GatewayId)) > 3 && aws.ToString(route.GatewayId)[:3] == "igw") {
								isPublic = true
								break
							}
						}
						if isPublic {
							break
						}
					}
				}
				if isPublic {
					public = true
				} else {
					private = true
				}
			}

			if public && private {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("VPC %s has private and public subnets.", vpcID)
			} else if public {
				statusExtended = fmt.Sprintf("VPC %s has only public subnets.", vpcID)
			} else if private {
				statusExtended = fmt.Sprintf("VPC %s has only private subnets.", vpcID)
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
			Service:        "vpc",
			ResourceID:     vpcID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcVpnConnectionTunnelsUp - AWS Site-to-Site VPN connection has both tunnels up
type VpcVpnConnectionTunnelsUp struct {
	metadata models.CheckMetadata
}

func NewVpcVpnConnectionTunnelsUp() *VpcVpnConnectionTunnelsUp {
	return &VpcVpnConnectionTunnelsUp{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_vpn_connection_tunnels_up",
			CheckTitle:   "VPC VPN connection has both tunnels UP",
			ServiceName:  "vpc",
			Severity:     "high",
			ResourceType: "VPNConnection",
			Description:  "Site-to-Site VPN connections should have both tunnels UP for high availability",
			RemediationText: "Ensure both VPN tunnels are UP by checking the VPN device configuration",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcVpnConnectionTunnelsUp) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcVpnConnectionTunnelsUp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	vpns, err := ec2Client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPN connections: %w", err)
	}

	for _, vpn := range vpns.VpnConnections {
		vpnID := aws.ToString(vpn.VpnConnectionId)
		status := models.StatusPass
		statusExtended := fmt.Sprintf("VPN Connection %s has both tunnels UP.", vpnID)

		if len(vpn.VgwTelemetry) < 2 {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("VPN Connection %s has less than 2 tunnels.", vpnID)
		} else {
			allUp := true
			for _, tunnel := range vpn.VgwTelemetry {
				if string(tunnel.Status) != "UP" {
					allUp = false
					break
				}
			}
			if !allUp {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("VPN Connection %s has at least one tunnel DOWN.", vpnID)
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
			Service:        "vpc",
			ResourceID:     vpnID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcEndpointConnectionsTrustBoundaries - VPC endpoint connections only from trusted accounts
type VpcEndpointConnectionsTrustBoundaries struct {
	metadata models.CheckMetadata
}

func NewVpcEndpointConnectionsTrustBoundaries() *VpcEndpointConnectionsTrustBoundaries {
	return &VpcEndpointConnectionsTrustBoundaries{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_endpoint_connections_trust_boundaries",
			CheckTitle:   "VPC endpoint connections only from trusted accounts",
			ServiceName:  "vpc",
			Severity:     "high",
			ResourceType: "VPCEndpoint",
			Description:  "VPC endpoint connections should only be accepted from trusted accounts",
			RemediationText: "Review and restrict VPC endpoint connection acceptance to trusted accounts",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcEndpointConnectionsTrustBoundaries) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcEndpointConnectionsTrustBoundaries) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC endpoints: %w", err)
	}

	for _, ep := range endpoints.VpcEndpoints {
		endpointID := aws.ToString(ep.VpcEndpointId)
		vpcID := aws.ToString(ep.VpcId)

		// Get the VPC endpoint policy
		_, _ = ec2Client.DescribeVpcEndpointServices(ctx, &ec2.DescribeVpcEndpointServicesInput{
			ServiceNames: []string{aws.ToString(ep.ServiceName)},
		})

		status := models.StatusPass
		statusExtended := fmt.Sprintf("VPC Endpoint %s in VPC %s has acceptable trust boundaries.", endpointID, vpcID)

		// For simplicity, flag endpoints that are in "PendingAcceptance" state as they may come from untrusted accounts
		if ep.State == types.StatePendingAcceptance {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("VPC Endpoint %s in VPC %s is in pending acceptance state.", endpointID, vpcID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "vpc",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcSubnetDifferentAz - VPC has subnets in multiple AZs
type VpcSubnetDifferentAz struct {
	metadata models.CheckMetadata
}

func NewVpcSubnetDifferentAz() *VpcSubnetDifferentAz {
	return &VpcSubnetDifferentAz{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_subnet_different_az",
			CheckTitle:   "VPC has subnets in multiple availability zones",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPC",
			Description:  "VPC should have subnets in multiple availability zones for high availability",
			RemediationText: "Create subnets in multiple availability zones",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcSubnetDifferentAz) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcSubnetDifferentAz) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("VPC %s has no subnets.", vpcID)

		subnets, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: []types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			},
		})
		if err == nil && len(subnets.Subnets) > 0 {
			azSet := make(map[string]bool)
			for _, subnet := range subnets.Subnets {
				if subnet.AvailabilityZone != nil {
					azSet[aws.ToString(subnet.AvailabilityZone)] = true
				}
			}

			if len(azSet) > 1 {
				status = models.StatusPass
				statusExtended = fmt.Sprintf("VPC %s has subnets in more than one availability zone.", vpcID)
			} else {
				for az := range azSet {
					statusExtended = fmt.Sprintf("VPC %s has only subnets in %s.", vpcID, az)
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
			Service:        "vpc",
			ResourceID:     vpcID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcEndpointMultiAzEnabled - VPC endpoint has subnets in different AZs
type VpcEndpointMultiAzEnabled struct {
	metadata models.CheckMetadata
}

func NewVpcEndpointMultiAzEnabled() *VpcEndpointMultiAzEnabled {
	return &VpcEndpointMultiAzEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_endpoint_multi_az_enabled",
			CheckTitle:   "VPC endpoint has subnets in different AZs",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPCEndpoint",
			Description:  "Interface VPC endpoints should have subnets in different availability zones",
			RemediationText: "Add subnets in different AZs to your VPC endpoint",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcEndpointMultiAzEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcEndpointMultiAzEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	endpoints, err := ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC endpoints: %w", err)
	}

	for _, ep := range endpoints.VpcEndpoints {
		// Only check Interface endpoints
		if ep.VpcEndpointType != types.VpcEndpointTypeInterface {
			continue
		}

		endpointID := aws.ToString(ep.VpcEndpointId)
		vpcID := aws.ToString(ep.VpcId)

		status := models.StatusFail
		statusExtended := fmt.Sprintf("VPC Endpoint %s in VPC %s does not have subnets in different AZs.", endpointID, vpcID)

		if len(ep.SubnetIds) > 1 {
			// Get subnet AZs
			subnetOutput, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
				SubnetIds: ep.SubnetIds,
			})
			if err == nil {
				azSet := make(map[string]bool)
				for _, subnet := range subnetOutput.Subnets {
					if subnet.AvailabilityZone != nil {
						azSet[aws.ToString(subnet.AvailabilityZone)] = true
					}
				}
				if len(azSet) > 1 {
					status = models.StatusPass
					statusExtended = fmt.Sprintf("VPC Endpoint %s in VPC %s has subnets in different AZs.", endpointID, vpcID)
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
			Service:        "vpc",
			ResourceID:     endpointID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcDifferentRegions - VPCs found in more than one region
type VpcDifferentRegions struct {
	metadata models.CheckMetadata
}

func NewVpcDifferentRegions() *VpcDifferentRegions {
	return &VpcDifferentRegions{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_different_regions",
			CheckTitle:   "VPCs found in more than one region",
			ServiceName:  "vpc",
			Severity:     "low",
			ResourceType: "Account",
			Description:  "VPCs should be deployed in multiple regions for high availability",
			RemediationText: "Deploy VPCs in multiple AWS regions",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcDifferentRegions) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcDifferentRegions) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	status := models.StatusFail
	statusExtended := "No VPCs found in this region."

	if len(vpcs.Vpcs) > 0 {
		statusExtended = "VPCs found only in one region. For multi-region support, deploy VPCs in multiple regions."
	}

	return []models.Finding{
		{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "vpc",
			ResourceID:     "account",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		},
	}, nil
}

// VpcFlowLogsEnabled - VPC flow logging is enabled
type VpcFlowLogsEnabled struct {
	metadata models.CheckMetadata
}

func NewVpcFlowLogsEnabled() *VpcFlowLogsEnabled {
	return &VpcFlowLogsEnabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_flow_logs_enabled",
			CheckTitle:   "VPC flow logging is enabled",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPC",
			Description:  "VPC flow logs should be enabled to capture network traffic information",
			RemediationText: "Enable VPC flow logs for your VPCs",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcFlowLogsEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcFlowLogsEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		vpcName := vpcID
		if vpc.Tags != nil {
			for _, tag := range vpc.Tags {
				if aws.ToString(tag.Key) == "Name" {
					vpcName = aws.ToString(tag.Value)
					break
				}
			}
		}

		status := models.StatusFail
		statusExtended := fmt.Sprintf("VPC %s Flow logs are disabled.", vpcName)

		// Check if flow logs are enabled for this VPC
		flowLogs, err := ec2Client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
			Filter: []types.Filter{
				{Name: aws.String("resource-id"), Values: []string{vpcID}},
			},
		})
		if err == nil && len(flowLogs.FlowLogs) > 0 {
			status = models.StatusPass
			statusExtended = fmt.Sprintf("VPC %s Flow logs are enabled.", vpcName)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "vpc",
			ResourceID:     vpcID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcEndpointForEc2Enabled - VPC has an EC2 endpoint
type VpcEndpointForEc2Enabled struct {
	metadata models.CheckMetadata
}

func NewVpcEndpointForEc2Enabled() *VpcEndpointForEc2Enabled {
	return &VpcEndpointForEc2Enabled{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_endpoint_for_ec2_enabled",
			CheckTitle:   "VPC has an EC2 endpoint",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "VPC",
			Description:  "VPCs should have EC2 VPC endpoints to avoid internet traversal for EC2 API calls",
			RemediationText: "Create a VPC endpoint for EC2 service",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcEndpointForEc2Enabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcEndpointForEc2Enabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	vpcs, err := ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPCs: %w", err)
	}

	for _, vpc := range vpcs.Vpcs {
		vpcID := aws.ToString(vpc.VpcId)
		status := models.StatusFail
		statusExtended := fmt.Sprintf("VPC %s has no EC2 endpoint.", vpcID)

		endpoints, err := ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			Filters: []types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			},
		})
		if err == nil {
			for _, ep := range endpoints.VpcEndpoints {
				if ep.ServiceName != nil {
					serviceName := aws.ToString(ep.ServiceName)
					if len(serviceName) > 15 && serviceName[len(serviceName)-15:] == ".ec2" {
						status = models.StatusPass
						statusExtended = fmt.Sprintf("VPC %s has an EC2 %s endpoint.", vpcID, ep.VpcEndpointType)
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
			Service:        "vpc",
			ResourceID:     vpcID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcSubnetNoPublicIpByDefault - VPC subnet does not auto-assign public IP
type VpcSubnetNoPublicIpByDefault struct {
	metadata models.CheckMetadata
}

func NewVpcSubnetNoPublicIpByDefault() *VpcSubnetNoPublicIpByDefault {
	return &VpcSubnetNoPublicIpByDefault{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_subnet_no_public_ip_by_default",
			CheckTitle:   "VPC subnet does not auto-assign public IP by default",
			ServiceName:  "vpc",
			Severity:     "medium",
			ResourceType: "Subnet",
			Description:  "Subnets should not auto-assign public IP addresses by default",
			RemediationText: "Disable auto-assign public IP on your subnets",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcSubnetNoPublicIpByDefault) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcSubnetNoPublicIpByDefault) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	subnets, err := ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe subnets: %w", err)
	}

	for _, subnet := range subnets.Subnets {
		subnetID := aws.ToString(subnet.SubnetId)

		status := models.StatusPass
		statusExtended := fmt.Sprintf("VPC subnet %s does NOT assign public IP by default.", subnetID)

		if aws.ToBool(subnet.MapPublicIpOnLaunch) {
			status = models.StatusFail
			statusExtended = fmt.Sprintf("VPC subnet %s assigns public IP by default.", subnetID)
		}

		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         status,
			StatusExtended: statusExtended,
			Provider:       "aws",
			Service:        "vpc",
			ResourceID:     subnetID,
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now().UTC(),
		})
	}

	return findings, nil
}

// VpcEndpointServicesAllowedPrincipalsTrustBoundaries - VPC endpoint services have trust boundary restrictions
type VpcEndpointServicesAllowedPrincipalsTrustBoundaries struct {
	metadata models.CheckMetadata
}

func NewVpcEndpointServicesAllowedPrincipalsTrustBoundaries() *VpcEndpointServicesAllowedPrincipalsTrustBoundaries {
	return &VpcEndpointServicesAllowedPrincipalsTrustBoundaries{
		metadata: models.CheckMetadata{
			Provider:     "aws",
			CheckID:      "vpc_endpoint_services_allowed_principals_trust_boundaries",
			CheckTitle:   "VPC endpoint services have trust boundary restrictions",
			ServiceName:  "vpc",
			Severity:     "high",
			ResourceType: "VPCEndpointService",
			Description:  "VPC endpoint services should only allow principals from trusted accounts",
			RemediationText: "Restrict VPC endpoint service allowed principals to trusted accounts",
			Categories:   []string{"networking"},
		},
	}
}

func (c *VpcEndpointServicesAllowedPrincipalsTrustBoundaries) Metadata() models.CheckMetadata { return c.metadata }

func (c *VpcEndpointServicesAllowedPrincipalsTrustBoundaries) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(vpcProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement vpcProvider")
	}
	ec2Client, err := p.EC2(ctx)
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}

	services, err := ec2Client.DescribeVpcEndpointServices(ctx, &ec2.DescribeVpcEndpointServicesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe VPC endpoint services: %w", err)
	}

	for _, service := range services.ServiceDetails {
		serviceID := aws.ToString(service.ServiceId)

		// Check allowed principals
		permissions, err := ec2Client.DescribeVpcEndpointServicePermissions(ctx, &ec2.DescribeVpcEndpointServicePermissionsInput{
			ServiceId: service.ServiceId,
		})

		if err != nil || len(permissions.AllowedPrincipals) == 0 {
			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         models.StatusPass,
				StatusExtended: fmt.Sprintf("VPC Endpoint Service %s has no allowed principals.", serviceID),
				Provider:       "aws",
				Service:        "vpc",
				ResourceID:     serviceID,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
			continue
		}

		for _, principal := range permissions.AllowedPrincipals {
			principalArn := aws.ToString(principal.Principal)
			status := models.StatusPass
			statusExtended := fmt.Sprintf("Found trusted account %s in VPC Endpoint Service %s.", principalArn, serviceID)

			// If principal is wildcard or root, flag it
			if principalArn == "*" || principalArn == "arn:aws:iam::*:root" {
				status = models.StatusFail
				statusExtended = fmt.Sprintf("Wildcard principal found in VPC Endpoint Service %s.", serviceID)
			}

			findings = append(findings, models.Finding{
				ID:             c.metadata.CheckID,
				Title:          c.metadata.CheckTitle,
				Description:    c.metadata.Description,
				Severity:       c.metadata.Severity,
				Status:         status,
				StatusExtended: statusExtended,
				Provider:       "aws",
				Service:        "vpc",
				ResourceID:     serviceID,
				Remediation:    c.metadata.RemediationText,
				Categories:     c.metadata.Categories,
				FoundAt:        time.Now().UTC(),
			})
		}
	}

	return findings, nil
}