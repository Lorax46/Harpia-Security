package ec2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ClientVpnEndpointConnectionLoggingEnabled - verifica logging de VPN
type ClientVpnEndpointConnectionLoggingEnabled struct {
	metadata models.CheckMetadata
}

func NewClientVpnEndpointConnectionLoggingEnabled() *ClientVpnEndpointConnectionLoggingEnabled {
	return &ClientVpnEndpointConnectionLoggingEnabled{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_client_vpn_endpoint_connection_logging_enabled",
			CheckTitle: "Ensure Client VPN endpoint has connection logging enabled",
			Description: "Client VPN endpoints should have connection logging enabled",
			Severity: "medium", ServiceName: "ec2", ResourceType: "ClientVpnEndpoint",
			RemediationText: "Enable connection logging for Client VPN endpoints",
			Categories: []string{"ec2", "vpn", "logging"},
		},
	}
}

func (c *ClientVpnEndpointConnectionLoggingEnabled) Metadata() models.CheckMetadata { return c.metadata }

func (c *ClientVpnEndpointConnectionLoggingEnabled) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, endpoint := range result.ClientVpnEndpoints {
		status := models.StatusFail
		msg := fmt.Sprintf("VPN endpoint %s has no connection logging", aws.ToString(endpoint.ClientVpnEndpointId))
		if endpoint.ConnectionLogOptions != nil && endpoint.ConnectionLogOptions.Enabled != nil && *endpoint.ConnectionLogOptions.Enabled {
			status = models.StatusPass
			msg = fmt.Sprintf("VPN endpoint %s has connection logging enabled", aws.ToString(endpoint.ClientVpnEndpointId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(endpoint.ClientVpnEndpointId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// isConfidentialInstance verifica se uma instância é confidencial via tags
func isConfidentialInstance(instance types.Instance) bool {
	if instance.Tags == nil {
		return false
	}
	for _, tag := range instance.Tags {
		key := strings.ToLower(aws.ToString(tag.Key))
		value := strings.ToLower(aws.ToString(tag.Value))
		if strings.Contains(key, "enclave") || strings.Contains(value, "confidential") {
			return true
		}
	}
	return false
}

// ConfidentialWorkloadHostImdsv2NotEnforced - verifica IMDSv2 em hosts confidenciais
type ConfidentialWorkloadHostImdsv2NotEnforced struct {
	metadata models.CheckMetadata
}

func NewConfidentialWorkloadHostImdsv2NotEnforced() *ConfidentialWorkloadHostImdsv2NotEnforced {
	return &ConfidentialWorkloadHostImdsv2NotEnforced{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_confidential_workload_host_imdsv2_not_enforced",
			CheckTitle: "Ensure confidential workload hosts enforce IMDSv2",
			Description: "Confidential workload hosts should enforce IMDSv2",
			Severity: "high", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Enforce IMDSv2 on confidential workload hosts",
			Categories: []string{"ec2", "confidential", "imdsv2"},
		},
	}
}

func (c *ConfidentialWorkloadHostImdsv2NotEnforced) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfidentialWorkloadHostImdsv2NotEnforced) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if instance.State.Name != types.InstanceStateNameRunning {
				continue
			}
			if !isConfidentialInstance(instance) {
				continue
			}
			status := models.StatusFail
			msg := fmt.Sprintf("Confidential host %s does not enforce IMDSv2", aws.ToString(instance.InstanceId))
			if instance.MetadataOptions != nil && instance.MetadataOptions.HttpTokens == types.HttpTokensStateRequired {
				status = models.StatusPass
				msg = fmt.Sprintf("Confidential host %s enforces IMDSv2", aws.ToString(instance.InstanceId))
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ec2",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ConfidentialWorkloadHostNotRunning - verifica hosts confidenciais rodando
type ConfidentialWorkloadHostNotRunning struct {
	metadata models.CheckMetadata
}

func NewConfidentialWorkloadHostNotRunning() *ConfidentialWorkloadHostNotRunning {
	return &ConfidentialWorkloadHostNotRunning{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_confidential_workload_host_not_running",
			CheckTitle: "Ensure confidential workload hosts are running",
			Description: "Confidential workload hosts should be in running state",
			Severity: "medium", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Start stopped confidential workload hosts",
			Categories: []string{"ec2", "confidential"},
		},
	}
}

func (c *ConfidentialWorkloadHostNotRunning) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfidentialWorkloadHostNotRunning) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if !isConfidentialInstance(instance) {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("Confidential host %s is running", aws.ToString(instance.InstanceId))
			if instance.State.Name != types.InstanceStateNameRunning {
				status = models.StatusFail
				msg = fmt.Sprintf("Confidential host %s is not running (%s)", aws.ToString(instance.InstanceId), instance.State.Name)
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ec2",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ConfidentialWorkloadHostPublicIp - verifica IP público em hosts confidenciais
type ConfidentialWorkloadHostPublicIp struct {
	metadata models.CheckMetadata
}

func NewConfidentialWorkloadHostPublicIp() *ConfidentialWorkloadHostPublicIp {
	return &ConfidentialWorkloadHostPublicIp{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_confidential_workload_host_public_ip",
			CheckTitle: "Ensure confidential workload hosts do not have public IP",
			Description: "Confidential workload hosts should not have public IP addresses",
			Severity: "medium", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Remove public IP from confidential workload hosts",
			Categories: []string{"ec2", "confidential", "networking"},
		},
	}
}

func (c *ConfidentialWorkloadHostPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfidentialWorkloadHostPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if !isConfidentialInstance(instance) {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("Confidential host %s has no public IP", aws.ToString(instance.InstanceId))
			if instance.PublicIpAddress != nil && aws.ToString(instance.PublicIpAddress) != "" {
				status = models.StatusFail
				msg = fmt.Sprintf("Confidential host %s has public IP", aws.ToString(instance.InstanceId))
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ec2",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ConfidentialWorkloadHostUnrestrictedIngress - verifica ingress irrestrito
type ConfidentialWorkloadHostUnrestrictedIngress struct {
	metadata models.CheckMetadata
}

func NewConfidentialWorkloadHostUnrestrictedIngress() *ConfidentialWorkloadHostUnrestrictedIngress {
	return &ConfidentialWorkloadHostUnrestrictedIngress{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_confidential_workload_host_unrestricted_ingress",
			CheckTitle: "Ensure confidential workload hosts have restricted ingress",
			Description: "Confidential workload hosts should not expose non-standard ports",
			Severity: "high", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Restrict ingress on confidential workload hosts",
			Categories: []string{"ec2", "confidential", "networking"},
		},
	}
}

func (c *ConfidentialWorkloadHostUnrestrictedIngress) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfidentialWorkloadHostUnrestrictedIngress) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if !isConfidentialInstance(instance) {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("Confidential host %s has restricted ingress", aws.ToString(instance.InstanceId))
			for _, sgID := range instance.SecurityGroups {
				sgResult, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{aws.ToString(sgID.GroupId)},
				})
				if err == nil {
					for _, sg := range sgResult.SecurityGroups {
						for _, perm := range sg.IpPermissions {
							for _, ipRange := range perm.IpRanges {
								if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
									if perm.FromPort != nil && perm.ToPort != nil {
										from := aws.ToInt32(perm.FromPort)
										to := aws.ToInt32(perm.ToPort)
										if from != 443 && to != 443 && from != 22 && to != 22 {
											status = models.StatusFail
											msg = fmt.Sprintf("Confidential host %s exposes non-standard ports", aws.ToString(instance.InstanceId))
										}
									}
								}
							}
						}
					}
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ec2",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ConfidentialWorkloadHostVsockProxyExposed - verifica vsock proxy
type ConfidentialWorkloadHostVsockProxyExposed struct {
	metadata models.CheckMetadata
}

func NewConfidentialWorkloadHostVsockProxyExposed() *ConfidentialWorkloadHostVsockProxyExposed {
	return &ConfidentialWorkloadHostVsockProxyExposed{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_confidential_workload_host_vsock_proxy_exposed",
			CheckTitle: "Ensure confidential workload hosts do not expose vsock proxy",
			Description: "Confidential workload hosts should not expose vsock-proxy ports",
			Severity: "medium", ServiceName: "ec2", ResourceType: "Instance",
			RemediationText: "Restrict vsock-proxy port access",
			Categories: []string{"ec2", "confidential", "vsock"},
		},
	}
}

func (c *ConfidentialWorkloadHostVsockProxyExposed) Metadata() models.CheckMetadata { return c.metadata }

func (c *ConfidentialWorkloadHostVsockProxyExposed) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, err
	}

	vsockPorts := []int32{8000, 8001, 8002, 8003, 8004, 8005}
	findings := []models.Finding{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			if !isConfidentialInstance(instance) {
				continue
			}
			status := models.StatusPass
			msg := fmt.Sprintf("Confidential host %s does not expose vsock-proxy", aws.ToString(instance.InstanceId))
			for _, sgID := range instance.SecurityGroups {
				sgResult, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
					GroupIds: []string{aws.ToString(sgID.GroupId)},
				})
				if err == nil {
					for _, sg := range sgResult.SecurityGroups {
						for _, perm := range sg.IpPermissions {
							for _, ipRange := range perm.IpRanges {
								if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
									for _, port := range vsockPorts {
										if perm.FromPort != nil && perm.ToPort != nil {
											from := aws.ToInt32(perm.FromPort)
											to := aws.ToInt32(perm.ToPort)
											if port >= from && port <= to {
												status = models.StatusFail
												msg = fmt.Sprintf("Confidential host %s exposes vsock-proxy port %d", aws.ToString(instance.InstanceId), port)
											}
										}
									}
								}
							}
						}
					}
				}
			}
			findings = append(findings, models.Finding{
				ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
				Description: c.metadata.Description, Severity: c.metadata.Severity,
				Status: status, StatusExtended: msg,
				ResourceID: aws.ToString(instance.InstanceId), Provider: "aws", Service: "ec2",
				FoundAt: time.Now().UTC(),
			})
		}
	}
	return findings, nil
}

// ElasticIpShodan - verifica Elastic IP no Shodan
type ElasticIpShodan struct {
	metadata models.CheckMetadata
}

func NewElasticIpShodan() *ElasticIpShodan {
	return &ElasticIpShodan{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_elastic_ip_shodan",
			CheckTitle: "Ensure Elastic IP is not listed in Shodan",
			Description: "Elastic IPs should not be listed in Shodan",
			Severity: "medium", ServiceName: "ec2", ResourceType: "ElasticIP",
			RemediationText: "Investigate Elastic IPs listed in Shodan",
			Categories: []string{"ec2", "eip", "shodan"},
		},
	}
}

func (c *ElasticIpShodan) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticIpShodan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, addr := range result.Addresses {
		status := models.StatusPass
		msg := fmt.Sprintf("Elastic IP %s not listed in Shodan", aws.ToString(addr.PublicIp))
		if addr.Tags != nil {
			for _, tag := range addr.Tags {
				if strings.Contains(strings.ToLower(aws.ToString(tag.Key)), "shodan") {
					status = models.StatusFail
					msg = fmt.Sprintf("Elastic IP %s may be listed in Shodan", aws.ToString(addr.PublicIp))
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(addr.PublicIp), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// TransitGatewayAutoAcceptVpcAttachments - verifica auto-accept do Transit Gateway
type TransitGatewayAutoAcceptVpcAttachments struct {
	metadata models.CheckMetadata
}

func NewTransitGatewayAutoAcceptVpcAttachments() *TransitGatewayAutoAcceptVpcAttachments {
	return &TransitGatewayAutoAcceptVpcAttachments{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_transitgateway_auto_accept_vpc_attachments",
			CheckTitle: "Ensure Transit Gateway does not auto-accept VPC attachments",
			Description: "Transit Gateway should not auto-accept VPC attachments",
			Severity: "medium", ServiceName: "ec2", ResourceType: "TransitGateway",
			RemediationText: "Disable auto-accept for Transit Gateway VPC attachments",
			Categories: []string{"ec2", "transit-gateway", "networking"},
		},
	}
}

func (c *TransitGatewayAutoAcceptVpcAttachments) Metadata() models.CheckMetadata { return c.metadata }

func (c *TransitGatewayAutoAcceptVpcAttachments) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, tgw := range result.TransitGateways {
		status := models.StatusPass
		msg := fmt.Sprintf("Transit Gateway %s does not auto-accept attachments", aws.ToString(tgw.TransitGatewayId))
		if tgw.Options != nil && tgw.Options.AutoAcceptSharedAttachments == types.AutoAcceptSharedAttachmentsValueEnable {
			status = models.StatusFail
			msg = fmt.Sprintf("Transit Gateway %s auto-accepts attachments", aws.ToString(tgw.TransitGatewayId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(tgw.TransitGatewayId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// SecurityGroupAllowIngressFromInternetToAnyPortFromIp - verifica SG com porta de IP específico
type SecurityGroupAllowIngressFromInternetToAnyPortFromIp struct {
	metadata models.CheckMetadata
}

func NewSecurityGroupAllowIngressFromInternetToAnyPortFromIp() *SecurityGroupAllowIngressFromInternetToAnyPortFromIp {
	return &SecurityGroupAllowIngressFromInternetToAnyPortFromIp{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip",
			CheckTitle: "Ensure security group does not allow any port from specific IP",
			Description: "Security groups should not allow any port from specific IPs",
			Severity: "high", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict security group rules",
			Categories: []string{"ec2", "security-group", "networking"},
		},
	}
}

func (c *SecurityGroupAllowIngressFromInternetToAnyPortFromIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *SecurityGroupAllowIngressFromInternetToAnyPortFromIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, sg := range result.SecurityGroups {
		hasWideOpen := false
		for _, perm := range sg.IpPermissions {
			for _, ipRange := range perm.IpRanges {
				cidr := aws.ToString(ipRange.CidrIp)
				if cidr != "0.0.0.0/0" && perm.FromPort == nil && perm.ToPort == nil {
					hasWideOpen = true
					break
				}
			}
			if hasWideOpen {
				break
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("Security group %s is compliant", aws.ToString(sg.GroupName))
		if hasWideOpen {
			status = models.StatusFail
			msg = fmt.Sprintf("Security group %s allows all ports from specific IP", aws.ToString(sg.GroupName))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(sg.GroupId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
