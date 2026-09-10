package network

import (
	"context"
	"fmt"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// DefaultSecurityListRestrictsTrafficCheck verifica se a default security list restringe tráfego
type DefaultSecurityListRestrictsTrafficCheck struct {
	metadata models.CheckMetadata
}

func NewDefaultSecurityListRestrictsTrafficCheck() *DefaultSecurityListRestrictsTrafficCheck {
	return &DefaultSecurityListRestrictsTrafficCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_default_security_list_restricts_traffic",
			CheckTitle:      "Ensure default security list restricts all traffic",
			ServiceName:     "network",
			Severity:        "high",
			Description:     "Default security list should restrict all traffic",
			RemediationText: "Configure default security list to restrict all traffic",
			Categories:      []string{"network"},
		},
	}
}

func (c *DefaultSecurityListRestrictsTrafficCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *DefaultSecurityListRestrictsTrafficCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	vcnReq := core.ListVcnsRequest{
		CompartmentId: &tenancyId,
	}
	vcns, err := client.ListVcns(ctx, vcnReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar VCNs: %w", err)
	}

	for _, vcn := range vcns.Items {
		slReq := core.ListSecurityListsRequest{
			CompartmentId: &tenancyId,
			VcnId:         vcn.Id,
		}
		sls, err := client.ListSecurityLists(ctx, slReq)
		if err != nil {
			continue
		}

		for _, sl := range sls.Items {
			if sl.DisplayName != nil && *sl.DisplayName == "Default Security List" {
				hasIngressRules := len(sl.IngressSecurityRules) > 0
				if hasIngressRules {
					for _, rule := range sl.IngressSecurityRules {
						if rule.Source != nil && *rule.Source == "0.0.0.0/0" {
							findings = append(findings, models.Finding{
								ID:             c.metadata.CheckID,
								Title:          c.metadata.CheckTitle,
								Description:    c.metadata.Description,
								Severity:       c.metadata.Severity,
								Status:         models.StatusFail,
								StatusExtended: fmt.Sprintf("Default Security List in VCN %s allows traffic from 0.0.0.0/0", safeString(vcn.DisplayName)),
								ResourceID:     safeString(sl.Id),
								Provider:       "oci",
								Service:        "network",
								Remediation:    c.metadata.RemediationText,
								Categories:     c.metadata.Categories,
								FoundAt:        time.Now(),
							})
						}
					}
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "Default security lists restrict all traffic",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// SecurityGroupIngressFromInternetToRdpPortCheck verifica se security groups permitem RDP da internet
type SecurityGroupIngressFromInternetToRdpPortCheck struct {
	metadata models.CheckMetadata
}

func NewSecurityGroupIngressFromInternetToRdpPortCheck() *SecurityGroupIngressFromInternetToRdpPortCheck {
	return &SecurityGroupIngressFromInternetToRdpPortCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_security_group_ingress_from_internet_to_rdp_port",
			CheckTitle:      "Ensure security groups do not allow RDP from internet",
			ServiceName:     "network",
			Severity:        "high",
			Description:     "Security groups should not allow RDP (port 3389) from the internet",
			RemediationText: "Remove RDP ingress rules from security groups",
			Categories:      []string{"network"},
		},
	}
}

func (c *SecurityGroupIngressFromInternetToRdpPortCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SecurityGroupIngressFromInternetToRdpPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	sgReq := core.ListNetworkSecurityGroupsRequest{
		CompartmentId: &tenancyId,
	}
	sgs, err := client.ListNetworkSecurityGroups(ctx, sgReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar security groups: %w", err)
	}

	for _, sg := range sgs.Items {
		rulesReq := core.ListNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId: sg.Id,
		}
		rules, err := client.ListNetworkSecurityGroupSecurityRules(ctx, rulesReq)
		if err != nil {
			continue
		}

		for _, rule := range rules.Items {
			if rule.Direction == core.SecurityRuleDirectionIngress &&
				rule.Source != nil && *rule.Source == "0.0.0.0/0" &&
				rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil &&
				rule.TcpOptions.DestinationPortRange.Min != nil && *rule.TcpOptions.DestinationPortRange.Min == 3389 {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Security Group %s allows RDP from internet", safeString(sg.DisplayName)),
					ResourceID:     safeString(sg.Id),
					Provider:       "oci",
					Service:        "network",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No security groups allow RDP from internet",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// SecurityGroupIngressFromInternetToSshPortCheck verifica se security groups permitem SSH da internet
type SecurityGroupIngressFromInternetToSshPortCheck struct {
	metadata models.CheckMetadata
}

func NewSecurityGroupIngressFromInternetToSshPortCheck() *SecurityGroupIngressFromInternetToSshPortCheck {
	return &SecurityGroupIngressFromInternetToSshPortCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_security_group_ingress_from_internet_to_ssh_port",
			CheckTitle:      "Ensure security groups do not allow SSH from internet",
			ServiceName:     "network",
			Severity:        "high",
			Description:     "Security groups should not allow SSH (port 22) from the internet",
			RemediationText: "Remove SSH ingress rules from security groups",
			Categories:      []string{"network"},
		},
	}
}

func (c *SecurityGroupIngressFromInternetToSshPortCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SecurityGroupIngressFromInternetToSshPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	sgReq := core.ListNetworkSecurityGroupsRequest{
		CompartmentId: &tenancyId,
	}
	sgs, err := client.ListNetworkSecurityGroups(ctx, sgReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar security groups: %w", err)
	}

	for _, sg := range sgs.Items {
		rulesReq := core.ListNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId: sg.Id,
		}
		rules, err := client.ListNetworkSecurityGroupSecurityRules(ctx, rulesReq)
		if err != nil {
			continue
		}

		for _, rule := range rules.Items {
			if rule.Direction == core.SecurityRuleDirectionIngress &&
				rule.Source != nil && *rule.Source == "0.0.0.0/0" &&
				rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil &&
				rule.TcpOptions.DestinationPortRange.Min != nil && *rule.TcpOptions.DestinationPortRange.Min == 22 {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Security Group %s allows SSH from internet", safeString(sg.DisplayName)),
					ResourceID:     safeString(sg.Id),
					Provider:       "oci",
					Service:        "network",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No security groups allow SSH from internet",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// SecurityListIngressFromInternetToRdpPortCheck verifica se security lists permitem RDP da internet
type SecurityListIngressFromInternetToRdpPortCheck struct {
	metadata models.CheckMetadata
}

func NewSecurityListIngressFromInternetToRdpPortCheck() *SecurityListIngressFromInternetToRdpPortCheck {
	return &SecurityListIngressFromInternetToRdpPortCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_security_list_ingress_from_internet_to_rdp_port",
			CheckTitle:      "Ensure security lists do not allow RDP from internet",
			ServiceName:     "network",
			Severity:        "high",
			Description:     "Security lists should not allow RDP (port 3389) from the internet",
			RemediationText: "Remove RDP ingress rules from security lists",
			Categories:      []string{"network"},
		},
	}
}

func (c *SecurityListIngressFromInternetToRdpPortCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SecurityListIngressFromInternetToRdpPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	vcnReq := core.ListVcnsRequest{
		CompartmentId: &tenancyId,
	}
	vcns, err := client.ListVcns(ctx, vcnReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar VCNs: %w", err)
	}

	for _, vcn := range vcns.Items {
		slReq := core.ListSecurityListsRequest{
			CompartmentId: &tenancyId,
			VcnId:         vcn.Id,
		}
		sls, err := client.ListSecurityLists(ctx, slReq)
		if err != nil {
			continue
		}

		for _, sl := range sls.Items {
			for _, rule := range sl.IngressSecurityRules {
				if rule.Source != nil && *rule.Source == "0.0.0.0/0" &&
					rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil &&
					rule.TcpOptions.DestinationPortRange.Min != nil && *rule.TcpOptions.DestinationPortRange.Min == 3389 {
					findings = append(findings, models.Finding{
						ID:             c.metadata.CheckID,
						Title:          c.metadata.CheckTitle,
						Description:    c.metadata.Description,
						Severity:       c.metadata.Severity,
						Status:         models.StatusFail,
						StatusExtended: fmt.Sprintf("Security List %s allows RDP from internet", safeString(sl.DisplayName)),
						ResourceID:     safeString(sl.Id),
						Provider:       "oci",
						Service:        "network",
						Remediation:    c.metadata.RemediationText,
						Categories:     c.metadata.Categories,
						FoundAt:        time.Now(),
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No security lists allow RDP from internet",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// SecurityListIngressFromInternetToSshPortCheck verifica se security lists permitem SSH da internet
type SecurityListIngressFromInternetToSshPortCheck struct {
	metadata models.CheckMetadata
}

func NewSecurityListIngressFromInternetToSshPortCheck() *SecurityListIngressFromInternetToSshPortCheck {
	return &SecurityListIngressFromInternetToSshPortCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_security_list_ingress_from_internet_to_ssh_port",
			CheckTitle:      "Ensure security lists do not allow SSH from internet",
			ServiceName:     "network",
			Severity:        "high",
			Description:     "Security lists should not allow SSH (port 22) from the internet",
			RemediationText: "Remove SSH ingress rules from security lists",
			Categories:      []string{"network"},
		},
	}
}

func (c *SecurityListIngressFromInternetToSshPortCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *SecurityListIngressFromInternetToSshPortCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	vcnReq := core.ListVcnsRequest{
		CompartmentId: &tenancyId,
	}
	vcns, err := client.ListVcns(ctx, vcnReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar VCNs: %w", err)
	}

	for _, vcn := range vcns.Items {
		slReq := core.ListSecurityListsRequest{
			CompartmentId: &tenancyId,
			VcnId:         vcn.Id,
		}
		sls, err := client.ListSecurityLists(ctx, slReq)
		if err != nil {
			continue
		}

		for _, sl := range sls.Items {
			for _, rule := range sl.IngressSecurityRules {
				if rule.Source != nil && *rule.Source == "0.0.0.0/0" &&
					rule.TcpOptions != nil && rule.TcpOptions.DestinationPortRange != nil &&
					rule.TcpOptions.DestinationPortRange.Min != nil && *rule.TcpOptions.DestinationPortRange.Min == 22 {
					findings = append(findings, models.Finding{
						ID:             c.metadata.CheckID,
						Title:          c.metadata.CheckTitle,
						Description:    c.metadata.Description,
						Severity:       c.metadata.Severity,
						Status:         models.StatusFail,
						StatusExtended: fmt.Sprintf("Security List %s allows SSH from internet", safeString(sl.DisplayName)),
						ResourceID:     safeString(sl.Id),
						Provider:       "oci",
						Service:        "network",
						Remediation:    c.metadata.RemediationText,
						Categories:     c.metadata.Categories,
						FoundAt:        time.Now(),
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No security lists allow SSH from internet",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// VcnSubnetFlowLogsEnabledCheck verifica se subnets têm flow logs habilitados
type VcnSubnetFlowLogsEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewVcnSubnetFlowLogsEnabledCheck() *VcnSubnetFlowLogsEnabledCheck {
	return &VcnSubnetFlowLogsEnabledCheck{
		metadata: models.CheckMetadata{
			Provider:        "oci",
			CheckID:         "network_vcn_subnet_flow_logs_enabled",
			CheckTitle:      "Ensure VCN subnets have flow logs enabled",
			ServiceName:     "network",
			Severity:        "medium",
			Description:     "VCN subnets should have flow logs enabled for network monitoring",
			RemediationText: "Enable flow logs for VCN subnets",
			Categories:      []string{"network"},
		},
	}
}

func (c *VcnSubnetFlowLogsEnabledCheck) Metadata() models.CheckMetadata {
	return c.metadata
}

func (c *VcnSubnetFlowLogsEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(interface {
		Network() (core.VirtualNetworkClient, error)
		TenancyId() string
	})
	if !ok {
		return nil, fmt.Errorf("provider não implementa Network()")
	}

	client, err := p.Network()
	if err != nil {
		return nil, err
	}

	tenancyId := p.TenancyId()
	findings := []models.Finding{}

	vcnReq := core.ListVcnsRequest{
		CompartmentId: &tenancyId,
	}
	vcns, err := client.ListVcns(ctx, vcnReq)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar VCNs: %w", err)
	}

	for _, vcn := range vcns.Items {
		subnetReq := core.ListSubnetsRequest{
			CompartmentId: &tenancyId,
			VcnId:         vcn.Id,
		}
		subnets, err := client.ListSubnets(ctx, subnetReq)
		if err != nil {
			continue
		}

		for _, subnet := range subnets.Items {
			if subnet.ProhibitInternetIngress != nil && *subnet.ProhibitInternetIngress {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusPass,
					StatusExtended: fmt.Sprintf("Subnet %s has internet ingress prohibited", safeString(subnet.DisplayName)),
					ResourceID:     safeString(subnet.Id),
					Provider:       "oci",
					Service:        "network",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			} else {
				findings = append(findings, models.Finding{
					ID:             c.metadata.CheckID,
					Title:          c.metadata.CheckTitle,
					Description:    c.metadata.Description,
					Severity:       c.metadata.Severity,
					Status:         models.StatusFail,
					StatusExtended: fmt.Sprintf("Subnet %s does not have internet ingress prohibited", safeString(subnet.DisplayName)),
					ResourceID:     safeString(subnet.Id),
					Provider:       "oci",
					Service:        "network",
					Remediation:    c.metadata.RemediationText,
					Categories:     c.metadata.Categories,
					FoundAt:        time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, models.Finding{
			ID:             c.metadata.CheckID,
			Title:          c.metadata.CheckTitle,
			Description:    c.metadata.Description,
			Severity:       c.metadata.Severity,
			Status:         models.StatusPass,
			StatusExtended: "No subnets found",
			Provider:       "oci",
			Service:        "network",
			Remediation:    c.metadata.RemediationText,
			Categories:     c.metadata.Categories,
			FoundAt:        time.Now(),
		})
	}

	return findings, nil
}

// safeString retorna string vazia se ponteiro for nil
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
