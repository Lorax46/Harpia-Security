package network

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Lorax46/TOTVS-Horus/internal/scanner/models"
)

type networkProvider interface {
	SecurityGroupsClient(ctx context.Context) (*armnetwork.SecurityGroupsClient, error)
	PublicIPAddressesClient(ctx context.Context) (*armnetwork.PublicIPAddressesClient, error)
}

// ==================== NSG SSH Restricted ====================

type NSGSSHRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewNSGSSHRestrictedCheck() *NSGSSHRestrictedCheck {
	return &NSGSSHRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "network_nsg_ssh_restricted",
			CheckTitle:      "NSGs should restrict SSH access from the internet",
			ServiceName:     "network",
			Severity:        "critical",
			ResourceType:    "SecurityGroup",
			ResourceGroup:   "Network",
			Description:     "NSGs should not allow SSH (port 22) access from the internet",
			Risk:            "Open SSH access from the internet can lead to unauthorized access",
			RemediationText: "Restrict SSH access to specific IP ranges",
			Categories:      []string{"network", "security"},
		},
	}
}

func (c *NSGSSHRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NSGSSHRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(networkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa networkProvider")
	}

	client, err := p.SecurityGroupsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar NSGs: %w", err)
		}
		for _, nsg := range page.Value {
			if nsg == nil || nsg.Name == nil {
				continue
			}
			sshOpen := false
			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule == nil || rule.Properties == nil {
						continue
					}
					if rule.Properties.DestinationPortRange != nil &&
						*rule.Properties.DestinationPortRange == "22" &&
						rule.Properties.SourceAddressPrefix != nil &&
						(*rule.Properties.SourceAddressPrefix == "*" || *rule.Properties.SourceAddressPrefix == "0.0.0.0/0") &&
						rule.Properties.Access != nil &&
						*rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
						sshOpen = true
						break
					}
				}
			}
			status := models.StatusPass
			ext := fmt.Sprintf("NSG %s does not allow SSH from internet", *nsg.Name)
			if sshOpen {
				status = models.StatusFail
				ext = fmt.Sprintf("NSG %s allows SSH from internet", *nsg.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "network",
				ResourceID:      *nsg.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== NSG RDP Restricted ====================

type NSGRDPRestrictedCheck struct {
	metadata models.CheckMetadata
}

func NewNSGRDPRestrictedCheck() *NSGRDPRestrictedCheck {
	return &NSGRDPRestrictedCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "network_nsg_rdp_restricted",
			CheckTitle:      "NSGs should restrict RDP access from the internet",
			ServiceName:     "network",
			Severity:        "critical",
			ResourceType:    "SecurityGroup",
			ResourceGroup:   "Network",
			Description:     "NSGs should not allow RDP (port 3389) access from the internet",
			Risk:            "Open RDP access from the internet can lead to unauthorized access",
			RemediationText: "Restrict RDP access to specific IP ranges",
			Categories:      []string{"network", "security"},
		},
	}
}

func (c *NSGRDPRestrictedCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *NSGRDPRestrictedCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(networkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa networkProvider")
	}

	client, err := p.SecurityGroupsClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar NSGs: %w", err)
		}
		for _, nsg := range page.Value {
			if nsg == nil || nsg.Name == nil {
				continue
			}
			rdpOpen := false
			if nsg.Properties != nil && nsg.Properties.SecurityRules != nil {
				for _, rule := range nsg.Properties.SecurityRules {
					if rule == nil || rule.Properties == nil {
						continue
					}
					if rule.Properties.DestinationPortRange != nil &&
						*rule.Properties.DestinationPortRange == "3389" &&
						rule.Properties.SourceAddressPrefix != nil &&
						(*rule.Properties.SourceAddressPrefix == "*" || *rule.Properties.SourceAddressPrefix == "0.0.0.0/0") &&
						rule.Properties.Access != nil &&
						*rule.Properties.Access == armnetwork.SecurityRuleAccessAllow {
						rdpOpen = true
						break
					}
				}
			}
			status := models.StatusPass
			ext := fmt.Sprintf("NSG %s does not allow RDP from internet", *nsg.Name)
			if rdpOpen {
				status = models.StatusFail
				ext = fmt.Sprintf("NSG %s allows RDP from internet", *nsg.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "network",
				ResourceID:      *nsg.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}

// ==================== Public IP Secured ====================

type PublicIPSecuredCheck struct {
	metadata models.CheckMetadata
}

func NewPublicIPSecuredCheck() *PublicIPSecuredCheck {
	return &PublicIPSecuredCheck{
		metadata: models.CheckMetadata{
			Provider:        "azure",
			CheckID:         "network_public_ip_secured",
			CheckTitle:      "Public IPs should be associated with resources",
			ServiceName:     "network",
			Severity:        "high",
			ResourceType:    "PublicIPAddress",
			ResourceGroup:   "Network",
			Description:     "Public IP addresses should be associated with resources (not orphaned) and secured",
			Risk:            "Orphaned public IPs can be security risks and incur unnecessary costs",
			RemediationText: "Associate public IPs with resources or delete unused ones",
			Categories:      []string{"network", "security"},
		},
	}
}

func (c *PublicIPSecuredCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *PublicIPSecuredCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	p, ok := provider.(networkProvider)
	if !ok {
		return nil, fmt.Errorf("provider não implementa networkProvider")
	}

	client, err := p.PublicIPAddressesClient(ctx)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("falha ao listar IPs públicos: %w", err)
		}
		for _, ip := range page.Value {
			if ip == nil || ip.Name == nil {
				continue
			}
			orphaned := ip.Properties != nil && ip.Properties.IPConfiguration == nil
			status := models.StatusPass
			ext := fmt.Sprintf("Public IP %s is associated with a resource", *ip.Name)
			if orphaned {
				status = models.StatusFail
				ext = fmt.Sprintf("Public IP %s is orphaned (not associated)", *ip.Name)
			}
			findings = append(findings, models.Finding{
				ID:              c.metadata.CheckID,
				Title:           c.metadata.CheckTitle,
				Description:     c.metadata.Description,
				Severity:        c.metadata.Severity,
				Status:          status,
				StatusExtended:  ext,
				Provider:        "azure",
				Service:         "network",
				ResourceID:      *ip.Name,
				Remediation:     c.metadata.RemediationText,
				Categories:      c.metadata.Categories,
				FoundAt:         time.Now(),
			})
		}
	}
	return findings, nil
}
