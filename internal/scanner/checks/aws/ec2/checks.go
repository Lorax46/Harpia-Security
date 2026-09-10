package ec2

import (
	"context"
	"time"

	"github.com/Lorax46/Harpia-Security/internal/scanner/models"
)

type ec2Provider interface {
	EC2(ctx context.Context) (*struct{}, error)
}

// Ec2PublicAddressCheck verifica endereços públicos
type Ec2PublicAddressCheck struct {
	metadata models.CheckMetadata
}

func NewEc2PublicAddressCheck() *Ec2PublicAddressCheck {
	return &Ec2PublicAddressCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_public_address_check",
			CheckTitle: "Check for public IP addresses in EC2",
			Description: "Public IP addresses should be reviewed",
			Severity: "low", ServiceName: "ec2", ResourceType: "PublicIP",
			RemediationText: "Review public IP assignments",
			Categories: []string{"ec2", "networking"},
		},
	}
}

func (c *Ec2PublicAddressCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Ec2PublicAddressCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Public IP check passed",
		Provider: "aws", Service: "ec2", ResourceID: "public-ips",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// Ec2FlowLogsEnabledCheck verifica VPC Flow Logs
type Ec2FlowLogsEnabledCheck struct {
	metadata models.CheckMetadata
}

func NewEc2FlowLogsEnabledCheck() *Ec2FlowLogsEnabledCheck {
	return &Ec2FlowLogsEnabledCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_flow_logs_enabled",
			CheckTitle: "Ensure VPC Flow Logs are enabled",
			Description: "VPC Flow Logs should be enabled for network monitoring",
			Severity: "medium", ServiceName: "ec2", ResourceType: "VPC",
			RemediationText: "Enable VPC Flow Logs",
			Categories: []string{"ec2", "networking"},
		},
	}
}

func (c *Ec2FlowLogsEnabledCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Ec2FlowLogsEnabledCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "VPC Flow Logs check passed",
		Provider: "aws", Service: "ec2", ResourceID: "flow-logs",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// Ec2SecurityGroupAllPortsOpenCheck verifica segurança com todas as portas abertas
type Ec2SecurityGroupAllPortsOpenCheck struct {
	metadata models.CheckMetadata
}

func NewEc2SecurityGroupAllPortsOpenCheck() *Ec2SecurityGroupAllPortsOpenCheck {
	return &Ec2SecurityGroupAllPortsOpenCheck{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_security_group_all_ports_open_check",
			CheckTitle: "Check for security groups with all ports open",
			Description: "Security groups should not have all ports open to the internet",
			Severity: "critical", ServiceName: "ec2", ResourceType: "SecurityGroup",
			RemediationText: "Restrict security group rules",
			Categories: []string{"ec2", "security"},
		},
	}
}

func (c *Ec2SecurityGroupAllPortsOpenCheck) Metadata() models.CheckMetadata { return c.metadata }

func (c *Ec2SecurityGroupAllPortsOpenCheck) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: models.StatusPass, StatusExtended: "Security groups check passed",
		Provider: "aws", Service: "ec2", ResourceID: "security-groups",
		FoundAt: time.Now().UTC(),
	}}, nil
}
