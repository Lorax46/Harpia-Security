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

// EbsVolumeEncryption - verifica criptografia de volumes EBS
type EbsVolumeEncryption struct {
	metadata models.CheckMetadata
}

func NewEbsVolumeEncryption() *EbsVolumeEncryption {
	return &EbsVolumeEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_encryption",
			CheckTitle: "Ensure EBS volumes are encrypted",
			Description: "EBS volumes should be encrypted at rest",
			Severity: "high", ServiceName: "ec2", ResourceType: "Volume",
			RemediationText: "Enable encryption for EBS volumes",
			Categories: []string{"ec2", "ebs", "encryption"},
		},
	}
}

func (c *EbsVolumeEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsVolumeEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, vol := range result.Volumes {
		status := models.StatusPass
		msg := fmt.Sprintf("Volume %s is encrypted", aws.ToString(vol.VolumeId))
		if !aws.ToBool(vol.Encrypted) {
			status = models.StatusFail
			msg = fmt.Sprintf("Volume %s is not encrypted", aws.ToString(vol.VolumeId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(vol.VolumeId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// EbsDefaultEncryption - verifica criptografia padrão de EBS
type EbsDefaultEncryption struct {
	metadata models.CheckMetadata
}

func NewEbsDefaultEncryption() *EbsDefaultEncryption {
	return &EbsDefaultEncryption{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_default_encryption",
			CheckTitle: "Ensure EBS default encryption is enabled",
			Description: "EBS encryption by default should be enabled",
			Severity: "high", ServiceName: "ec2", ResourceType: "Account",
			RemediationText: "Enable EBS encryption by default",
			Categories: []string{"ec2", "ebs", "encryption"},
		},
	}
}

func (c *EbsDefaultEncryption) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsDefaultEncryption) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "EBS encryption by default is disabled"
	if result.EbsEncryptionByDefault != nil && *result.EbsEncryptionByDefault {
		status = models.StatusPass
		msg = "EBS encryption by default is enabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "ec2", ResourceID: "ebs-default-encryption",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EbsPublicSnapshot - verifica snapshots públicos
type EbsPublicSnapshot struct {
	metadata models.CheckMetadata
}

func NewEbsPublicSnapshot() *EbsPublicSnapshot {
	return &EbsPublicSnapshot{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_public_snapshot",
			CheckTitle: "Ensure EBS snapshots are not public",
			Description: "EBS snapshots should not be publicly accessible",
			Severity: "critical", ServiceName: "ec2", ResourceType: "Snapshot",
			RemediationText: "Remove public access from EBS snapshots",
			Categories: []string{"ec2", "ebs", "snapshot"},
		},
	}
}

func (c *EbsPublicSnapshot) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsPublicSnapshot) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, snap := range result.Snapshots {
		isPublic := false
		// Verificar se o snapshot é público
		if snap.State == types.SnapshotStateCompleted {
			// Snapshots são públicos se tiverem permissão de grupo 'all'
			details, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: snap.SnapshotId,
				Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
			})
			if err == nil {
				for _, perm := range details.CreateVolumePermissions {
					if perm.Group == types.PermissionGroupAll {
						isPublic = true
						break
					}
				}
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("Snapshot %s is not public", aws.ToString(snap.SnapshotId))
		if isPublic {
			status = models.StatusFail
			msg = fmt.Sprintf("Snapshot %s is public", aws.ToString(snap.SnapshotId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(snap.SnapshotId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// EbsSnapshotsEncrypted - verifica criptografia de snapshots
type EbsSnapshotsEncrypted struct {
	metadata models.CheckMetadata
}

func NewEbsSnapshotsEncrypted() *EbsSnapshotsEncrypted {
	return &EbsSnapshotsEncrypted{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_snapshots_encrypted",
			CheckTitle: "Ensure EBS snapshots are encrypted",
			Description: "EBS snapshots should be encrypted",
			Severity: "high", ServiceName: "ec2", ResourceType: "Snapshot",
			RemediationText: "Enable encryption for EBS snapshots",
			Categories: []string{"ec2", "ebs", "snapshot"},
		},
	}
}

func (c *EbsSnapshotsEncrypted) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsSnapshotsEncrypted) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, snap := range result.Snapshots {
		status := models.StatusPass
		msg := fmt.Sprintf("Snapshot %s is encrypted", aws.ToString(snap.SnapshotId))
		if !aws.ToBool(snap.Encrypted) {
			status = models.StatusFail
			msg = fmt.Sprintf("Snapshot %s is not encrypted", aws.ToString(snap.SnapshotId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(snap.SnapshotId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// ElasticIpUnassigned - verifica Elastic IPs não associados
type ElasticIpUnassigned struct {
	metadata models.CheckMetadata
}

func NewElasticIpUnassigned() *ElasticIpUnassigned {
	return &ElasticIpUnassigned{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_elastic_ip_unassigned",
			CheckTitle: "Ensure Elastic IPs are associated with resources",
			Description: "Elastic IPs should be associated with an instance or network interface",
			Severity: "low", ServiceName: "ec2", ResourceType: "ElasticIP",
			RemediationText: "Release unused Elastic IPs",
			Categories: []string{"ec2", "eip", "cost"},
		},
	}
}

func (c *ElasticIpUnassigned) Metadata() models.CheckMetadata { return c.metadata }

func (c *ElasticIpUnassigned) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
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
		msg := fmt.Sprintf("Elastic IP %s is associated", aws.ToString(addr.PublicIp))
		if addr.AssociationId == nil || aws.ToString(addr.AssociationId) == "" {
			status = models.StatusFail
			msg = fmt.Sprintf("Elastic IP %s is not associated", aws.ToString(addr.PublicIp))
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

// LaunchTemplateImdsv2Required - verifica IMDSv2 em launch templates
type LaunchTemplateImdsv2Required struct {
	metadata models.CheckMetadata
}

func NewLaunchTemplateImdsv2Required() *LaunchTemplateImdsv2Required {
	return &LaunchTemplateImdsv2Required{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_imdsv2_required",
			CheckTitle: "Ensure EC2 launch templates require IMDSv2",
			Description: "Launch templates should require IMDSv2",
			Severity: "high", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Configure launch templates to require IMDSv2",
			Categories: []string{"ec2", "launch-template", "imdsv2"},
		},
	}
}

func (c *LaunchTemplateImdsv2Required) Metadata() models.CheckMetadata { return c.metadata }

func (c *LaunchTemplateImdsv2Required) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, lt := range result.LaunchTemplates {
		status := models.StatusPass
		msg := fmt.Sprintf("Launch template %s requires IMDSv2", aws.ToString(lt.LaunchTemplateName))
		// Verificar versões do template
		versions, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: lt.LaunchTemplateId,
		})
		if err == nil {
			for _, v := range versions.LaunchTemplateVersions {
				if v.LaunchTemplateData != nil && v.LaunchTemplateData.MetadataOptions != nil {
					if v.LaunchTemplateData.MetadataOptions.HttpTokens != types.LaunchTemplateHttpTokensStateRequired {
						status = models.StatusFail
						msg = fmt.Sprintf("Launch template %s does not require IMDSv2", aws.ToString(lt.LaunchTemplateName))
					}
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(lt.LaunchTemplateName), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// LaunchTemplateNoPublicIp - verifica IP público em launch templates
type LaunchTemplateNoPublicIp struct {
	metadata models.CheckMetadata
}

func NewLaunchTemplateNoPublicIp() *LaunchTemplateNoPublicIp {
	return &LaunchTemplateNoPublicIp{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_no_public_ip",
			CheckTitle: "Ensure EC2 launch templates do not assign public IPs",
			Description: "Launch templates should not assign public IPs",
			Severity: "high", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Disable public IP assignment in launch templates",
			Categories: []string{"ec2", "launch-template", "networking"},
		},
	}
}

func (c *LaunchTemplateNoPublicIp) Metadata() models.CheckMetadata { return c.metadata }

func (c *LaunchTemplateNoPublicIp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, lt := range result.LaunchTemplates {
		status := models.StatusPass
		msg := fmt.Sprintf("Launch template %s does not assign public IPs", aws.ToString(lt.LaunchTemplateName))
		versions, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: lt.LaunchTemplateId,
		})
		if err == nil {
			for _, v := range versions.LaunchTemplateVersions {
				if v.LaunchTemplateData != nil {
					for _, eni := range v.LaunchTemplateData.NetworkInterfaces {
						if eni.AssociatePublicIpAddress != nil && *eni.AssociatePublicIpAddress {
							status = models.StatusFail
							msg = fmt.Sprintf("Launch template %s assigns public IPs", aws.ToString(lt.LaunchTemplateName))
						}
					}
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(lt.LaunchTemplateName), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// LaunchTemplateNoSecrets - verifica segredos em launch templates
type LaunchTemplateNoSecrets struct {
	metadata models.CheckMetadata
}

func NewLaunchTemplateNoSecrets() *LaunchTemplateNoSecrets {
	return &LaunchTemplateNoSecrets{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_launch_template_no_secrets",
			CheckTitle: "Ensure EC2 launch templates do not contain secrets",
			Description: "Launch template user data should not contain secrets",
			Severity: "high", ServiceName: "ec2", ResourceType: "LaunchTemplate",
			RemediationText: "Remove secrets from launch template user data",
			Categories: []string{"ec2", "launch-template", "secrets"},
		},
	}
}

func (c *LaunchTemplateNoSecrets) Metadata() models.CheckMetadata { return c.metadata }

func (c *LaunchTemplateNoSecrets) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{})
	if err != nil {
		return nil, err
	}

	secretPatterns := []string{"password", "secret", "api_key", "apikey", "token", "access_key", "private_key"}
	findings := []models.Finding{}
	for _, lt := range result.LaunchTemplates {
		status := models.StatusPass
		msg := fmt.Sprintf("Launch template %s has no secrets", aws.ToString(lt.LaunchTemplateName))
		versions, err := client.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: lt.LaunchTemplateId,
		})
		if err == nil {
			for _, v := range versions.LaunchTemplateVersions {
				if v.LaunchTemplateData != nil && v.LaunchTemplateData.UserData != nil {
					userData := aws.ToString(v.LaunchTemplateData.UserData)
					for _, pattern := range secretPatterns {
						if strings.Contains(strings.ToLower(userData), pattern) {
							status = models.StatusFail
							msg = fmt.Sprintf("Launch template %s contains secrets", aws.ToString(lt.LaunchTemplateName))
							break
						}
					}
				}
			}
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(lt.LaunchTemplateName), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// NetworkAclUnused - verifica NACLs não utilizadas
type NetworkAclUnused struct {
	metadata models.CheckMetadata
}

func NewNetworkAclUnused() *NetworkAclUnused {
	return &NetworkAclUnused{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_unused",
			CheckTitle: "Ensure unused NACLs are removed",
			Description: "Non-default NACLs should be associated with subnets",
			Severity: "low", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Remove unused NACLs",
			Categories: []string{"ec2", "nacl", "networking"},
		},
	}
}

func (c *NetworkAclUnused) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkAclUnused) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, nacl := range result.NetworkAcls {
		isDefault := aws.ToBool(nacl.IsDefault)
		status := models.StatusPass
		msg := fmt.Sprintf("NACL %s is in use", aws.ToString(nacl.NetworkAclId))
		if !isDefault && len(nacl.Associations) == 0 {
			status = models.StatusFail
			msg = fmt.Sprintf("NACL %s is not associated with any subnet", aws.ToString(nacl.NetworkAclId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(nacl.NetworkAclId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// NetworkAclIngressSsh - verifica NACL para SSH
type NetworkAclIngressSsh struct {
	metadata models.CheckMetadata
}

func NewNetworkAclIngressSsh() *NetworkAclIngressSsh {
	return &NetworkAclIngressSsh{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_tcp_port_22",
			CheckTitle: "Ensure NACL does not allow SSH from Internet",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to TCP port 22",
			Severity: "medium", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict SSH access in NACLs",
			Categories: []string{"ec2", "nacl", "ssh"},
		},
	}
}

func (c *NetworkAclIngressSsh) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkAclIngressSsh) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, nacl := range result.NetworkAcls {
		hasSshOpen := false
		for _, entry := range nacl.Entries {
			if aws.ToBool(entry.Egress) {
				continue
			}
			if string(entry.RuleAction) == "allow" {
				if entry.PortRange != nil {
					from := aws.ToInt32(entry.PortRange.From)
					to := aws.ToInt32(entry.PortRange.To)
					if from <= 22 && to >= 22 {
						cidr := aws.ToString(entry.CidrBlock)
						if cidr == "0.0.0.0/0" {
							hasSshOpen = true
							break
						}
					}
				}
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("NACL %s does not allow SSH from Internet", aws.ToString(nacl.NetworkAclId))
		if hasSshOpen {
			status = models.StatusFail
			msg = fmt.Sprintf("NACL %s allows SSH from Internet", aws.ToString(nacl.NetworkAclId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(nacl.NetworkAclId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// NetworkAclIngressRdp - verifica NACL para RDP
type NetworkAclIngressRdp struct {
	metadata models.CheckMetadata
}

func NewNetworkAclIngressRdp() *NetworkAclIngressRdp {
	return &NetworkAclIngressRdp{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_tcp_port_3389",
			CheckTitle: "Ensure NACL does not allow RDP from Internet",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to TCP port 3389",
			Severity: "medium", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict RDP access in NACLs",
			Categories: []string{"ec2", "nacl", "rdp"},
		},
	}
}

func (c *NetworkAclIngressRdp) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkAclIngressRdp) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, nacl := range result.NetworkAcls {
		hasRdpOpen := false
		for _, entry := range nacl.Entries {
			if aws.ToBool(entry.Egress) {
				continue
			}
			if string(entry.RuleAction) == "allow" {
				if entry.PortRange != nil {
					from := aws.ToInt32(entry.PortRange.From)
					to := aws.ToInt32(entry.PortRange.To)
					if from <= 3389 && to >= 3389 {
						cidr := aws.ToString(entry.CidrBlock)
						if cidr == "0.0.0.0/0" {
							hasRdpOpen = true
							break
						}
					}
				}
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("NACL %s does not allow RDP from Internet", aws.ToString(nacl.NetworkAclId))
		if hasRdpOpen {
			status = models.StatusFail
			msg = fmt.Sprintf("NACL %s allows RDP from Internet", aws.ToString(nacl.NetworkAclId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(nacl.NetworkAclId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// NetworkAclIngressAnyPort - verifica NACL para qualquer porta
type NetworkAclIngressAnyPort struct {
	metadata models.CheckMetadata
}

func NewNetworkAclIngressAnyPort() *NetworkAclIngressAnyPort {
	return &NetworkAclIngressAnyPort{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_networkacl_allow_ingress_any_port",
			CheckTitle: "Ensure NACL does not allow any port from Internet",
			Description: "NACLs should not allow ingress from 0.0.0.0/0 to any port",
			Severity: "high", ServiceName: "ec2", ResourceType: "NetworkACL",
			RemediationText: "Restrict NACL rules",
			Categories: []string{"ec2", "nacl", "networking"},
		},
	}
}

func (c *NetworkAclIngressAnyPort) Metadata() models.CheckMetadata { return c.metadata }

func (c *NetworkAclIngressAnyPort) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, nacl := range result.NetworkAcls {
		hasAnyPort := false
		for _, entry := range nacl.Entries {
			if aws.ToBool(entry.Egress) {
				continue
			}
			if string(entry.RuleAction) == "allow" {
				cidr := aws.ToString(entry.CidrBlock)
				if cidr == "0.0.0.0/0" {
					if entry.PortRange == nil {
						hasAnyPort = true
						break
					}
					from := aws.ToInt32(entry.PortRange.From)
					to := aws.ToInt32(entry.PortRange.To)
					if from == 0 && to == 65535 {
						hasAnyPort = true
						break
					}
				}
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("NACL %s does not allow any port from Internet", aws.ToString(nacl.NetworkAclId))
		if hasAnyPort {
			status = models.StatusFail
			msg = fmt.Sprintf("NACL %s allows any port from Internet", aws.ToString(nacl.NetworkAclId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(nacl.NetworkAclId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AmiPublic - verifica AMIs públicas
type AmiPublic struct {
	metadata models.CheckMetadata
}

func NewAmiPublic() *AmiPublic {
	return &AmiPublic{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ami_public",
			CheckTitle: "Ensure AMIs are not public",
			Description: "AMIs owned by the account should not be public",
			Severity: "critical", ServiceName: "ec2", ResourceType: "AMI",
			RemediationText: "Remove public access from AMIs",
			Categories: []string{"ec2", "ami", "public"},
		},
	}
}

func (c *AmiPublic) Metadata() models.CheckMetadata { return c.metadata }

func (c *AmiPublic) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, img := range result.Images {
		status := models.StatusPass
		msg := fmt.Sprintf("AMI %s is not public", aws.ToString(img.ImageId))
		if img.Public != nil && *img.Public {
			status = models.StatusFail
			msg = fmt.Sprintf("AMI %s is public", aws.ToString(img.ImageId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(img.ImageId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// AmiAccountBlockPublicAccess - verifica bloqueio de AMIs públicas a nível de conta
type AmiAccountBlockPublicAccess struct {
	metadata models.CheckMetadata
}

func NewAmiAccountBlockPublicAccess() *AmiAccountBlockPublicAccess {
	return &AmiAccountBlockPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ami_account_block_public_access",
			CheckTitle: "Ensure AMI block public access is enabled",
			Description: "AMI block public access should be enabled at account level",
			Severity: "medium", ServiceName: "ec2", ResourceType: "Account",
			RemediationText: "Enable AMI block public access",
			Categories: []string{"ec2", "ami", "account"},
		},
	}
}

func (c *AmiAccountBlockPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *AmiAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.GetImageBlockPublicAccessState(ctx, &ec2.GetImageBlockPublicAccessStateInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "AMI block public access is disabled"
	if result.ImageBlockPublicAccessState != nil && *result.ImageBlockPublicAccessState == "block-new-shares" {
		status = models.StatusPass
		msg = "AMI block public access is enabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "ec2", ResourceID: "ami-block-public-access",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EbsSnapshotAccountBlockPublicAccess - verifica bloqueio de snapshots públicos
type EbsSnapshotAccountBlockPublicAccess struct {
	metadata models.CheckMetadata
}

func NewEbsSnapshotAccountBlockPublicAccess() *EbsSnapshotAccountBlockPublicAccess {
	return &EbsSnapshotAccountBlockPublicAccess{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_snapshot_account_block_public_access",
			CheckTitle: "Ensure EBS snapshot block public access is enabled",
			Description: "EBS snapshot block public access should be enabled",
			Severity: "high", ServiceName: "ec2", ResourceType: "Account",
			RemediationText: "Enable EBS snapshot block public access",
			Categories: []string{"ec2", "ebs", "snapshot"},
		},
	}
}

func (c *EbsSnapshotAccountBlockPublicAccess) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsSnapshotAccountBlockPublicAccess) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.GetSnapshotBlockPublicAccessState(ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{})
	if err != nil {
		return nil, err
	}

	status := models.StatusFail
	msg := "EBS snapshot block public access is disabled"
	if result.State == types.SnapshotBlockPublicAccessStateBlockAllSharing {
		status = models.StatusPass
		msg = "EBS snapshot block public access is enabled"
	}

	return []models.Finding{{
		ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
		Description: c.metadata.Description, Severity: c.metadata.Severity,
		Status: status, StatusExtended: msg,
		Provider: "aws", Service: "ec2", ResourceID: "ebs-snapshot-block-public-access",
		FoundAt: time.Now().UTC(),
	}}, nil
}

// EbsVolumeProtectedByBackupPlan - verifica proteção de volumes por backup
type EbsVolumeProtectedByBackupPlan struct {
	metadata models.CheckMetadata
}

func NewEbsVolumeProtectedByBackupPlan() *EbsVolumeProtectedByBackupPlan {
	return &EbsVolumeProtectedByBackupPlan{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_protected_by_backup_plan",
			CheckTitle: "Ensure EBS volumes are protected by backup plan",
			Description: "EBS volumes should be protected by a backup plan",
			Severity: "medium", ServiceName: "ec2", ResourceType: "Volume",
			RemediationText: "Add EBS volumes to a backup plan",
			Categories: []string{"ec2", "ebs", "backup"},
		},
	}
}

func (c *EbsVolumeProtectedByBackupPlan) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsVolumeProtectedByBackupPlan) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	result, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, vol := range result.Volumes {
		// Verificar tags indicando proteção de backup
		hasBackup := false
		for _, tag := range vol.Tags {
			if aws.ToString(tag.Key) == "BackupPlan" || aws.ToString(tag.Key) == "backup" {
				hasBackup = true
				break
			}
		}
		status := models.StatusPass
		msg := fmt.Sprintf("Volume %s is protected by backup plan", aws.ToString(vol.VolumeId))
		if !hasBackup {
			status = models.StatusFail
			msg = fmt.Sprintf("Volume %s is not protected by backup plan", aws.ToString(vol.VolumeId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(vol.VolumeId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}

// EbsVolumeSnapshotsExists - verifica se volume tem snapshots
type EbsVolumeSnapshotsExists struct {
	metadata models.CheckMetadata
}

func NewEbsVolumeSnapshotsExists() *EbsVolumeSnapshotsExists {
	return &EbsVolumeSnapshotsExists{
		metadata: models.CheckMetadata{
			Provider: "aws", CheckID: "ec2_ebs_volume_snapshots_exists",
			CheckTitle: "Ensure EBS volumes have snapshots",
			Description: "EBS volumes should have at least one snapshot",
			Severity: "high", ServiceName: "ec2", ResourceType: "Volume",
			RemediationText: "Create snapshots for EBS volumes",
			Categories: []string{"ec2", "ebs", "snapshot"},
		},
	}
}

func (c *EbsVolumeSnapshotsExists) Metadata() models.CheckMetadata { return c.metadata }

func (c *EbsVolumeSnapshotsExists) Execute(ctx context.Context, provider interface{}) ([]models.Finding, error) {
	client, ok := getEC2Client(ctx, provider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement EC2 provider")
	}

	volumes, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{})
	if err != nil {
		return nil, err
	}

	findings := []models.Finding{}
	for _, vol := range volumes.Volumes {
		snapshots, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			Filters: []types.Filter{
				{Name: aws.String("volume-id"), Values: []string{aws.ToString(vol.VolumeId)}},
			},
		})
		if err != nil {
			continue
		}
		status := models.StatusPass
		msg := fmt.Sprintf("Volume %s has %d snapshot(s)", aws.ToString(vol.VolumeId), len(snapshots.Snapshots))
		if len(snapshots.Snapshots) == 0 {
			status = models.StatusFail
			msg = fmt.Sprintf("Volume %s has no snapshots", aws.ToString(vol.VolumeId))
		}
		findings = append(findings, models.Finding{
			ID: c.metadata.CheckID, Title: c.metadata.CheckTitle,
			Description: c.metadata.Description, Severity: c.metadata.Severity,
			Status: status, StatusExtended: msg,
			ResourceID: aws.ToString(vol.VolumeId), Provider: "aws", Service: "ec2",
			FoundAt: time.Now().UTC(),
		})
	}
	return findings, nil
}
